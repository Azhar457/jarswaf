use crate::{config, logging, proxy, tls};
use axum::{
    body::Body,
    extract::{ConnectInfo, Host, State},
    http::Request,
    response::Response,
    routing::any,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

// Shared application state for Agent
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<std::sync::RwLock<config::Config>>,
    pub log_tx: tokio::sync::mpsc::Sender<logging::WafLogEntry>,
    pub blocklist: Arc<std::sync::RwLock<std::collections::HashSet<std::net::IpAddr>>>,
    pub http_client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        axum::body::Body,
    >,
}

// Main request handler for Agent
async fn handler(
    state: State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    host: Option<Host>,
    req: Request<Body>,
) -> Response<Body> {
    proxy::forward_request(state, addr, host, req).await
}

// Untuk privilege dropping (bind port <1024 lalu drop ke nobody)
#[cfg(unix)]
fn drop_privileges() {
    if let Err(e) = nix::unistd::setgid(nix::unistd::Gid::from_raw(65534)) {
        warn!("Failed to setgid: {}", e);
    }
    if let Err(e) = nix::unistd::setuid(nix::unistd::Uid::from_raw(65534)) {
        warn!("Failed to setuid: {}", e);
    }
}

pub async fn run_server(cfg: &config::Config, state: AppState) {
    // Build Axum router
    let app = Router::new()
        .route("/", any(handler))
        .route("/*path", any(handler))
        .with_state(state);

    // Bind HTTPS if configured
    let tls_cfg = cfg.tls.clone();
    let config_arc = Arc::new(std::sync::RwLock::new(cfg.clone())); // we can just use the Arc from AppState later, but we need to update domains/email
    let config_arc_tls = config_arc.clone();
    let app_tls = app.clone();
    let port_https = cfg.global.port_https;

    if tls_cfg.mode == "local_ca" {
        tokio::spawn(async move {
            let ca = tls::LocalCA::new(&tls_cfg.cert_dir);
            if let Err(e) = ca.ensure_ca() {
                error!("Failed to ensure local CA: {}", e);
                return;
            }

            let domain = {
                let lock = config_arc_tls.read().unwrap();
                lock.vhosts
                    .first()
                    .and_then(|v| v.hosts.first())
                    .cloned()
                    .unwrap_or_else(|| "localhost".to_string())
            };

            let (certs, key) = match ca.generate_server_cert(&domain) {
                Ok(pair) => pair,
                Err(e) => {
                    error!("Failed to generate server cert for {}: {}", domain, e);
                    return;
                }
            };

            let rustls_config = match rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
            {
                Ok(mut config) => {
                    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                    std::sync::Arc::new(config)
                }
                Err(e) => {
                    error!("Failed to build ServerConfig: {}", e);
                    return;
                }
            };

            let acceptor = tokio_rustls::TlsAcceptor::from(rustls_config);
            let https_addr = SocketAddr::from(([0, 0, 0, 0], port_https));
            let listener = match tokio::net::TcpListener::bind(https_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind HTTPS port {}: {}", port_https, e);
                    return;
                }
            };

            info!(
                "Aegis Agent WAF listening on https://{} (HTTPS)",
                https_addr
            );

            let service = app_tls.into_make_service_with_connect_info::<SocketAddr>();
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let mut service_clone = service.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("TLS handshake failed: {}", e);
                            return;
                        }
                    };

                    use hyper_util::rt::TokioIo;
                    use tower::Service;
                    let io = TokioIo::new(tls_stream);
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );

                    let route_service = match service_clone.call(peer_addr).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    let hyper_service =
                        hyper_util::service::TowerToHyperService::new(route_service);

                    if let Err(err) = builder.serve_connection(io, hyper_service).await {
                        error!("Error serving TLS connection: {:?}", err);
                    }
                });
            }
        });
    } else if tls_cfg.mode == "acme" {
        tokio::spawn(async move {
            let domains: Vec<String> = {
                let lock = config_arc_tls.read().unwrap();
                let mut doms: Vec<String> = lock
                    .vhosts
                    .iter()
                    .flat_map(|v| v.hosts.clone())
                    .filter(|h| !h.contains('*'))
                    .collect();
                for cert in &lock.certificates {
                    if !doms.contains(&cert.domain) {
                        doms.push(cert.domain.clone());
                    }
                }
                doms
            };

            let email = {
                let lock = config_arc_tls.read().unwrap();
                lock.certificates
                    .first()
                    .map(|c| c.email.clone())
                    .unwrap_or_else(|| "admin@aegiswaf.local".to_string())
            };

            if domains.is_empty() {
                warn!("No valid domains found for ACME. Skipping ACME setup.");
                return;
            }

            let cert_dir: &'static std::path::Path =
                Box::leak(std::path::PathBuf::from(tls_cfg.cert_dir.clone()).into_boxed_path());
            let mut acme_state = rustls_acme::AcmeConfig::new(domains)
                .contact([format!("mailto:{}", email)])
                .cache(rustls_acme::caches::DirCache::new(cert_dir))
                .directory_lets_encrypt(false) // use staging by default to avoid rate limits during demo
                .state();

            let mut rustls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(acme_state.resolver());
            rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(rustls_config));
            let https_addr = SocketAddr::from(([0, 0, 0, 0], port_https));
            let listener = match tokio::net::TcpListener::bind(https_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind HTTPS port {} for ACME: {}", port_https, e);
                    return;
                }
            };

            info!(
                "Aegis Agent WAF listening on https://{} (ACME TLS)",
                https_addr
            );

            // Spawn ACME worker task
            tokio::spawn(async move {
                use tokio_stream::StreamExt;
                loop {
                    match acme_state.next().await {
                        Some(Ok(event)) => info!("ACME Event: {:?}", event),
                        Some(Err(err)) => error!("ACME Error: {:?}", err),
                        None => break,
                    }
                }
            });

            let service = app_tls.into_make_service_with_connect_info::<SocketAddr>();
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let mut service_clone = service.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("ACME TLS handshake failed: {}", e);
                            return;
                        }
                    };

                    use hyper_util::rt::TokioIo;
                    use tower::Service;
                    let io = TokioIo::new(tls_stream);
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );

                    let route_service = match service_clone.call(peer_addr).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    let hyper_service =
                        hyper_util::service::TowerToHyperService::new(route_service);

                    if let Err(err) = builder.serve_connection(io, hyper_service).await {
                        error!("Error serving ACME TLS connection: {:?}", err);
                    }
                });
            }
        });
    }

    // Bind HTTP
    let http_addr = SocketAddr::from(([0, 0, 0, 0], cfg.global.port_http));
    let http_listener = tokio::net::TcpListener::bind(http_addr)
        .await
        .expect("Cannot bind HTTP port");

    info!("Aegis Agent WAF listening on http://{}", http_addr);
    if !cfg.vhosts.is_empty() {
        info!("Backend default: {}", cfg.vhosts[0].backend);
    }

    // Drop root privileges setelah bind
    #[cfg(unix)]
    if std::process::id() == 0 {
        drop_privileges();
    }

    axum::serve(
        http_listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
