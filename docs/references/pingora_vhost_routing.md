# Pingora VHost Routing

In `jarsWAF`, routing is determined by the `Host` header of incoming requests. Since Pingora is highly asynchronous and multi-threaded, we cannot rely on standard `RwLock` for reading configuration per-request without causing massive thread contention.

## Lock-Free Routing with ArcSwap

We use `arc_swap::ArcSwap` to store the active configuration.

```rust
use arc_swap::ArcSwap;
use std::sync::Arc;
use crate::config::Config;

pub static GLOBAL_CONFIG: ArcSwap<Config> = ArcSwap::from_pointee(Config::default());
```

When `config.toml` changes, the config watcher will load the new config and call `GLOBAL_CONFIG.store(Arc::new(new_config))`. Active requests will continue using their locally cloned `Arc<Config>`, while new requests will instantly get the new config.

## VHost Resolution Logic in `upstream_peer`

Inside `ProxyHttp::upstream_peer`:

```rust
async fn upstream_peer(
    &self,
    session: &mut Session,
    _ctx: &mut Self::CTX,
) -> Result<Box<HttpPeer>> {
    let host_header = session.req_header().headers.get("host").and_then(|h| h.to_str().ok());
    
    let config = GLOBAL_CONFIG.load();
    let (backend_addr, vhost) = match vhost::match_vhost(host_header, &config) {
        Some((b, v)) => (b.clone(), v.clone()),
        None => return Err(pingora::Error::explain(
            pingora::ErrorType::HTTPStatus(400),
            "Unrecognized Host",
        )),
    };

    let peer = HttpPeer::new(&backend_addr, false, "".to_string());
    Ok(Box::new(peer))
}
```

This ensures zero lock contention while evaluating route rules for millions of requests.
