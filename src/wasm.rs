//! WASM Plugin System for jarsWAF
//!
//! Allows loading `.wasm` plugins from the `plugins/` directory.
//! Each plugin exports an `inspect_request` function that receives
//! request data via linear memory and returns a verdict (0=pass, >0=block).

use std::path::Path;
use wasmtime::*;

/// A single loaded WASM plugin.
struct WasmPlugin {
    name: String,
    module: Module,
}

/// Engine that manages all loaded WASM plugins.
pub struct WasmPluginEngine {
    engine: Engine,
    plugins: Vec<WasmPlugin>,
}

impl WasmPluginEngine {
    /// Load all `.wasm` files from the given directory.
    /// Non-fatal: invalid files are logged and skipped.
    pub fn load_plugins(dir: &Path) -> Self {
        let engine = Engine::default();
        let mut plugins = Vec::new();

        if !dir.exists() {
            return Self { engine, plugins };
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Self { engine, plugins },
        };

        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                continue;
            }

            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            match Module::from_file(&engine, &path) {
                Ok(module) => {
                    tracing::info!(plugin = %name, "WASM plugin loaded");
                    plugins.push(WasmPlugin { name, module });
                }
                Err(e) => {
                    tracing::warn!(plugin = %name, error = %e, "Failed to load WASM plugin");
                }
            }
        }

        Self { engine, plugins }
    }

    /// Construct a WasmPluginEngine from an already-compiled module (for testing).
    #[cfg(test)]
    pub fn from_module(engine: Engine, name: &str, module: Module) -> Self {
        Self {
            engine,
            plugins: vec![WasmPlugin {
                name: name.to_string(),
                module,
            }],
        }
    }

    /// Run all loaded plugins against a request.
    /// Returns `Some((rule_id, message))` on the first plugin that blocks.
    pub fn inspect_request(&self, path: &str, query: &str, body: &str) -> Option<(String, String)> {
        for plugin in &self.plugins {
            match self.run_plugin(plugin, path, query, body) {
                Ok(true) => {
                    let rule_id = format!("WASM-{}", plugin.name.to_uppercase());
                    let msg = format!("Blocked by WASM plugin '{}'", plugin.name);
                    return Some((rule_id, msg));
                }
                Ok(false) => {} // passed
                Err(e) => {
                    tracing::warn!(
                        plugin = %plugin.name,
                        error = %e,
                        "WASM plugin execution error, skipping"
                    );
                }
            }
        }
        None
    }

    /// Execute a single plugin. Returns `true` if the request should be blocked.
    fn run_plugin(&self, plugin: &WasmPlugin, path: &str, query: &str, body: &str) -> Result<bool> {
        let mut store = Store::new(&self.engine, ());
        let instance = Instance::new(&mut store, &plugin.module, &[])?;

        // Get the plugin's exported memory
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("Plugin has no exported memory"))?;

        // Write request data into linear memory at known offsets.
        // Layout: [path @ 0] [query @ 4096] [body @ 8192]
        // Each segment is max 4096 bytes — simple and predictable.
        let path_bytes = &path.as_bytes()[..path.len().min(4095)];
        let query_bytes = &query.as_bytes()[..query.len().min(4095)];
        let body_bytes = &body.as_bytes()[..body.len().min(4095)];

        // Ensure memory is large enough (at least 1 page = 64KB)
        let current_pages = memory.size(&store);
        if current_pages == 0 {
            memory.grow(&mut store, 1)?;
        }

        memory.write(&mut store, 0, path_bytes)?;
        memory.write(&mut store, 4096, query_bytes)?;
        memory.write(&mut store, 8192, body_bytes)?;

        // Call the exported inspect function
        let inspect_fn = instance
            .get_typed_func::<(i32, i32, i32, i32, i32, i32), i32>(&mut store, "inspect_request")
            .map_err(|e| anyhow::anyhow!("Missing inspect_request export: {}", e))?;

        let result = inspect_fn.call(
            &mut store,
            (
                0,
                path_bytes.len() as i32,
                4096,
                query_bytes.len() as i32,
                8192,
                body_bytes.len() as i32,
            ),
        )?;

        Ok(result > 0)
    }

    /// Number of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// WAT module that blocks any request where path contains "/wp-admin".
    /// Simple byte scan: iterate path bytes looking for the sequence.
    const BLOCK_WP_ADMIN_WAT: &str = r#"
    (module
      (memory (export "memory") 1)

      (func (export "inspect_request")
        (param $path_ptr i32) (param $path_len i32)
        (param $query_ptr i32) (param $query_len i32)
        (param $body_ptr i32) (param $body_len i32)
        (result i32)

        (local $i i32)
        (local $end i32)

        ;; We need path_len >= 9 to match "/wp-admin" (9 chars)
        (if (i32.lt_s (local.get $path_len) (i32.const 9))
          (then (return (i32.const 0)))
        )

        ;; end = path_len - 8 (last valid start position for 9-char match)
        (local.set $end (i32.sub (local.get $path_len) (i32.const 8)))
        (local.set $i (i32.const 0))

        (block $break
          (loop $loop
            (br_if $break (i32.ge_s (local.get $i) (local.get $end)))

            ;; Check if path[i..i+9] == "/wp-admin"
            ;; '/' = 47, 'w' = 119, 'p' = 112, '-' = 45, 'a' = 97, 'd' = 100, 'm' = 109, 'i' = 105, 'n' = 110
            (if (i32.and
                  (i32.and
                    (i32.and
                      (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (local.get $i))) (i32.const 47))
                      (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (i32.add (local.get $i) (i32.const 1)))) (i32.const 119))
                    )
                    (i32.and
                      (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (i32.add (local.get $i) (i32.const 2)))) (i32.const 112))
                      (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (i32.add (local.get $i) (i32.const 3)))) (i32.const 45))
                    )
                  )
                  (i32.and
                    (i32.and
                      (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (i32.add (local.get $i) (i32.const 4)))) (i32.const 97))
                      (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (i32.add (local.get $i) (i32.const 5)))) (i32.const 100))
                    )
                    (i32.and
                      (i32.and
                        (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (i32.add (local.get $i) (i32.const 6)))) (i32.const 109))
                        (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (i32.add (local.get $i) (i32.const 7)))) (i32.const 105))
                      )
                      (i32.eq (i32.load8_u (i32.add (local.get $path_ptr) (i32.add (local.get $i) (i32.const 8)))) (i32.const 110))
                    )
                  )
                )
              (then (return (i32.const 1)))
            )

            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $loop)
          )
        )

        (i32.const 0)
      )
    )
    "#;

    /// Always-pass plugin (returns 0 for everything).
    const PASS_ALL_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "inspect_request")
        (param i32) (param i32) (param i32) (param i32) (param i32) (param i32)
        (result i32)
        (i32.const 0)
      )
    )
    "#;

    #[test]
    fn test_wasm_engine_no_plugins() {
        let dir = std::path::Path::new("/tmp/jarswaf-test-empty-plugins");
        let _ = std::fs::create_dir_all(dir);
        let engine = WasmPluginEngine::load_plugins(dir);
        assert_eq!(engine.plugin_count(), 0);
        assert!(engine.inspect_request("/test", "", "").is_none());
    }

    #[test]
    fn test_wasm_plugin_blocks_wp_admin() {
        let engine = Engine::default();
        let module = Module::new(&engine, BLOCK_WP_ADMIN_WAT).expect("WAT compile failed");
        let wasm_engine = WasmPluginEngine::from_module(engine, "block-wp-admin", module);

        // Should block /wp-admin
        let result = wasm_engine.inspect_request("/wp-admin/index.php", "", "");
        assert!(result.is_some());
        let (rule_id, _msg) = result.unwrap();
        assert_eq!(rule_id, "WASM-BLOCK-WP-ADMIN");

        // Should pass normal paths
        let result = wasm_engine.inspect_request("/api/v1/users", "", "");
        assert!(result.is_none());
    }

    #[test]
    fn test_wasm_plugin_pass_all() {
        let engine = Engine::default();
        let module = Module::new(&engine, PASS_ALL_WAT).expect("WAT compile failed");
        let wasm_engine = WasmPluginEngine::from_module(engine, "pass-all", module);

        assert!(wasm_engine
            .inspect_request("/anything", "q=1", "body")
            .is_none());
        assert!(wasm_engine.inspect_request("/wp-admin", "", "").is_none());
    }
}
