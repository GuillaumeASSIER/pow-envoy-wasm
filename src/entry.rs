//! Point d'entree du module Proxy-WASM.
//!
//! Compile uniquement pour `wasm32-wasip1`. La macro `main!` du SDK exporte
//! `_initialize`, donc Envoy instancie le module en mode reacteur sans executer
//! de `_start` WASI.

use crate::plugin::PowRoot;
use proxy_wasm::traits::RootContext;
use proxy_wasm::types::LogLevel;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(PowRoot::default()) });
}}
