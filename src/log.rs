//! Journalisation avec seuil.
//!
//! Le seuil est lu une fois, a la lecture de la configuration. L'appel est
//! court-circuite avant toute allocation quand le niveau est au-dessus du
//! seuil : contrairement a la version Go, qui formate ses messages de debogage
//! sur chaque requete pour que l'hote les jette ensuite, le chemin chaud ne
//! paie rien quand le debogage est desactive.

use core::sync::atomic::{AtomicU8, Ordering};
use proxy_wasm::types::LogLevel as HostLevel;

use crate::config::LogLevel;

/// Seuil courant. `Info` par defaut, comme la version Go.
static LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

pub fn set_level(level: LogLevel) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Vrai si un message de ce niveau doit etre emis.
pub fn enabled(level: LogLevel) -> bool {
    (level as u8) <= LEVEL.load(Ordering::Relaxed)
}

/// Traduit le seuil interne vers celui de l'hote.
pub fn host_level(level: LogLevel) -> HostLevel {
    match level {
        LogLevel::Error => HostLevel::Error,
        LogLevel::Warn => HostLevel::Warn,
        LogLevel::Info => HostLevel::Info,
        LogLevel::Debug => HostLevel::Debug,
        LogLevel::Trace => HostLevel::Trace,
    }
}

/// Emet un message si le seuil le permet.
#[macro_export]
macro_rules! log_at {
    ($level:expr, $($arg:tt)*) => {{
        if $crate::log::enabled($level) {
            let message = format!($($arg)*);
            let _ = proxy_wasm::hostcalls::log($crate::log::host_level($level), &message);
        }
    }};
}

/// Raccourcis, pour alleger les appels dans l'adaptateur.
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => { $crate::log_at!($crate::config::LogLevel::Debug, $($arg)*) };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log_at!($crate::config::LogLevel::Info, $($arg)*) };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log_at!($crate::config::LogLevel::Error, $($arg)*) };
}
