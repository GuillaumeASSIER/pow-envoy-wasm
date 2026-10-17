//! Configuration du plugin, telle qu'elle arrive dans `WasmPlugin.pluginConfig`.
//!
//! Meme surface que la version Go, plus un reglage de niveau de log utile : la
//! version Go formate ses messages de debogage sur chaque requete, meme quand
//! l'hote les jette. Ici le niveau est lu une fois au demarrage, et les appels
//! sont court-circuites avant toute allocation.

use crate::token::DEFAULT_DIFFICULTY;
use crate::MIN_SECRET_LEN;
use serde::Deserialize;

/// Origine de l'adresse client retenue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSource {
    /// `source.address`, puis `X-Forwarded-For`, puis `X-Real-IP`.
    Auto,
    /// `source.address` uniquement : on ne fait confiance a aucun en-tete.
    Peer,
}

/// Seuil de journalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl LogLevel {
    fn parse(raw: &str) -> LogLevel {
        match raw.trim().to_ascii_lowercase().as_str() {
            "error" => LogLevel::Error,
            "warn" | "warning" => LogLevel::Warn,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => LogLevel::Info,
        }
    }
}

/// Cause d'un refus de demarrage. Un plugin qui ne peut pas signer de challenge
/// ne doit pas se charger en silence.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Configuration absente ou vide.
    Missing,
    /// Configuration illisible.
    Malformed,
    /// Secret absent, vide, ou trop court.
    BadSecret,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::Missing => write!(f, "configuration du plugin absente"),
            ConfigError::Malformed => write!(f, "configuration du plugin illisible (JSON attendu)"),
            ConfigError::BadSecret => write!(
                f,
                "secret obligatoire, longueur minimale {MIN_SECRET_LEN} octets"
            ),
        }
    }
}

/// Vue brute du JSON, avant application des bornes et des defauts.
#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    secret: String,
    #[serde(default)]
    header: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    base_difficulty: u32,
    #[serde(default)]
    min_difficulty: u32,
    #[serde(default)]
    max_difficulty: u32,
    #[serde(default)]
    client_ip_source: String,
    #[serde(default)]
    log_level: String,
}

/// Configuration effective.
#[derive(Debug, Clone)]
pub struct Config {
    /// Secret HMAC. Jamais journalise.
    pub secret: String,
    /// En-tete de reponse a poser, si configure.
    pub header: String,
    /// Valeur de cet en-tete.
    pub value: String,
    pub base_difficulty: u32,
    pub min_difficulty: u32,
    pub max_difficulty: u32,
    pub ip_source: IpSource,
    pub log_level: LogLevel,
}

impl Config {
    /// Lit et valide la configuration.
    ///
    /// Les bornes de difficulte reprennent exactement la logique de la version
    /// Go : un `base` hors bornes est ramene dans l'intervalle, un `max`
    /// incoherent est remplace par 26.
    pub fn from_json(raw: &[u8]) -> Result<Config, ConfigError> {
        if raw.is_empty() {
            return Err(ConfigError::Missing);
        }
        let parsed: RawConfig = serde_json::from_slice(raw).map_err(|_| ConfigError::Malformed)?;

        let secret = parsed.secret.trim().to_string();
        if secret.len() < MIN_SECRET_LEN {
            return Err(ConfigError::BadSecret);
        }

        let mut base = parsed.base_difficulty;
        let mut min = parsed.min_difficulty;
        let mut max = parsed.max_difficulty;

        if base < 1 {
            base = DEFAULT_DIFFICULTY;
        }
        if min < 1 {
            min = 12;
        }
        if max < 1 || max < min {
            max = 26;
        }
        base = base.clamp(min, max);

        let ip_source = match parsed.client_ip_source.trim().to_ascii_lowercase().as_str() {
            "source_address" | "peer" | "source" => IpSource::Peer,
            _ => IpSource::Auto,
        };

        Ok(Config {
            secret,
            header: parsed.header.trim().to_string(),
            value: parsed.value.trim().to_string(),
            base_difficulty: base,
            min_difficulty: min,
            max_difficulty: max,
            ip_source,
            log_level: LogLevel::parse(&parsed.log_level),
        })
    }

    /// La cle HMAC, en octets.
    pub fn key(&self) -> &[u8] {
        self.secret.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"{"secret":"0123456789abcdef0123456789abcdef"}"#;

    #[test]
    fn defaults_match_go_implementation() {
        let c = Config::from_json(OK.as_bytes()).expect("config valide");
        assert_eq!(c.base_difficulty, 18);
        assert_eq!(c.min_difficulty, 12);
        assert_eq!(c.max_difficulty, 26);
        assert_eq!(c.ip_source, IpSource::Auto);
        assert_eq!(c.log_level, LogLevel::Info);
        assert_eq!(c.header, "");
    }

    #[test]
    fn secret_is_mandatory() {
        assert_eq!(Config::from_json(b"").err(), Some(ConfigError::Missing));
        assert_eq!(
            Config::from_json(br#"{"header":"x"}"#).err(),
            Some(ConfigError::BadSecret)
        );
        assert_eq!(
            Config::from_json(br#"{"secret":"trop court"}"#).err(),
            Some(ConfigError::BadSecret)
        );
        assert_eq!(
            Config::from_json(b"pas du json").err(),
            Some(ConfigError::Malformed)
        );
    }

    #[test]
    fn difficulty_bounds_are_clamped_like_go() {
        let c = Config::from_json(
            br#"{"secret":"0123456789abcdef0123456789abcdef","base_difficulty":40,
                 "min_difficulty":10,"max_difficulty":20}"#,
        )
        .unwrap();
        assert_eq!(
            (c.min_difficulty, c.base_difficulty, c.max_difficulty),
            (10, 20, 20)
        );

        // max < min devient 26, puis base est ramene dans [min, 26].
        let c = Config::from_json(
            br#"{"secret":"0123456789abcdef0123456789abcdef","base_difficulty":30,
                 "min_difficulty":12,"max_difficulty":5}"#,
        )
        .unwrap();
        assert_eq!(
            (c.min_difficulty, c.base_difficulty, c.max_difficulty),
            (12, 26, 26)
        );
    }

    #[test]
    fn ip_source_variants() {
        for raw in ["source_address", "PEER", " source "] {
            let json = format!(
                r#"{{"secret":"0123456789abcdef0123456789abcdef","client_ip_source":"{raw}"}}"#
            );
            assert_eq!(
                Config::from_json(json.as_bytes()).unwrap().ip_source,
                IpSource::Peer
            );
        }
        let json = r#"{"secret":"0123456789abcdef0123456789abcdef","client_ip_source":"auto"}"#;
        assert_eq!(
            Config::from_json(json.as_bytes()).unwrap().ip_source,
            IpSource::Auto
        );
    }

    #[test]
    fn optional_header_and_log_level() {
        let json = r#"{"secret":"0123456789abcdef0123456789abcdef","header":" x-pow ","value":" v ","log_level":"debug"}"#;
        let c = Config::from_json(json.as_bytes()).unwrap();
        assert_eq!((c.header.as_str(), c.value.as_str()), ("x-pow", "v"));
        assert_eq!(c.log_level, LogLevel::Debug);
    }
}
