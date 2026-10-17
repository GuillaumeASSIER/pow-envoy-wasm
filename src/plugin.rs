//! Contexte racine : lecture de la configuration, difficulte dynamique,
//! creation des contextes HTTP.

use core::time::Duration;
use std::cell::RefCell;
use std::rc::Rc;

use proxy_wasm::traits::{Context, HttpContext, RootContext};

use crate::config::Config;
use crate::http::PowHttp;
use crate::log;
use crate::protocol::Engine;
use crate::{log_debug, log_error, log_info};

/// Cle de donnees partagees, identique a celle de la version Go : plusieurs
/// machines virtuelles Wasm d'un meme proxy partagent ainsi une difficulte
/// courante.
pub const SHARED_KEY_DIFFICULTY: &str = "challenge:current_difficulty";

/// Periode du battement qui ajuste la difficulte, en millisecondes.
const TICK_MILLIS: u64 = 5_000;

/// Etat partage entre le contexte racine et les contextes HTTP.
///
/// Le Wasm est mono-thread, donc `Rc<RefCell<..>>` suffit et evite un verrou.
pub struct Shared {
    pub config: Config,
    pub engine: Engine,
}

/// Contexte racine du plugin.
#[derive(Default)]
pub struct PowRoot {
    shared: Option<Rc<RefCell<Shared>>>,
}

impl Context for PowRoot {}

impl RootContext for PowRoot {
    /// Lit la configuration. Refuse de demarrer si le secret manque : un plugin
    /// qui ne peut pas signer de challenge ne doit pas se charger en silence.
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        let raw = match self.get_plugin_configuration() {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => {
                log_error!(
                    "pow-proxy: configuration obligatoire, attendu un JSON avec au moins \
                     {{\"secret\":\"<32 octets ou plus>\"}}"
                );
                return false;
            }
        };

        let config = match Config::from_json(&raw) {
            Ok(config) => config,
            Err(err) => {
                log_error!("pow-proxy: {err}");
                return false;
            }
        };

        log::set_level(config.log_level);
        proxy_wasm::set_log_level(log::host_level(config.log_level));

        let mut engine = Engine::new(&config);
        if let Some(value) = self.read_shared_difficulty() {
            engine.adopt_current_difficulty(value);
        }

        log_info!(
            "pow-proxy: difficulte base={} min={} max={}, source_ip={:?}, secret={} octets, log={:?}",
            config.base_difficulty,
            config.min_difficulty,
            config.max_difficulty,
            config.ip_source,
            config.secret.len(),
            config.log_level
        );
        log_info!(
            "pow-proxy: fenetre challenge={}s clearance={}s",
            crate::CHALLENGE_LIFETIME_SECS,
            crate::CLEARANCE_LIFETIME_SECS
        );

        self.shared = Some(Rc::new(RefCell::new(Shared { config, engine })));

        // Battement pour la difficulte dynamique. Plus lent que la version Go
        // si on le souhaite : c'est un reglage, pas une contrainte.
        self.set_tick_period(Duration::from_millis(TICK_MILLIS));
        log_debug!("pow-proxy: battement de difficulte toutes les {TICK_MILLIS} ms");

        true
    }

    /// Recalcule la difficulte d'apres la pression mesuree, et la publie.
    fn on_tick(&mut self) {
        let Some(shared) = self.shared.as_ref() else {
            return;
        };

        let (difficulty, recent) = {
            let mut guard = shared.borrow_mut();
            let recent = guard.engine.issued_in_window();
            (guard.engine.tick(), recent)
        };

        let text = difficulty.to_string();
        // Echec de publication sans consequence : la difficulte locale reste
        // correcte, seule la coordination entre instances est perdue.
        let _ = self.set_shared_data(SHARED_KEY_DIFFICULTY, Some(text.as_bytes()), None);

        if recent > 0 {
            log_debug!(
                "pow-proxy: {recent} challenges depuis le dernier battement, difficulte {difficulty}"
            );
        }
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        self.shared
            .as_ref()
            .map(|shared| Box::new(PowHttp::new(shared.clone())) as Box<dyn HttpContext>)
    }
}

impl PowRoot {
    /// Difficulte courante publiee par une autre instance, si elle existe.
    fn read_shared_difficulty(&self) -> Option<u32> {
        let (data, _cas) = self.get_shared_data(SHARED_KEY_DIFFICULTY);
        let bytes = data?;
        String::from_utf8(bytes).ok()?.trim().parse::<u32>().ok()
    }
}
