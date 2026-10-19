//! Adaptateur Proxy-WASM : lecture des faits de la requete, application du
//! verdict rendu par `protocol::Engine`.
//!
//! Aucune decision n'est prise ici. Si tu lis une regle metier dans ce fichier,
//! c'est qu'elle est au mauvais endroit : elle doit descendre dans `protocol`,
//! ou elle sera testable.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::UNIX_EPOCH;

use proxy_wasm::traits::{Context, HttpContext};
use proxy_wasm::types::Action;

use crate::plugin::Shared;
use crate::protocol::{self, HostView, Verdict};
use crate::{log_debug, log_error};

/// Page servie avec le challenge.
///
/// C'est le client JavaScript du depot d'origine, repris tel quel : le format
/// sur le fil ne change pas, donc le solveur non plus. Voir la note de licence
/// dans le README du plugin.
const CHALLENGE_HTML: &str = include_str!("../assets/challenge.html");

/// Page servie quand le scoring demande un captcha interactif.
///
/// Elle ne verifie rien par elle-meme : elle charge le composant, puis poste le
/// jeton a `/__challenge/captcha`, que l'infrastructure route vers le service de
/// verification. Le module ne peut pas valider un jeton de captcha aupres d'un
/// fournisseur : il n'a pas de sortie reseau garantie, et la cle de verification
/// n'a rien a faire dans un binaire distribue.
const CAPTCHA_HTML: &str = include_str!("../assets/captcha.html");

/// Contexte HTTP : un par flux.
pub struct PowHttp {
    shared: Rc<RefCell<Shared>>,
    /// Clearance a poser sur la reponse, quand une solution vient d'etre
    /// acceptee. La version Go fait le meme report : l'en-tete de reponse n'est
    /// ecrit qu'une fois la reponse de l'origine en cours de construction.
    grant: Option<protocol::ClearanceGrant>,
}

impl PowHttp {
    pub fn new(shared: Rc<RefCell<Shared>>) -> PowHttp {
        PowHttp {
            shared,
            grant: None,
        }
    }
}

impl Context for PowHttp {}

impl HostView for PowHttp {
    fn cookie_header(&self) -> Option<String> {
        self.get_http_request_header("cookie")
    }

    fn token_header(&self) -> Option<String> {
        self.get_http_request_header("challenge-token")
    }

    fn peer_address(&self) -> Option<String> {
        self.get_property(vec!["source", "address"])
            .and_then(|raw| String::from_utf8(raw).ok())
    }

    fn forwarded_for(&self) -> Option<String> {
        self.get_http_request_header("x-forwarded-for")
    }

    fn real_ip(&self) -> Option<String> {
        self.get_http_request_header("x-real-ip")
    }

    /// Octets bruts : l'ABI rend un entier de 8 octets petit-boutistes, qui
    /// n'est pas de l'UTF-8 valide. Le decodage se fait dans `client`.
    fn connection_id(&self) -> Option<Vec<u8>> {
        self.get_property(vec!["connection", "id"])
    }

    /// En-tete interne de remediation, pose par la couche de scoring.
    ///
    /// Le bord doit l'ecraser a l'entree : un client qui l'ecrit lui-meme
    /// choisirait sa propre sanction.
    fn remediation_hint(&self) -> Option<String> {
        self.get_http_request_header("x-challenge-action")
    }

    fn is_https(&self) -> bool {
        if let Some(scheme) = self.get_http_request_header(":scheme") {
            return scheme.eq_ignore_ascii_case("https");
        }
        self.get_property(vec!["request", "scheme"])
            .and_then(|raw| String::from_utf8(raw).ok())
            .map(|scheme| scheme.eq_ignore_ascii_case("https"))
            .unwrap_or(false)
    }
}

impl HttpContext for PowHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let now = self
            .get_current_time()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let verdict = {
            let mut shared = self.shared.borrow_mut();
            shared.engine.handle(self, now)
        };

        match verdict {
            Verdict::Pass => Action::Continue,

            Verdict::Grant(grant) => {
                log_debug!("pow-proxy: solution acceptee, clearance en attente sur la reponse");
                self.grant = Some(grant);
                Action::Continue
            }

            Verdict::Challenge(order) => {
                log_debug!(
                    "pow-proxy: challenge emis (difficulte {} depuis {}, ctx={:?})",
                    order.difficulty,
                    order.source.as_str(),
                    order.signed.c.len()
                );
                if self.send_challenge(&order) {
                    Action::Pause
                } else {
                    // L'envoi a echoue : mieux vaut laisser passer la requete
                    // que de la bloquer sans reponse.
                    Action::Continue
                }
            }

            Verdict::Captcha => {
                log_debug!("pow-proxy: page de captcha servie");
                if self.send_response(403, CAPTCHA_HTML) {
                    Action::Pause
                } else {
                    Action::Continue
                }
            }

            Verdict::Drop => {
                // Refus sans challenge. Une vraie coupure de connexion ne
                // s'obtient pas depuis un filtre HTTP : on renvoie le minimum,
                // sans corps, et on laisse le client tirer la conclusion.
                log_debug!("pow-proxy: requete refusee sans challenge");
                if self.send_response(403, "") {
                    Action::Pause
                } else {
                    Action::Continue
                }
            }
        }
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if let Some(grant) = self.grant.take() {
            let secure = grant.secure;

            let (name, value) = protocol::clearance_cookie_header(&grant);
            self.add_http_response_header(&name, &value);

            // Les cookies de resolution ont rempli leur role : on les efface
            // pour que la solution brute ne serve pas de laissez-passer.
            for (name, value) in protocol::solution_cookie_cleanup(secure) {
                self.add_http_response_header(&name, &value);
            }

            log_debug!(
                "pow-proxy: clearance posee (max-age={}s, secure={secure})",
                grant.max_age
            );
        }

        let (header, value) = {
            let shared = self.shared.borrow();
            (shared.config.header.clone(), shared.config.value.clone())
        };
        if !header.is_empty() {
            self.add_http_response_header(&header, &value);
        }

        Action::Continue
    }
}

impl PowHttp {
    /// Envoie une reponse locale, jamais mise en cache.
    fn send_response(&self, status: u32, body: &str) -> bool {
        let headers: Vec<(&str, &str)> = vec![
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
        ];

        match proxy_wasm::hostcalls::send_http_response(status, headers, Some(body.as_bytes())) {
            Ok(()) => true,
            Err(err) => {
                log_error!("pow-proxy: envoi de la reponse impossible ({err:?})");
                false
            }
        }
    }

    /// Sert la page de challenge avec ses cookies. Rend `false` si l'envoi a
    /// echoue, auquel cas l'appelant ne doit pas interrompre la requete.
    fn send_challenge(&self, order: &protocol::ChallengeOrder) -> bool {
        let headers = protocol::challenge_cookie_headers(order);
        let pairs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();

        match proxy_wasm::hostcalls::send_http_response(403, pairs, Some(CHALLENGE_HTML.as_bytes()))
        {
            Ok(()) => true,
            Err(err) => {
                log_error!("pow-proxy: envoi du challenge impossible ({err:?})");
                false
            }
        }
    }
}
