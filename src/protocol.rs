//! Logique de decision, sans aucun appel a l'hote.
//!
//! `Engine::handle` prend une vue de la requete (`HostView`) et rend un verdict.
//! L'adaptateur Proxy-WASM n'a plus qu'a appliquer le verdict par des hostcalls.
//! C'est ce qui rend le comportement complet testable : les tests fournissent
//! une vue fabriquee et verifient le verdict, et peuvent meme verifier **quels**
//! faits ont ete lus, donc que le chemin rapide ne touche pas a la connexion.

use crate::client;
use crate::config::{Config, IpSource};
use crate::cookie;
use crate::token::{self, ClientContext, SaltDeriver, SignedChallenge, Solution};

/// Taille du sel d'un challenge, en octets.
const CHALLENGE_SALT_LEN: usize = 32;

/// D'ou vient la difficulte retenue, pour les journaux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifficultySource {
    /// Valeur configuree.
    Config,
    /// Valeur courante ajustee par la pression mesuree.
    Dynamic,
}

impl DifficultySource {
    pub fn as_str(self) -> &'static str {
        match self {
            DifficultySource::Config => "config",
            DifficultySource::Dynamic => "dynamique",
        }
    }
}

/// Ce qu'on fait d'une requete qui n'a pas de preuve valable.
///
/// Trois issues, et une seule par defaut. La decision vient d'une couche
/// exterieure (le moteur de scoring), qui la transmet dans l'en-tete interne
/// `x-challenge-action`. Cet en-tete doit etre ecrase par le bord : lu depuis le
/// client, il laisserait choisir sa propre sanction.
///
/// En l'absence d'en-tete, ou sur une valeur inconnue, on retombe sur la preuve
/// de travail : c'est l'issue la plus douce qui filtre quand meme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remediation {
    /// Refuser sans rien demander : la requete est rejetee.
    Drop,
    /// Servir un captcha interactif, resolu par un service de verification.
    Captcha,
    /// Servir le challenge de preuve de travail. Defaut.
    Pow,
}

impl Remediation {
    /// Lit une valeur d'en-tete. Tout ce qui n'est pas reconnu vaut `Pow`.
    pub fn parse(raw: Option<&str>) -> Remediation {
        match raw.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("drop") | Some("deny") | Some("block") => Remediation::Drop,
            Some("captcha") => Remediation::Captcha,
            Some("pow") | Some("challenge") => Remediation::Pow,
            _ => Remediation::Pow,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Remediation::Drop => "drop",
            Remediation::Captcha => "captcha",
            Remediation::Pow => "pow",
        }
    }
}

/// Faits de la requete, lus a la demande dans l'hote.
///
/// Chaque methode correspond a un hostcall ou a une lecture d'en-tete. Les
/// methodes ne sont appelees que lorsqu'elles sont necessaires : c'est le
/// contrat que verifient les tests de chemin rapide.
pub trait HostView {
    /// En-tete `Cookie` de la requete.
    fn cookie_header(&self) -> Option<String>;
    /// En-tete `challenge-token`, utilise par les clients non navigateur.
    fn token_header(&self) -> Option<String>;
    /// Propriete `source.address` : l'adresse du pair TCP.
    fn peer_address(&self) -> Option<String>;
    /// En-tete `X-Forwarded-For`.
    fn forwarded_for(&self) -> Option<String>;
    /// En-tete `X-Real-IP`.
    fn real_ip(&self) -> Option<String>;
    /// Propriete `connection.id` de la connexion descendante, en octets bruts.
    ///
    /// L'ABI rend un entier de 8 octets petit-boutistes qui n'est pas de
    /// l'UTF-8 : la conversion en texte se fait dans `client::connection_id`.
    fn connection_id(&self) -> Option<Vec<u8>>;
    /// En-tete interne `x-challenge-action`, pose par la couche de scoring.
    ///
    /// Il n'est jamais lu depuis le client : le bord l'ecrase a l'entree.
    fn remediation_hint(&self) -> Option<String>;
    /// Requete arrivee en HTTPS, pour le drapeau `Secure` des cookies.
    fn is_https(&self) -> bool;
}

/// Bornes et valeur courante de la difficulte.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub base: u32,
    pub min: u32,
    pub max: u32,
    pub current: u32,
}

impl Policy {
    pub fn from_config(config: &Config) -> Policy {
        Policy {
            base: config.base_difficulty,
            min: config.min_difficulty,
            max: config.max_difficulty,
            current: 0,
        }
    }

    /// Ramene une valeur dans les bornes.
    pub fn clamp(&self, d: u32) -> u32 {
        d.clamp(self.min, self.max)
    }

    /// Difficulte a utiliser pour un nouveau challenge.
    ///
    /// Priorite : valeur courante ajustee par la pression, puis valeur de
    /// configuration. Aucun client ne peut imposer sa difficulte : la seule
    /// entree exterieure est la remediation, pas un nombre.
    pub fn effective(&self) -> (u32, DifficultySource) {
        if self.current > 0 {
            return (self.clamp(self.current), DifficultySource::Dynamic);
        }
        (self.clamp(self.base), DifficultySource::Config)
    }
}

/// Verdict rendu par le moteur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// La requete passe telle quelle.
    Pass,
    /// La requete passe, et une clearance doit etre posee sur la reponse.
    Grant(ClearanceGrant),
    /// La requete doit recevoir un challenge de preuve de travail.
    Challenge(ChallengeOrder),
    /// La requete doit recevoir un captcha interactif.
    ///
    /// Le module sert la page et laisse la verification a un service dedie :
    /// lui seul peut valider un jeton de captcha aupres du fournisseur.
    Captcha,
    /// La requete est refusee sans rien demander.
    Drop,
}

/// Clearance a poser sur la reponse, une fois la solution acceptee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearanceGrant {
    pub token: String,
    pub max_age: i64,
    pub secure: bool,
}

/// Challenge a servir, avec ce qu'il faut pour journaliser et poser les cookies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeOrder {
    pub signed: SignedChallenge,
    pub difficulty: u32,
    pub source: DifficultySource,
    pub max_age: i64,
    pub secure: bool,
}

/// Le moteur : secret, bornes de difficulte, sequence de sel, compteur.
///
/// Une seule instance par plugin. Le Wasm est mono-thread, donc aucun verrou.
#[derive(Debug)]
pub struct Engine {
    key: Vec<u8>,
    ip_source: IpSource,
    policy: Policy,
    salts: SaltDeriver,
    /// Challenges emis depuis le dernier `tick`, pour la difficulte dynamique.
    issued_in_window: u64,
}

impl Engine {
    pub fn new(config: &Config) -> Engine {
        Engine {
            key: config.key().to_vec(),
            ip_source: config.ip_source,
            policy: Policy::from_config(config),
            salts: SaltDeriver::new(config.key()),
            issued_in_window: 0,
        }
    }

    /// Difficulte courante, telle que publiee dans les donnees partagees.
    pub fn current_difficulty(&self) -> u32 {
        self.policy.current
    }

    /// Reprend une difficulte courante publiee par une autre instance.
    ///
    /// Utile quand plusieurs machines virtuelles Wasm se partagent l'etat via
    /// les donnees partagees de l'hote.
    pub fn adopt_current_difficulty(&mut self, value: u32) {
        if value > 0 {
            self.policy.current = self.policy.clamp(value);
        }
    }

    /// Recalcule la difficulte courante d'apres le nombre de challenges emis
    /// depuis le dernier appel, puis remet le compteur a zero.
    ///
    /// Les seuils sont ceux de la version Go ; ce sont des heuristiques de
    /// depart, a ajuster sur du trafic reel.
    pub fn tick(&mut self) -> u32 {
        let recent = core::mem::take(&mut self.issued_in_window);

        let delta = match recent {
            r if r >= 800 => 6,
            r if r >= 400 => 4,
            r if r >= 180 => 3,
            r if r >= 80 => 2,
            r if r >= 35 => 1,
            _ => 0,
        };

        self.policy.current = self.policy.clamp(self.policy.base.saturating_add(delta));
        self.policy.current
    }

    /// Challenges emis depuis le dernier `tick`.
    pub fn issued_in_window(&self) -> u64 {
        self.issued_in_window
    }

    /// Resout l'adresse client selon la politique configuree.
    pub fn resolve_ip<V: HostView>(&self, view: &V) -> String {
        if let Some(ip) = view
            .peer_address()
            .as_deref()
            .and_then(client::normalize_ip)
        {
            return ip;
        }

        if self.ip_source == IpSource::Peer {
            return String::new();
        }

        if let Some(ip) = view
            .forwarded_for()
            .and_then(|h| client::first_forwarded_ip(&h))
        {
            return ip;
        }

        if let Some(ip) = view.real_ip().as_deref().and_then(client::normalize_ip) {
            return ip;
        }

        String::new()
    }

    /// Identite complete : adresse et identifiant de connexion.
    fn resolve_client<V: HostView>(&self, view: &V) -> ClientContext {
        ClientContext {
            ip: self.resolve_ip(view),
            cid: view
                .connection_id()
                .and_then(|raw| client::connection_id(&raw))
                .unwrap_or_default(),
        }
    }

    /// Emet une clearance pour un client deja authentifie.
    pub fn mint_clearance(&mut self, client: &ClientContext, now: i64) -> ClearanceGrant {
        let salt = self.salts.next_bytes(now, token::CLEARANCE_SALT_LEN);
        ClearanceGrant {
            token: token::issue_clearance(&self.key, client.clearance_bind(), now, &salt),
            max_age: crate::CLEARANCE_LIFETIME_SECS as i64,
            secure: false,
        }
    }

    /// Decide du sort d'une requete.
    ///
    /// Ordre volontaire, herite de la version Go : le cookie de clearance est
    /// teste en premier, et ce chemin ne lit que l'adresse du client. La
    /// connexion, le schema et la difficulte ne sont lus que si la clearance
    /// est absente ou invalide.
    pub fn handle<V: HostView>(&mut self, view: &V, now: i64) -> Verdict {
        let raw_cookie = view.cookie_header();
        let cookies = cookie::parse_challenge_cookies(raw_cookie.as_deref().unwrap_or(""));

        // 1) Clearance : le chemin chaud, apres une resolution reussie.
        if cookies.has_clearance() {
            let ip = self.resolve_ip(view);
            if token::verify_clearance(&self.key, &cookies.clearance, &ip, now).is_ok() {
                return Verdict::Pass;
            }
        }

        // 2) Solution par cookies, valable une fois.
        let client = self.resolve_client(view);
        let secure = view.is_https();

        if cookies.has_solution_parts() {
            match cookies.nonce_value() {
                Some(nonce) => {
                    let sol = Solution {
                        c: cookies.challenge.clone(),
                        s: cookies.signature.clone(),
                        n: nonce,
                    };
                    if token::verify_solution(&self.key, &sol, &client, now).is_ok() {
                        let mut grant = self.mint_clearance(&client, now);
                        grant.secure = secure;
                        return Verdict::Grant(grant);
                    }
                }
                None => {
                    // Nonce illisible : on retombe sur l'emission d'un challenge.
                }
            }
        }

        // 3) En-tete `challenge-token`, pour les clients qui ne gerent pas les
        //    cookies : un jeton JSON {c,s,n}.
        if let Some(raw) = view.token_header() {
            if let Ok(sol) = serde_json::from_str::<Solution>(&raw) {
                if token::verify_solution(&self.key, &sol, &client, now).is_ok() {
                    let mut grant = self.mint_clearance(&client, now);
                    grant.secure = secure;
                    return Verdict::Grant(grant);
                }
            }
        }

        // 4) Aucune preuve valable : la couche de scoring decide de l'issue.
        //
        // Sans en-tete, on sert une preuve de travail : c'est le defaut, et
        // c'est aussi ce qui se passe si le scoring est indisponible.
        match Remediation::parse(view.remediation_hint().as_deref()) {
            Remediation::Drop => Verdict::Drop,

            Remediation::Captcha => Verdict::Captcha,

            Remediation::Pow => {
                let (difficulty, source) = self.policy.effective();
                let salt = self.salts.next_bytes(now, CHALLENGE_SALT_LEN);
                let signed = token::issue_challenge(&self.key, difficulty, &client, now, &salt);

                self.issued_in_window = self.issued_in_window.saturating_add(1);

                Verdict::Challenge(ChallengeOrder {
                    signed,
                    difficulty,
                    source,
                    max_age: crate::CHALLENGE_LIFETIME_SECS as i64,
                    secure,
                })
            }
        }
    }
}

/// Les quatre cookies d'une reponse de challenge, dans l'ordre d'emission.
///
/// Le nonce et la clearance precedents sont effaces : un challenge frais
/// invalide les restes d'une tentative precedente.
pub fn challenge_cookie_headers(order: &ChallengeOrder) -> Vec<(String, String)> {
    vec![
        (
            "Set-Cookie".to_string(),
            cookie::set_cookie(
                cookie::CHALLENGE_COOKIE,
                &order.signed.c,
                order.max_age,
                false,
                order.secure,
            ),
        ),
        (
            "Set-Cookie".to_string(),
            cookie::set_cookie(
                cookie::SIGNATURE_COOKIE,
                &order.signed.s,
                order.max_age,
                false,
                order.secure,
            ),
        ),
        (
            "Set-Cookie".to_string(),
            cookie::clear_cookie(cookie::NONCE_COOKIE, order.secure),
        ),
        (
            "Set-Cookie".to_string(),
            cookie::clear_cookie(cookie::CLEARANCE_COOKIE, order.secure),
        ),
        (cookie::SIGNATURE_COOKIE.to_string(), order.signed.s.clone()),
    ]
}

/// Efface les cookies d'une solution acceptee, une fois la clearance posee.
pub fn solution_cookie_cleanup(secure: bool) -> Vec<(String, String)> {
    [
        cookie::CHALLENGE_COOKIE,
        cookie::SIGNATURE_COOKIE,
        cookie::NONCE_COOKIE,
    ]
    .into_iter()
    .map(|name| ("Set-Cookie".to_string(), cookie::clear_cookie(name, secure)))
    .collect()
}

/// Cookie de clearance a poser apres une solution acceptee.
pub fn clearance_cookie_header(grant: &ClearanceGrant) -> (String, String) {
    (
        "Set-Cookie".to_string(),
        cookie::set_cookie(
            cookie::CLEARANCE_COOKIE,
            &grant.token,
            grant.max_age,
            true,
            grant.secure,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cookie::ChallengeCookies;
    use core::cell::RefCell;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct MockView {
        cookies: Option<String>,
        token: Option<String>,
        peer: Option<String>,
        xff: Option<String>,
        real: Option<String>,
        cid: Option<Vec<u8>>,
        action_hint: Option<String>,
        https: bool,
        reads: RefCell<Vec<&'static str>>,
    }

    impl MockView {
        fn new() -> MockView {
            MockView::default()
        }

        fn reads(&self) -> Vec<&'static str> {
            self.reads.borrow().clone()
        }
    }

    macro_rules! read {
        ($self:ident, $name:literal, $value:expr) => {{
            $self.reads.borrow_mut().push($name);
            $value
        }};
    }

    impl HostView for MockView {
        fn cookie_header(&self) -> Option<String> {
            read!(self, "cookie", self.cookies.clone())
        }
        fn token_header(&self) -> Option<String> {
            read!(self, "token", self.token.clone())
        }
        fn peer_address(&self) -> Option<String> {
            read!(self, "peer", self.peer.clone())
        }
        fn forwarded_for(&self) -> Option<String> {
            read!(self, "xff", self.xff.clone())
        }
        fn real_ip(&self) -> Option<String> {
            read!(self, "real-ip", self.real.clone())
        }
        fn connection_id(&self) -> Option<Vec<u8>> {
            read!(self, "cid", self.cid.clone())
        }
        fn remediation_hint(&self) -> Option<String> {
            read!(self, "action", self.action_hint.clone())
        }
        fn is_https(&self) -> bool {
            self.reads.borrow_mut().push("https");
            self.https
        }
    }

    fn engine() -> Engine {
        let config = Config::from_json(
            format!(r#"{{"secret":"{SECRET}","base_difficulty":8,"min_difficulty":6,"max_difficulty":26}}"#)
                .as_bytes(),
        )
        .expect("config");
        Engine::new(&config)
    }

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn anonymous_request_gets_a_challenge() {
        let mut e = engine();
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9:41022".into());

        match e.handle(&view, NOW) {
            Verdict::Challenge(order) => {
                assert_eq!(order.difficulty, 8);
                assert_eq!(order.source, DifficultySource::Config);
                assert_eq!(order.max_age, 60);
                assert!(!order.secure);
                // Le challenge est verifiable avec le secret du moteur.
                let sol = Solution {
                    c: order.signed.c.clone(),
                    s: order.signed.s.clone(),
                    n: token::solve(&order.signed.c, order.difficulty, 1 << 22).unwrap(),
                };
                assert!(token::verify_solution(
                    SECRET.as_bytes(),
                    &sol,
                    &ClientContext::new("203.0.113.9", ""),
                    NOW
                )
                .is_ok());
            }
            other => panic!("attendu Challenge, obtenu {other:?}"),
        }
        assert_eq!(e.issued_in_window(), 1);
    }

    #[test]
    fn challenge_carries_the_client_connection_id() {
        let mut e = engine();
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());
        view.cid = Some(1234u64.to_le_bytes().to_vec());

        let order = match e.handle(&view, NOW) {
            Verdict::Challenge(order) => order,
            other => panic!("attendu Challenge, obtenu {other:?}"),
        };

        let payload = decode_payload(&order.signed.c);
        assert_eq!(payload.ctx, "203.0.113.9");
        assert_eq!(payload.cid, "1234");
    }

    #[test]
    fn solving_the_challenge_grants_clearance() {
        let mut e = engine();
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());
        view.cid = Some(1234u64.to_le_bytes().to_vec());
        view.https = true;

        let order = match e.handle(&view, NOW) {
            Verdict::Challenge(order) => order,
            other => panic!("attendu Challenge, obtenu {other:?}"),
        };

        let nonce = token::solve(&order.signed.c, order.difficulty, 1 << 22).unwrap();
        let mut solved = MockView::new();
        solved.peer = Some("203.0.113.9".into());
        solved.cid = Some(1234u64.to_le_bytes().to_vec());
        // Le drapeau Secure suit la requete qui presente la solution, pas celle
        // qui a porte le challenge.
        solved.https = true;
        solved.cookies = Some(format!(
            "challenge={}; challenge-sig={}; challenge-nonce={nonce}",
            order.signed.c, order.signed.s
        ));

        let grant = match e.handle(&solved, NOW + 1) {
            Verdict::Grant(grant) => grant,
            other => panic!("attendu Grant, obtenu {other:?}"),
        };
        assert!(
            grant.secure,
            "le drapeau Secure suit le schema de la requete"
        );
        assert_eq!(grant.max_age, 1800);

        // Le cookie pose est HttpOnly : le JavaScript de la page ne doit pas
        // pouvoir lire la clearance.
        let (_, clearance_cookie) = clearance_cookie_header(&grant);
        assert!(clearance_cookie.contains("HttpOnly"));
        assert!(clearance_cookie.contains("Secure"));
        assert!(clearance_cookie.contains("Max-Age=1800"));

        // Meme parcours en clair : la clearance est emise sans Secure.
        let mut plain = MockView::new();
        plain.peer = Some("203.0.113.9".into());
        plain.cid = Some(1234u64.to_le_bytes().to_vec());
        plain.cookies = Some(format!(
            "challenge={}; challenge-sig={}; challenge-nonce={nonce}",
            order.signed.c, order.signed.s
        ));
        match e.handle(&plain, NOW + 1) {
            Verdict::Grant(grant) => assert!(!grant.secure),
            other => panic!("attendu Grant, obtenu {other:?}"),
        }

        // La clearance emise vaut pour la suite, sur une nouvelle connexion.
        let mut later = MockView::new();
        later.peer = Some("203.0.113.9".into());
        later.cookies = Some(format!("challenge-clearance={}", grant.token));
        assert_eq!(e.handle(&later, NOW + 2), Verdict::Pass);
    }

    #[test]
    fn valid_clearance_skips_connection_and_scheme_reads() {
        let mut e = engine();
        let client = ClientContext::new("203.0.113.9", "1234");
        let grant = e.mint_clearance(&client, NOW);

        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());
        view.cid = Some(1234u64.to_le_bytes().to_vec());
        view.cookies = Some(format!("challenge-clearance={}", grant.token));

        assert_eq!(e.handle(&view, NOW + 5), Verdict::Pass);

        let reads = view.reads();
        assert!(reads.contains(&"cookie"), "le cookie a bien ete lu");
        assert!(reads.contains(&"peer"), "l'adresse a bien ete lue");
        assert!(
            !reads.contains(&"cid"),
            "le chemin rapide ne doit pas lire l'identifiant de connexion : {reads:?}"
        );
        assert!(
            !reads.contains(&"https"),
            "le chemin rapide ne doit pas lire le schema : {reads:?}"
        );
        assert!(
            !reads.contains(&"diff"),
            "le chemin rapide ne doit pas lire la difficulte : {reads:?}"
        );
    }

    #[test]
    fn clearance_for_another_ip_is_refused() {
        let mut e = engine();
        let client = ClientContext::new("203.0.113.9", "");
        let grant = e.mint_clearance(&client, NOW);

        let mut view = MockView::new();
        view.peer = Some("198.51.100.7".into());
        view.cookies = Some(format!("challenge-clearance={}", grant.token));

        match e.handle(&view, NOW + 1) {
            Verdict::Challenge(_) => {}
            other => panic!("attendu Challenge, obtenu {other:?}"),
        }
    }

    #[test]
    fn expired_clearance_is_refused() {
        let mut e = engine();
        let client = ClientContext::new("203.0.113.9", "");
        let grant = e.mint_clearance(&client, NOW);

        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());
        view.cookies = Some(format!("challenge-clearance={}", grant.token));

        match e.handle(&view, NOW + 1801) {
            Verdict::Challenge(_) => {}
            other => panic!("attendu Challenge, obtenu {other:?}"),
        }
    }

    #[test]
    fn forged_clearance_is_refused() {
        let mut e = engine();
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());
        view.cookies = Some("challenge-clearance=Y29ycHM.sig".into());

        match e.handle(&view, NOW) {
            Verdict::Challenge(_) => {}
            other => panic!("attendu Challenge, obtenu {other:?}"),
        }
    }

    #[test]
    fn solution_from_another_connection_is_refused() {
        let mut e = engine();
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());
        view.cid = Some(1234u64.to_le_bytes().to_vec());

        let order = match e.handle(&view, NOW) {
            Verdict::Challenge(order) => order,
            other => panic!("attendu Challenge, obtenu {other:?}"),
        };
        let nonce = token::solve(&order.signed.c, order.difficulty, 1 << 22).unwrap();

        // Meme IP, mais connexion differente : le challenge ne se rejoue pas.
        let mut replay = MockView::new();
        replay.peer = Some("203.0.113.9".into());
        replay.cid = Some(5678u64.to_le_bytes().to_vec());
        replay.cookies = Some(format!(
            "challenge={}; challenge-sig={}; challenge-nonce={nonce}",
            order.signed.c, order.signed.s
        ));

        match e.handle(&replay, NOW + 1) {
            Verdict::Challenge(_) => {}
            other => panic!("attendu Challenge, obtenu {other:?}"),
        }
    }

    #[test]
    fn token_header_grants_clearance() {
        let mut e = engine();
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());

        let order = match e.handle(&view, NOW) {
            Verdict::Challenge(order) => order,
            other => panic!("attendu Challenge, obtenu {other:?}"),
        };
        let nonce = token::solve(&order.signed.c, order.difficulty, 1 << 22).unwrap();
        let token = serde_json::json!({ "c": order.signed.c, "s": order.signed.s, "n": nonce });

        let mut api = MockView::new();
        api.peer = Some("203.0.113.9".into());
        api.token = Some(token.to_string());

        match e.handle(&api, NOW + 1) {
            Verdict::Grant(grant) => assert!(grant.token.contains('.')),
            other => panic!("attendu Grant, obtenu {other:?}"),
        }
    }

    #[test]
    fn malformed_token_header_falls_through_to_a_challenge() {
        let mut e = engine();
        for token in [
            "pas du json",
            "{}",
            r#"{"c":1}"#,
            r#"{"c":"a","s":"b","n":"x"}"#,
        ] {
            let mut view = MockView::new();
            view.peer = Some("203.0.113.9".into());
            view.token = Some(token.to_string());
            match e.handle(&view, NOW) {
                Verdict::Challenge(_) => {}
                other => panic!("entree {token:?} : attendu Challenge, obtenu {other:?}"),
            }
        }
    }

    #[test]
    fn incomplete_solution_cookies_fall_through() {
        let mut e = engine();
        for cookies in [
            "challenge=abc",
            "challenge=abc; challenge-sig=def",
            "challenge=abc; challenge-sig=def; challenge-nonce=pas-un-nombre",
        ] {
            let mut view = MockView::new();
            view.peer = Some("203.0.113.9".into());
            view.cookies = Some(cookies.to_string());
            match e.handle(&view, NOW) {
                Verdict::Challenge(_) => {}
                other => panic!("cookies {cookies:?} : attendu Challenge, obtenu {other:?}"),
            }
        }
    }

    #[test]
    fn remediation_hint_selects_the_outcome() {
        let mut e = engine();

        // Sans en-tete, ou avec une valeur inconnue, on sert une preuve de
        // travail : c'est le defaut, et il resiste a une couche de scoring
        // absente ou fautive.
        for given in [None, Some(""), Some("n'importe quoi"), Some("pow")] {
            let mut view = MockView::new();
            view.peer = Some("203.0.113.9".into());
            view.action_hint = given.map(|v| v.to_string());
            match e.handle(&view, NOW) {
                Verdict::Challenge(order) => {
                    assert_eq!(order.difficulty, 8, "difficulte pour {given:?}");
                    assert_eq!(order.source, DifficultySource::Config);
                }
                other => panic!("{given:?} : attendu Challenge, obtenu {other:?}"),
            }
        }

        for given in ["captcha", "CAPTCHA"] {
            let mut view = MockView::new();
            view.peer = Some("203.0.113.9".into());
            view.action_hint = Some(given.to_string());
            assert_eq!(e.handle(&view, NOW), Verdict::Captcha, "pour {given:?}");
        }

        for given in ["drop", "DENY", "block"] {
            let mut view = MockView::new();
            view.peer = Some("203.0.113.9".into());
            view.action_hint = Some(given.to_string());
            assert_eq!(e.handle(&view, NOW), Verdict::Drop, "pour {given:?}");
        }
    }

    #[test]
    fn a_clearance_still_wins_over_a_remediation_hint() {
        // Un client deja valide ne doit pas etre puni parce qu'une couche de
        // scoring a mal note son adresse : la clearance passe avant tout.
        let mut e = engine();
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());

        let order = match e.handle(&view, NOW) {
            Verdict::Challenge(order) => order,
            other => panic!("attendu Challenge, obtenu {other:?}"),
        };
        let nonce = token::solve(&order.signed.c, order.difficulty, 1 << 22).unwrap();

        let clearance = match e.handle(
            &{
                let mut v = MockView::new();
                v.peer = Some("203.0.113.9".into());
                v.cookies = Some(format!(
                    "challenge={}; challenge-sig={}; challenge-nonce={nonce}",
                    order.signed.c, order.signed.s
                ));
                v
            },
            NOW + 1,
        ) {
            Verdict::Grant(g) => g,
            other => panic!("attendu Grant, obtenu {other:?}"),
        };

        let mut scored = MockView::new();
        scored.peer = Some("203.0.113.9".into());
        scored.cookies = Some(format!("challenge-clearance={}", clearance.token));
        scored.action_hint = Some("drop".to_string());

        assert_eq!(e.handle(&scored, NOW + 2), Verdict::Pass);
    }

    #[test]
    fn dynamic_difficulty_follows_pressure() {
        let mut e = engine();
        let config = Config::from_json(
            format!(r#"{{"secret":"{SECRET}","base_difficulty":8,"min_difficulty":6,"max_difficulty":10}}"#)
                .as_bytes(),
        )
        .unwrap();
        let mut e2 = Engine::new(&config);

        // Aucune emission : on revient a la valeur de base.
        assert_eq!(e.tick(), 8);

        // 35 emissions dans la fenetre : +1.
        for _ in 0..35 {
            let mut view = MockView::new();
            view.peer = Some("203.0.113.9".into());
            let _ = e.handle(&view, NOW);
        }
        assert_eq!(e.tick(), 9);
        assert_eq!(e.issued_in_window(), 0);

        // 400 emissions : +4, mais borne par max.
        for _ in 0..400 {
            let mut view = MockView::new();
            view.peer = Some("203.0.113.9".into());
            let _ = e2.handle(&view, NOW);
        }
        assert_eq!(e2.tick(), 10, "la borne haute s'applique");

        // La difficulte courante est ensuite utilisee, et l'en-tete la supplante.
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());
        match e2.handle(&view, NOW) {
            Verdict::Challenge(order) => {
                assert_eq!(order.difficulty, 10);
                assert_eq!(order.source, DifficultySource::Dynamic);
            }
            other => panic!("attendu Challenge, obtenu {other:?}"),
        }
    }

    #[test]
    fn ip_source_peer_ignores_forwarding_headers() {
        let config = Config::from_json(
            format!(r#"{{"secret":"{SECRET}","client_ip_source":"source_address"}}"#).as_bytes(),
        )
        .unwrap();
        let mut e = Engine::new(&config);

        let mut view = MockView::new();
        view.xff = Some("198.51.100.7".into());
        view.real = Some("198.51.100.8".into());

        match e.handle(&view, NOW) {
            Verdict::Challenge(order) => {
                let payload = decode_payload(&order.signed.c);
                assert_eq!(payload.ctx, "", "aucun en-tete de transfert n'est cru");
            }
            other => panic!("attendu Challenge, obtenu {other:?}"),
        }

        let reads = view.reads();
        assert!(
            !reads.contains(&"xff"),
            "X-Forwarded-For ne doit pas etre lu : {reads:?}"
        );
        assert!(
            !reads.contains(&"real-ip"),
            "X-Real-IP ne doit pas etre lu : {reads:?}"
        );
    }

    #[test]
    fn ip_source_auto_prefers_peer_then_forwarded_for() {
        let mut e = engine();

        // Le pair TCP prime, meme si l'en-tete annonce autre chose.
        let mut with_peer = MockView::new();
        with_peer.peer = Some("203.0.113.9:5555".into());
        with_peer.xff = Some("198.51.100.7".into());
        if let Verdict::Challenge(order) = e.handle(&with_peer, NOW) {
            assert_eq!(decode_payload(&order.signed.c).ctx, "203.0.113.9");
        } else {
            panic!("attendu Challenge");
        }
        assert!(!with_peer.reads().contains(&"xff"));

        // Sans pair exploitable : le premier element de X-Forwarded-For.
        let mut without_peer = MockView::new();
        without_peer.xff = Some("198.51.100.7, 10.0.0.1".into());
        without_peer.real = Some("10.0.0.9".into());
        if let Verdict::Challenge(order) = e.handle(&without_peer, NOW) {
            assert_eq!(decode_payload(&order.signed.c).ctx, "198.51.100.7");
        } else {
            panic!("attendu Challenge");
        }

        // Puis X-Real-IP en dernier recours.
        let mut real_only = MockView::new();
        real_only.real = Some("10.0.0.9".into());
        if let Verdict::Challenge(order) = e.handle(&real_only, NOW) {
            assert_eq!(decode_payload(&order.signed.c).ctx, "10.0.0.9");
        } else {
            panic!("attendu Challenge");
        }
    }

    #[test]
    fn each_challenge_has_its_own_salt() {
        let mut e = engine();
        let mut view = MockView::new();
        view.peer = Some("203.0.113.9".into());

        let first = match e.handle(&view, NOW) {
            Verdict::Challenge(order) => order,
            other => panic!("{other:?}"),
        };
        let second = match e.handle(&view, NOW) {
            Verdict::Challenge(order) => order,
            other => panic!("{other:?}"),
        };

        assert_ne!(first.signed.c, second.signed.c);
        assert_ne!(first.signed.s, second.signed.s);
        assert_ne!(
            decode_payload(&first.signed.c).salt,
            decode_payload(&second.signed.c).salt
        );
    }

    #[test]
    fn challenge_response_headers_are_complete() {
        let order = ChallengeOrder {
            signed: SignedChallenge {
                c: "CHAL".into(),
                s: "SIG".into(),
            },
            difficulty: 18,
            source: DifficultySource::Config,
            max_age: 60,
            secure: true,
        };

        let headers = challenge_cookie_headers(&order);
        let set_cookies: Vec<&str> = headers
            .iter()
            .filter(|(k, _)| k == "Set-Cookie")
            .map(|(_, v)| v.as_str())
            .collect();

        assert_eq!(set_cookies.len(), 4, "deux cookies poses, deux effaces");
        assert_eq!(
            set_cookies[0],
            "challenge=CHAL; Path=/; Max-Age=60; SameSite=Lax; Secure"
        );
        assert_eq!(
            set_cookies[1],
            "challenge-sig=SIG; Path=/; Max-Age=60; SameSite=Lax; Secure"
        );
        assert_eq!(
            set_cookies[2],
            "challenge-nonce=; Path=/; Max-Age=0; SameSite=Lax; Secure"
        );
        assert_eq!(
            set_cookies[3],
            "challenge-clearance=; Path=/; Max-Age=0; SameSite=Lax; Secure; HttpOnly"
        );
        // La signature est aussi exposee en en-tete, pour les clients sans cookie.
        assert!(headers.contains(&("challenge-sig".to_string(), "SIG".to_string())));
    }

    #[test]
    fn clearance_cookie_is_httponly() {
        let grant = ClearanceGrant {
            token: "corps.sig".into(),
            max_age: 1800,
            secure: false,
        };
        let (name, value) = clearance_cookie_header(&grant);
        assert_eq!(name, "Set-Cookie");
        assert_eq!(
            value,
            "challenge-clearance=corps.sig; Path=/; Max-Age=1800; SameSite=Lax; HttpOnly"
        );

        let cleanup = solution_cookie_cleanup(true);
        assert_eq!(cleanup.len(), 3);
        assert!(cleanup
            .iter()
            .all(|(_, v)| v.contains("Max-Age=0") && v.contains("Secure")));
    }

    fn decode_payload(challenge: &str) -> token::ChallengePayload {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine as _;
        serde_json::from_slice(&B64.decode(challenge.as_bytes()).expect("base64")).expect("json")
    }

    #[test]
    fn cookies_struct_helpers_are_used_by_engine() {
        // Garde-fou : les aides de lecture de cookies restent coherentes avec
        // celles utilisees par le moteur.
        let parsed = ChallengeCookies {
            clearance: "x".into(),
            ..Default::default()
        };
        assert!(parsed.has_clearance());
        assert!(!parsed.has_solution_parts());
    }
}
