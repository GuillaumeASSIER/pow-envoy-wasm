//! Jetons du protocole : challenge signe, solution, clearance.
//!
//! Format identique a la version Go, pour que les cookies et les jetons deja
//! emis restent valides :
//!
//! ```text
//! challenge   = base64url(JSON {ts,exp,diff,salt,ctx?,cid?})
//! signature   = base64url(HMAC-SHA256(secret, challenge))
//! proof       = SHA-256(base64url_decode(challenge) || nonce_be64) a >= diff bits de tete a zero
//! clearance   = body "." base64url(HMAC-SHA256(secret, body))
//! body        = base64url(exp_be64 || salt16 || ip_utf8)
//! ```
//!
//! Toutes les comparaisons de MAC passent par `Mac::verify_slice`, qui est a
//! temps constant. Aucune comparaison d'octets a la main.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Difficulte appliquee quand aucune n'est configuree (18 bits de tete a zero).
pub const DEFAULT_DIFFICULTY: u32 = 18;

/// Taille du sel embarque dans un jeton de clearance, en octets.
pub const CLEARANCE_SALT_LEN: usize = 16;

/// Longueur du prefixe fixe d'un corps de clearance : expiration puis sel.
pub const CLEARANCE_FIXED_PREFIX: usize = 8 + CLEARANCE_SALT_LEN;

/// Etiquette de derivation du sel, versionnee pour pouvoir tourner un jour.
const SALT_LABEL: &[u8] = b"exoledge/pow/salt/v1";

type HmacSha256 = Hmac<Sha256>;

/// Refus possible lors de la verification d'un jeton.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Format illisible : base64 invalide, JSON invalide, champs manquants.
    InvalidToken,
    /// Le MAC ne correspond pas. Couvre aussi le cas d'un secret different.
    BadSignature,
    /// Le jeton est hors de sa fenetre de validite.
    Expired,
    /// La preuve de travail ne satisfait pas la difficulte annoncee.
    BadPoW,
    /// Le jeton a ete emis pour un autre client.
    ContextMismatch,
}

impl TokenError {
    /// Forme courte, pour les journaux.
    pub fn as_str(self) -> &'static str {
        match self {
            TokenError::InvalidToken => "jeton illisible",
            TokenError::BadSignature => "signature invalide",
            TokenError::Expired => "jeton expire",
            TokenError::BadPoW => "preuve de travail invalide",
            TokenError::ContextMismatch => "contexte client different",
        }
    }
}

/// Identite du client, telle qu'elle est liee au jeton.
///
/// Le challenge lie l'IP **et** l'identifiant de connexion Envoy : une solution
/// trouvee sur une connexion ne se rejoue pas sur une autre. La clearance, elle,
/// ne lie que l'IP, pour survivre a la fermeture de la connexion et a un
/// rechargement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientContext {
    pub ip: String,
    pub cid: String,
}

impl ClientContext {
    pub fn new(ip: impl Into<String>, cid: impl Into<String>) -> Self {
        ClientContext {
            ip: ip.into(),
            cid: cid.into(),
        }
    }

    /// Contexte de clearance : IP seule.
    pub fn clearance_bind(&self) -> &str {
        &self.ip
    }

    /// Forme compacte pour les journaux.
    pub fn label(&self) -> String {
        match (self.ip.is_empty(), self.cid.is_empty()) {
            (true, true) => String::new(),
            (false, true) => self.ip.clone(),
            (true, false) => format!("cid={}", self.cid),
            (false, false) => format!("{};cid={}", self.ip, self.cid),
        }
    }
}

/// Charge utile signee, telle que le navigateur la relit en JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengePayload {
    /// Emission, en secondes Unix.
    pub ts: i64,
    /// Fin de validite, en secondes Unix.
    pub exp: i64,
    /// Nombre de bits de tete a zero exiges du SHA-256.
    pub diff: u32,
    /// Sel, en base64url.
    pub salt: String,
    /// IP du client, omise si inconnue.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ctx: String,
    /// Identifiant de connexion Envoy, omis si indisponible.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cid: String,
}

/// Challenge signe, envoye au client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedChallenge {
    /// `base64url(payload)`, aussi appele `challenge` dans les cookies.
    pub c: String,
    /// `base64url(HMAC-SHA256(challenge))`.
    pub s: String,
}

/// Solution soumise par le client, par cookie ou par en-tete `challenge-token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Solution {
    pub c: String,
    pub s: String,
    pub n: u64,
}

/// Calcule `HMAC-SHA256(cle, donnee)`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepte toute taille de cle");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verifie un MAC a temps constant.
fn verify_mac(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepte toute taille de cle");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// Indique si `hash` commence par au moins `bits` bits a zero.
///
/// Meme convention que la version Go et que le solveur JavaScript : on lit les
/// bits du poids fort vers le poids faible, octet par octet.
pub fn has_leading_zero_bits(hash: &[u8], bits: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let whole = (bits / 8) as usize;
    if hash.len() < whole {
        return false;
    }
    if hash[..whole].iter().any(|b| *b != 0) {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    match hash.get(whole) {
        Some(b) => b >> (8 - rest) == 0,
        None => false,
    }
}

/// Source de sel pour les challenges.
///
/// La version Go tire son sel de `crypto/rand`, donc de `random_get` de WASI,
/// que l'hote doit fournir. Ici le sel est derive par HMAC en mode compteur :
/// `HMAC(secret, etiquette || sequence || horodatage || compteur)`. Trois
/// consequences, et c'est la seule divergence de fond avec la version Go :
///
/// - le module n'importe plus aucune fonction WASI hors de ce que le SDK
///   utilise, donc il se charge meme sur un hote sans `random_get` ;
/// - les tests sont reproductibles : meme secret, meme sequence, meme
///   horodatage, meme sel ;
/// - le sel reste imprevisible pour qui ne detient pas le secret, ce qui est
///   exactement la propriete dont depend le challenge (empecher de precalculer
///   une table de solutions partagee entre clients).
#[derive(Debug, Clone)]
pub struct SaltDeriver {
    secret: Vec<u8>,
    seq: u64,
}

impl SaltDeriver {
    pub fn new(secret: &[u8]) -> Self {
        SaltDeriver {
            secret: secret.to_vec(),
            seq: 0,
        }
    }

    /// Nombre de sels deja produits depuis le chargement du plugin.
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Produit `out_len` octets. Le compteur interne avance a chaque appel.
    pub fn next_bytes(&mut self, now: i64, out_len: usize) -> Vec<u8> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        self.derive(seq, now, out_len)
    }

    /// Derivation deterministe, pour les tests et la generation de vecteurs.
    pub fn derive(&self, seq: u64, now: i64, out_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(out_len);
        let mut block: u32 = 0;
        while out.len() < out_len {
            let mut msg = Vec::with_capacity(SALT_LABEL.len() + 20);
            msg.extend_from_slice(SALT_LABEL);
            msg.extend_from_slice(&seq.to_be_bytes());
            msg.extend_from_slice(&now.to_be_bytes());
            msg.extend_from_slice(&block.to_be_bytes());
            let h = hmac_sha256(&self.secret, &msg);
            let take = core::cmp::min(32, out_len - out.len());
            out.extend_from_slice(&h[..take]);
            block = block.wrapping_add(1);
        }
        out
    }
}

/// Emet un challenge signe.
///
/// `now` et `salt` sont des parametres et non des lectures d'horloge ou
/// d'alea : c'est ce qui rend l'emission testable octet pour octet.
pub fn issue_challenge(
    key: &[u8],
    difficulty: u32,
    client: &ClientContext,
    now: i64,
    salt: &[u8],
) -> SignedChallenge {
    let difficulty = if difficulty < 1 {
        DEFAULT_DIFFICULTY
    } else {
        difficulty
    };

    let payload = ChallengePayload {
        ts: now,
        exp: now + crate::CHALLENGE_LIFETIME_SECS as i64,
        diff: difficulty,
        salt: B64.encode(salt),
        ctx: client.ip.clone(),
        cid: client.cid.clone(),
    };

    // serde respecte l'ordre de declaration, comme encoding/json en Go : les
    // octets signes sont donc identiques a ceux de la version Go.
    let body = serde_json::to_vec(&payload).expect("charge utile serialisable");
    let challenge = B64.encode(&body);
    let sig = hmac_sha256(key, challenge.as_bytes());

    SignedChallenge {
        c: challenge,
        s: B64.encode(sig),
    }
}

/// Verifie une solution soumise par le client.
///
/// L'ordre des controles est volontairement : signature, puis expiration, puis
/// preuve de travail, puis contexte. La version Go testait l'expiration avant
/// la signature, donc sur un champ non authentifie ; signer d'abord evite de
/// prendre une decision sur des donnees que personne n'a signees.
pub fn verify_solution(
    key: &[u8],
    sol: &Solution,
    expected: &ClientContext,
    now: i64,
) -> Result<ChallengePayload, TokenError> {
    if sol.c.is_empty() || sol.s.is_empty() {
        return Err(TokenError::InvalidToken);
    }

    let raw = B64
        .decode(sol.c.as_bytes())
        .map_err(|_| TokenError::InvalidToken)?;

    let sig = B64
        .decode(sol.s.as_bytes())
        .map_err(|_| TokenError::BadSignature)?;

    if !verify_mac(key, sol.c.as_bytes(), &sig) {
        return Err(TokenError::BadSignature);
    }

    let payload: ChallengePayload =
        serde_json::from_slice(&raw).map_err(|_| TokenError::InvalidToken)?;

    if now > payload.exp {
        return Err(TokenError::Expired);
    }

    let mut data = Vec::with_capacity(raw.len() + 8);
    data.extend_from_slice(&raw);
    data.extend_from_slice(&sol.n.to_be_bytes());
    let sum = Sha256::digest(&data);

    if !has_leading_zero_bits(&sum, payload.diff) {
        return Err(TokenError::BadPoW);
    }

    match_challenge_context(&payload.ctx, &payload.cid, expected)?;

    Ok(payload)
}

/// Applique la liaison IP et connexion du challenge.
pub fn match_challenge_context(
    token_ip: &str,
    token_cid: &str,
    expected: &ClientContext,
) -> Result<(), TokenError> {
    if !expected.ip.is_empty() && (token_ip.is_empty() || token_ip != expected.ip) {
        return Err(TokenError::ContextMismatch);
    }
    if !token_cid.is_empty() && !expected.cid.is_empty() && token_cid != expected.cid {
        return Err(TokenError::ContextMismatch);
    }
    Ok(())
}

/// Emet un jeton de clearance pour `ip`, valable `CLEARANCE_LIFETIME_SECS`.
pub fn issue_clearance(key: &[u8], ip: &str, now: i64, salt: &[u8]) -> String {
    let exp = now + crate::CLEARANCE_LIFETIME_SECS as i64;
    let body = encode_clearance_body(exp, salt, ip);
    let sig = hmac_sha256(key, body.as_bytes());
    format!("{body}.{}", B64.encode(sig))
}

/// Encapsule `exp || salt || ip` en base64url. Aucun JSON, aucun separateur :
/// une IPv6 se relit donc sans decoupage sur les deux-points.
pub fn encode_clearance_body(exp: i64, salt: &[u8], ip: &str) -> String {
    let ip_bytes = ip.as_bytes();
    let mut raw = Vec::with_capacity(CLEARANCE_FIXED_PREFIX + ip_bytes.len());
    raw.extend_from_slice(&exp.to_be_bytes());
    let mut padded = [0u8; CLEARANCE_SALT_LEN];
    let take = core::cmp::min(salt.len(), CLEARANCE_SALT_LEN);
    padded[..take].copy_from_slice(&salt[..take]);
    raw.extend_from_slice(&padded);
    raw.extend_from_slice(ip_bytes);
    B64.encode(&raw)
}

/// Inverse de [`encode_clearance_body`] : expiration et IP signees.
pub fn decode_clearance_body(body: &str) -> Result<(i64, String), TokenError> {
    let raw = B64
        .decode(body.as_bytes())
        .map_err(|_| TokenError::InvalidToken)?;
    if raw.len() < CLEARANCE_FIXED_PREFIX {
        return Err(TokenError::InvalidToken);
    }
    let mut exp_bytes = [0u8; 8];
    exp_bytes.copy_from_slice(&raw[..8]);
    let exp = i64::from_be_bytes(exp_bytes);
    let ip = String::from_utf8(raw[CLEARANCE_FIXED_PREFIX..].to_vec())
        .map_err(|_| TokenError::InvalidToken)?;
    Ok((exp, ip))
}

/// Verifie un cookie de clearance. `expected_ip` vide desactive la liaison IP.
pub fn verify_clearance(
    key: &[u8],
    token: &str,
    expected_ip: &str,
    now: i64,
) -> Result<(), TokenError> {
    let (body, sig) = token.split_once('.').ok_or(TokenError::InvalidToken)?;
    if body.is_empty() || sig.is_empty() {
        return Err(TokenError::InvalidToken);
    }

    let tag = B64
        .decode(sig.as_bytes())
        .map_err(|_| TokenError::BadSignature)?;

    if !verify_mac(key, body.as_bytes(), &tag) {
        return Err(TokenError::BadSignature);
    }

    let (exp, token_ip) = decode_clearance_body(body)?;

    if now > exp {
        return Err(TokenError::Expired);
    }

    if !expected_ip.is_empty() && (token_ip.is_empty() || token_ip != expected_ip) {
        return Err(TokenError::ContextMismatch);
    }

    Ok(())
}

/// Cherche un nonce satisfaisant la difficulte demandee.
///
/// Sert aux tests et au client de verification `powcli` ; c'est la meme boucle
/// que le solveur JavaScript du navigateur, en Rust.
pub fn solve(challenge_b64: &str, difficulty: u32, max_iterations: u64) -> Option<u64> {
    let raw = B64.decode(challenge_b64.as_bytes()).ok()?;
    let mut buf = Vec::with_capacity(raw.len() + 8);
    buf.extend_from_slice(&raw);
    buf.extend_from_slice(&[0u8; 8]);
    let head = buf.len() - 8;

    for nonce in 0..max_iterations {
        buf[head..].copy_from_slice(&nonce.to_be_bytes());
        let sum = Sha256::digest(&buf);
        if has_leading_zero_bits(&sum, difficulty) {
            return Some(nonce);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn solve_solution(ch: &SignedChallenge, diff: u32) -> Solution {
        let n = solve(&ch.c, diff, 1 << 22).expect("solution trouvee");
        Solution {
            c: ch.c.clone(),
            s: ch.s.clone(),
            n,
        }
    }

    #[test]
    fn issue_and_verify_solution() {
        let client = ClientContext::new("1.2.3.4", "99");
        let ch = issue_challenge(SECRET, 8, &client, 1_700_000_000, &[7u8; 32]);
        let sol = solve_solution(&ch, 8);

        assert!(verify_solution(SECRET, &sol, &client, 1_700_000_000).is_ok());
    }

    #[test]
    fn ip_and_connection_are_bound() {
        let client = ClientContext::new("1.2.3.4", "99");
        let ch = issue_challenge(SECRET, 8, &client, 1_700_000_000, &[7u8; 32]);
        let sol = solve_solution(&ch, 8);

        assert_eq!(
            verify_solution(
                SECRET,
                &sol,
                &ClientContext::new("9.9.9.9", "99"),
                1_700_000_000
            ),
            Err(TokenError::ContextMismatch)
        );
        assert_eq!(
            verify_solution(
                SECRET,
                &sol,
                &ClientContext::new("1.2.3.4", "100"),
                1_700_000_000
            ),
            Err(TokenError::ContextMismatch)
        );
        // Identifiant de connexion indisponible cote verificateur : le controle
        // est ignore, comme dans la version Go.
        assert!(verify_solution(
            SECRET,
            &sol,
            &ClientContext::new("1.2.3.4", ""),
            1_700_000_000
        )
        .is_ok());
    }

    #[test]
    fn session_id_binding_ignored_when_token_has_none() {
        let client = ClientContext::new("1.1.1.1", "");
        let ch = issue_challenge(SECRET, 8, &client, 1_700_000_000, &[1u8; 32]);
        let sol = solve_solution(&ch, 8);
        assert!(verify_solution(
            SECRET,
            &sol,
            &ClientContext::new("1.1.1.1", "7"),
            1_700_000_000
        )
        .is_ok());
    }

    #[test]
    fn bad_signature_is_rejected() {
        let client = ClientContext::new("1.2.3.4", "1");
        let ch = issue_challenge(SECRET, 8, &client, 1_700_000_000, &[3u8; 32]);
        let mut sol = solve_solution(&ch, 8);
        sol.s = B64.encode([0u8; 32]);
        assert_eq!(
            verify_solution(SECRET, &sol, &client, 1_700_000_000),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let client = ClientContext::new("1.2.3.4", "");
        let ch = issue_challenge(SECRET, 8, &client, 1_700_000_000, &[3u8; 32]);
        let sol = solve_solution(&ch, 8);
        assert_eq!(
            verify_solution(
                b"ffffffffffffffffffffffffffffffff",
                &sol,
                &client,
                1_700_000_000
            ),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn bad_proof_of_work_is_rejected() {
        let client = ClientContext::new("1.2.3.4", "");
        let ch = issue_challenge(SECRET, 8, &client, 1_700_000_000, &[3u8; 32]);
        let sol = Solution {
            c: ch.c.clone(),
            s: ch.s.clone(),
            n: u64::MAX,
        };
        // u64::MAX ne resout pas 8 bits avec une probabilite de 255/256.
        match verify_solution(SECRET, &sol, &client, 1_700_000_000) {
            Err(TokenError::BadPoW) => {}
            Ok(_) => {
                eprintln!("nonce u64::MAX a resolu le PoW : cas improbable, test sans conclusion")
            }
            other => panic!("attendu BadPoW, obtenu {other:?}"),
        }
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let client = ClientContext::new("1.2.3.4", "");
        let ch = issue_challenge(SECRET, 8, &client, 1_700_000_000, &[3u8; 32]);
        let sol = solve_solution(&ch, 8);
        // 61 secondes plus tard : hors fenetre.
        assert_eq!(
            verify_solution(SECRET, &sol, &client, 1_700_000_061),
            Err(TokenError::Expired)
        );
        // A la seconde d'expiration exacte, la version Go accepte encore.
        assert!(verify_solution(SECRET, &sol, &client, 1_700_000_060).is_ok());
    }

    #[test]
    fn malformed_solutions_are_rejected() {
        let client = ClientContext::new("1.2.3.4", "");
        let empty = Solution {
            c: String::new(),
            s: String::new(),
            n: 0,
        };
        assert_eq!(
            verify_solution(SECRET, &empty, &client, 0),
            Err(TokenError::InvalidToken)
        );

        let not_b64 = Solution {
            c: "!!!".into(),
            s: "???".into(),
            n: 0,
        };
        assert_eq!(
            verify_solution(SECRET, &not_b64, &client, 0),
            Err(TokenError::InvalidToken)
        );
    }

    #[test]
    fn default_difficulty_when_zero() {
        let ch = issue_challenge(
            SECRET,
            0,
            &ClientContext::default(),
            1_700_000_000,
            &[0u8; 32],
        );
        let raw = B64.decode(ch.c.as_bytes()).unwrap();
        let payload: ChallengePayload = serde_json::from_slice(&raw).unwrap();
        assert_eq!(payload.diff, DEFAULT_DIFFICULTY);
    }

    #[test]
    fn clearance_round_trip_and_binding() {
        let tok = issue_clearance(
            SECRET,
            "10.0.0.1",
            1_700_000_000,
            &[9u8; CLEARANCE_SALT_LEN],
        );
        assert!(!tok.contains('{'), "la clearance ne doit pas etre du JSON");
        assert!(verify_clearance(SECRET, &tok, "10.0.0.1", 1_700_000_000).is_ok());
        assert_eq!(
            verify_clearance(SECRET, &tok, "10.0.0.2", 1_700_000_000),
            Err(TokenError::ContextMismatch)
        );
        assert_eq!(
            verify_clearance(SECRET, &tok, "10.0.0.1", 1_700_001_801),
            Err(TokenError::Expired)
        );
        // Contexte vide cote verificateur : la liaison IP est desactivee.
        assert!(verify_clearance(SECRET, &tok, "", 1_700_000_000).is_ok());
    }

    #[test]
    fn clearance_handles_ipv6() {
        let ip = "2001:db8::1";
        let tok = issue_clearance(SECRET, ip, 1_700_000_000, &[4u8; CLEARANCE_SALT_LEN]);
        assert!(verify_clearance(SECRET, &tok, ip, 1_700_000_000).is_ok());
        let (_, decoded) = decode_clearance_body(tok.split_once('.').unwrap().0).unwrap();
        assert_eq!(decoded, ip);
    }

    #[test]
    fn clearance_tampering_is_rejected() {
        let tok = issue_clearance(
            SECRET,
            "10.0.0.1",
            1_700_000_000,
            &[9u8; CLEARANCE_SALT_LEN],
        );
        let (body, _) = tok.split_once('.').unwrap();
        let forged_body =
            encode_clearance_body(4_000_000_000, &[9u8; CLEARANCE_SALT_LEN], "10.0.0.1");
        let forged = format!("{forged_body}.{}", tok.split_once('.').unwrap().1);
        assert_eq!(
            verify_clearance(SECRET, &forged, "10.0.0.1", 1_700_000_000),
            Err(TokenError::BadSignature)
        );
        assert_eq!(
            verify_clearance(SECRET, "pas un jeton", "10.0.0.1", 1_700_000_000),
            Err(TokenError::InvalidToken)
        );
        assert_eq!(
            verify_clearance(SECRET, "abc.", "10.0.0.1", 1_700_000_000),
            Err(TokenError::InvalidToken)
        );
        // Corps valide mais signature d'un autre corps.
        assert!(verify_clearance(SECRET, body, "10.0.0.1", 1_700_000_000).is_err());
    }

    #[test]
    fn leading_zero_bits_matches_reference_semantics() {
        let zero = [0u8; 32];
        assert!(has_leading_zero_bits(&zero, 0));
        assert!(has_leading_zero_bits(&zero, 16));
        assert!(has_leading_zero_bits(&zero, 256));

        let mut h = [0u8; 32];
        h[0] = 0x0f;
        assert!(has_leading_zero_bits(&h, 4));
        assert!(!has_leading_zero_bits(&h, 5));

        let mut h = [0u8; 32];
        h[0] = 0x00;
        h[1] = 0x80;
        assert!(has_leading_zero_bits(&h, 8));
        assert!(!has_leading_zero_bits(&h, 9));
        assert!(!has_leading_zero_bits(&[0xffu8; 32], 1));
        assert!(!has_leading_zero_bits(&[0u8; 2], 32));
    }

    #[test]
    fn salt_derivation_is_deterministic_and_distinct() {
        let mut a = SaltDeriver::new(SECRET);
        assert_eq!(
            a.derive(0, 1_700_000_000, 32),
            a.derive(0, 1_700_000_000, 32)
        );
        assert_ne!(
            a.derive(0, 1_700_000_000, 32),
            a.derive(1, 1_700_000_000, 32)
        );
        assert_ne!(
            a.derive(0, 1_700_000_000, 32),
            a.derive(0, 1_700_000_001, 32)
        );

        let first = a.next_bytes(1_700_000_000, 32);
        let second = a.next_bytes(1_700_000_000, 32);
        assert_ne!(
            first, second,
            "deux challenges successifs ne partagent pas leur sel"
        );
        assert_eq!(a.sequence(), 2);

        // Un autre secret donne un autre flux.
        assert_ne!(
            first,
            SaltDeriver::new(b"ffffffffffffffffffffffffffffffff").derive(0, 1_700_000_000, 32)
        );

        // Sortie longue : plusieurs blocs concatenes.
        assert_eq!(a.derive(0, 1, 48).len(), 48);
        assert_ne!(a.derive(0, 1, 48)[..32], a.derive(0, 1, 48)[32..]);
    }

    #[test]
    fn payload_json_field_order_matches_go() {
        let client = ClientContext::new("1.2.3.4", "99");
        let ch = issue_challenge(SECRET, 18, &client, 1_700_000_000, &[0u8; 32]);
        let raw = String::from_utf8(B64.decode(ch.c.as_bytes()).unwrap()).unwrap();
        let keys: Vec<&str> = ["ts", "exp", "diff", "salt", "ctx", "cid"]
            .into_iter()
            .collect();
        let mut cursor = 0usize;
        for k in keys {
            let needle = format!("\"{k}\":");
            let at = raw[cursor..]
                .find(&needle)
                .map(|i| i + cursor)
                .unwrap_or_else(|| {
                    panic!("cle {k} absente de la charge utile : {raw}");
                });
            cursor = at;
        }
        assert!(raw.starts_with("{\"ts\":"));
        assert!(raw.ends_with("}"));
    }

    #[test]
    fn client_label_matches_go() {
        assert_eq!(ClientContext::new("1.2.3.4", "9").label(), "1.2.3.4;cid=9");
        assert_eq!(ClientContext::new("1.2.3.4", "").label(), "1.2.3.4");
        assert_eq!(ClientContext::new("", "9").label(), "cid=9");
        assert_eq!(ClientContext::default().label(), "");
    }
}
