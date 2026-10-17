//! Cookies du protocole : lecture en une passe, ecriture au format impose.
//!
//! Portage fidele de la version Go, tolerances comprises. Les chaines produites
//! sont identiques caractere pour caractere : un navigateur qui a deja les
//! cookies de la version Go les presente sans changement.

/// Cookie de clearance de longue duree.
pub const CLEARANCE_COOKIE: &str = "challenge-clearance";
/// Cookie portant le challenge signe.
pub const CHALLENGE_COOKIE: &str = "challenge";
/// Cookie portant la signature du challenge.
pub const SIGNATURE_COOKIE: &str = "challenge-sig";
/// Cookie portant le nonce trouve.
pub const NONCE_COOKIE: &str = "challenge-nonce";

/// Les quatre cookies du protocole, extraits d'une seule lecture du `Cookie`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChallengeCookies {
    pub clearance: String,
    pub challenge: String,
    pub signature: String,
    pub nonce: String,
}

impl ChallengeCookies {
    /// Vrai quand les trois cookies d'une solution sont presents.
    pub fn has_solution_parts(&self) -> bool {
        !self.challenge.is_empty() && !self.signature.is_empty() && !self.nonce.is_empty()
    }

    /// Nonce decode. `None` si absent ou non numerique.
    pub fn nonce_value(&self) -> Option<u64> {
        self.nonce.trim().parse::<u64>().ok()
    }

    /// Vrai si le client presente un cookie de clearance, valide ou non.
    pub fn has_clearance(&self) -> bool {
        !self.clearance.is_empty()
    }
}

/// Extrait les quatre cookies du protocole en une seule passe sur l'en-tete.
///
/// Aucun decoupage en tableau intermediaire : la version Go evitait deja cette
/// allocation, la version Rust fait pareil.
pub fn parse_challenge_cookies(header: &str) -> ChallengeCookies {
    let mut out = ChallengeCookies::default();
    if header.is_empty() {
        return out;
    }

    let bytes = header.as_bytes();
    let mut start = 0usize;
    let n = bytes.len();

    while start < n {
        while start < n && (bytes[start] == b' ' || bytes[start] == b';') {
            start += 1;
        }
        if start >= n {
            break;
        }

        let eq = match header[start..].find('=') {
            Some(i) => start + i,
            None => break,
        };

        let name = header[start..eq].trim();
        let value_start = eq + 1;

        let value = match header[value_start..].find(';') {
            Some(semi) => {
                let v = header[value_start..value_start + semi].trim().to_string();
                start = value_start + semi + 1;
                v
            }
            None => {
                let v = header[value_start..].trim().to_string();
                start = n;
                v
            }
        };

        match name {
            CLEARANCE_COOKIE => out.clearance = value,
            CHALLENGE_COOKIE => out.challenge = value,
            SIGNATURE_COOKIE => out.signature = value,
            NONCE_COOKIE => out.nonce = value,
            _ => {}
        }
    }

    out
}

/// Lit un cookie unique. Conserve la tolerance de la version Go : valeur vide
/// apres un separateur, espaces autour du nom et de la valeur, absence de
/// separateur devant le nom.
pub fn get_cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    if header.is_empty() {
        return None;
    }

    let prefix = format!("{name}=");

    if let Some(rest) = header.strip_prefix(&prefix) {
        return Some(match rest.find(';') {
            Some(i) => rest[..i].trim(),
            None => rest.trim(),
        });
    }

    for sep in ["; ", ";"] {
        let search = format!("{sep}{prefix}");
        if let Some(idx) = header.find(&search) {
            let rest = &header[idx + search.len()..];
            return Some(match rest.find(';') {
                Some(i) => rest[..i].trim(),
                None => rest.trim(),
            });
        }
    }

    None
}

/// Formate un `Set-Cookie`. Ordre des attributs identique a la version Go.
pub fn set_cookie(name: &str, value: &str, max_age: i64, http_only: bool, secure: bool) -> String {
    let mut out = format!("{name}={value}; Path=/; Max-Age={max_age}; SameSite=Lax");
    if http_only {
        out.push_str("; HttpOnly");
    }
    if secure {
        out.push_str("; Secure");
    }
    out
}

/// Formate l'effacement d'un cookie. `Max-Age=0` suffit a le supprimer.
///
/// L'ordre `Secure` puis `HttpOnly` est celui de la version Go : le navigateur
/// doit voir les memes attributs pour remplacer le bon cookie.
pub fn clear_cookie(name: &str, secure: bool) -> String {
    let mut out = format!("{name}=; Path=/; Max-Age=0; SameSite=Lax");
    if secure {
        out.push_str("; Secure");
    }
    if name == CLEARANCE_COOKIE {
        out.push_str("; HttpOnly");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_cookie_matches_reference_behaviour() {
        let cases: [(&str, &str, Option<&str>); 9] = [
            ("", "challenge", None),
            ("challenge=abc", "challenge", Some("abc")),
            ("challenge=abc; challenge-sig=xyz", "challenge", Some("abc")),
            (
                "challenge=abc; challenge-sig=xyz",
                "challenge-sig",
                Some("xyz"),
            ),
            ("foo=1; challenge=val; bar=2", "challenge", Some("val")),
            (
                "challenge=abc;challenge-sig=xyz",
                "challenge-sig",
                Some("xyz"),
            ),
            ("other=1", "challenge", None),
            ("challenge=  spaced  ", "challenge", Some("spaced")),
            (
                "a=1; challenge-nonce=42; b=2",
                "challenge-nonce",
                Some("42"),
            ),
        ];
        for (header, name, want) in cases {
            assert_eq!(
                get_cookie(header, name),
                want,
                "get_cookie({header:?}, {name:?})"
            );
        }
    }

    #[test]
    fn parse_extracts_all_four_cookies() {
        let h = "a=1; challenge=abc; challenge-sig=sig; challenge-nonce=9; challenge-clearance=cltok; b=2";
        let got = parse_challenge_cookies(h);
        assert_eq!(got.challenge, "abc");
        assert_eq!(got.signature, "sig");
        assert_eq!(got.nonce, "9");
        assert_eq!(got.clearance, "cltok");

        // Lecture en une passe et lecture unitaire doivent concorder.
        for (name, value) in [
            (CHALLENGE_COOKIE, got.challenge.as_str()),
            (SIGNATURE_COOKIE, got.signature.as_str()),
            (NONCE_COOKIE, got.nonce.as_str()),
            (CLEARANCE_COOKIE, got.clearance.as_str()),
        ] {
            assert_eq!(get_cookie(h, name), Some(value));
        }

        let empty = parse_challenge_cookies("");
        assert_eq!(empty, ChallengeCookies::default());
        assert!(!empty.has_clearance());

        // Une valeur contenant un point (corps.signature) passe telle quelle.
        let h2 = "challenge-clearance=body.sig";
        assert_eq!(parse_challenge_cookies(h2).clearance, "body.sig");
        assert_eq!(get_cookie(h2, CLEARANCE_COOKIE), Some("body.sig"));
    }

    #[test]
    fn solution_parts_detection() {
        let mut c = ChallengeCookies::default();
        assert!(!c.has_solution_parts());
        c.challenge = "c".into();
        c.signature = "s".into();
        assert!(!c.has_solution_parts());
        c.nonce = "12".into();
        assert!(c.has_solution_parts());
        assert_eq!(c.nonce_value(), Some(12));

        c.nonce = "pas un nombre".into();
        assert_eq!(c.nonce_value(), None);
        c.nonce.clear();
        assert_eq!(c.nonce_value(), None);
    }

    #[test]
    fn cookie_formatting_is_byte_identical() {
        assert_eq!(
            set_cookie("challenge", "tok", 60, false, false),
            "challenge=tok; Path=/; Max-Age=60; SameSite=Lax"
        );
        assert_eq!(
            set_cookie("challenge-clearance", "tok", 1800, true, true),
            "challenge-clearance=tok; Path=/; Max-Age=1800; SameSite=Lax; HttpOnly; Secure"
        );
        assert_eq!(
            clear_cookie("challenge", false),
            "challenge=; Path=/; Max-Age=0; SameSite=Lax"
        );
        assert_eq!(
            clear_cookie("challenge-clearance", true),
            "challenge-clearance=; Path=/; Max-Age=0; SameSite=Lax; Secure; HttpOnly"
        );
    }

    #[test]
    fn parse_ignores_unknown_and_malformed_segments() {
        let c = parse_challenge_cookies("__cf_bm=x; challenge=abc; ; =vide; challenge-nonce=1");
        assert_eq!(c.challenge, "abc");
        assert_eq!(c.nonce, "1");
        assert_eq!(c.signature, "");
    }
}
