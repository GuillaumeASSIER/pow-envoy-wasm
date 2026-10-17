//! Resolution de l'identite client.
//!
//! Ces fonctions ne font aucun appel a l'hote : elles prennent les octets bruts
//! que l'adaptateur Proxy-WASM a lus et rendent une forme normalisee. C'est ce
//! qui permet de les tester sans Envoy.

use core::net::IpAddr;

/// Normalise une adresse : espace retire, port retire, crochets retires,
/// validation, puis forme canonique.
///
/// Un jeton qui n'est pas une adresse IP rend `None`. La validation stricte
/// importe : `X-Forwarded-For` est un en-tete que le client peut ecrire, et une
/// valeur non validee deviendrait une cle de liaison de jeton.
pub fn normalize_ip(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    let host = match split_host_port(s) {
        Some((host, _port)) => host,
        // Pas de port : on tolere les crochets autour d'une IPv6.
        None => s.trim_start_matches('[').trim_end_matches(']'),
    };

    let host = host.trim();
    if host.is_empty() {
        return None;
    }

    host.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Separe `hote` et `port` a la maniere de `net.SplitHostPort` : IPv6 entre
/// crochets obligatoire des qu'un port suit.
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if after.is_empty() {
            return Some((host, ""));
        }
        let port = after.strip_prefix(':')?;
        return Some((host, port));
    }

    let (host, port) = s.rsplit_once(':')?;
    if host.contains(':') {
        // IPv6 sans crochets : il n'y a pas de port a separer.
        return None;
    }
    Some((host, port))
}

/// Premiere adresse exploitable d'un `X-Forwarded-For`.
///
/// Le premier element est l'adresse d'origine quand chaque relais ajoute la
/// sienne ; les elements suivants sont des proxys, et un relais mal configure
/// peut y placer n'importe quoi.
pub fn first_forwarded_ip(xff: &str) -> Option<String> {
    xff.split(',').find_map(normalize_ip)
}

/// Identifiant de connexion Envoy, tel que l'ABI le presente.
///
/// L'ABI expose les attributs entiers en 8 octets petit-boutistes ; certaines
/// implementations rendent une forme textuelle. `None` quand la valeur est
/// absente ou nulle.
pub fn connection_id(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    if raw.len() >= 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&raw[..8]);
        return Some(u64::from_le_bytes(buf).to_string());
    }
    let s = String::from_utf8_lossy(raw).trim().to_string();
    if s.is_empty() || s == "0" {
        return None;
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ip_strips_port_and_validates() {
        let cases: [(&str, Option<&str>); 11] = [
            ("1.2.3.4:5678", Some("1.2.3.4")),
            ("[2001:db8::1]:80", Some("2001:db8::1")),
            ("  8.8.8.8  ", Some("8.8.8.8")),
            ("not-an-ip", None),
            ("", None),
            ("   ", None),
            ("2001:db8::1", Some("2001:db8::1")),
            ("[2001:db8::1]", Some("2001:db8::1")),
            ("1.2.3.4:pas-numerique", Some("1.2.3.4")),
            ("::1", Some("::1")),
            ("fe80::1%eth0", None),
        ];
        for (input, want) in cases {
            assert_eq!(
                normalize_ip(input).as_deref(),
                want,
                "normalize_ip({input:?})"
            );
        }
    }

    #[test]
    fn normalize_ip_keeps_host_when_port_is_junk() {
        // Le port n'est jamais utilise : seule l'adresse compte pour la liaison
        // du jeton. Un port illisible n'invalide donc pas l'hote, qui reste
        // valide et verifie.
        assert_eq!(
            normalize_ip("1.2.3.4:pas-numerique").as_deref(),
            Some("1.2.3.4")
        );
    }

    #[test]
    fn canonical_form_is_collapsed() {
        // Deux ecritures de la meme IPv6 donnent la meme cle de liaison, sinon
        // un client pourrait rejouer un jeton en changeant d'ecriture.
        assert_eq!(
            normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001"),
            normalize_ip("2001:db8::1")
        );
    }

    #[test]
    fn forwarded_for_takes_first_usable() {
        assert_eq!(
            first_forwarded_ip("203.0.113.1, 10.0.0.1").as_deref(),
            Some("203.0.113.1")
        );
        assert_eq!(
            first_forwarded_ip("inconnu, 10.0.0.1").as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(first_forwarded_ip("").as_deref(), None);
        assert_eq!(first_forwarded_ip(" , ; ").as_deref(), None);
    }

    #[test]
    fn connection_id_decodes_little_endian_abi() {
        // L'ABI rend 8 octets petit-boutistes.
        assert_eq!(
            connection_id(&[1, 0, 0, 0, 0, 0, 0, 0]).as_deref(),
            Some("1")
        );
        assert_eq!(
            connection_id(&[0, 0, 0, 0, 0, 0, 0, 0]).as_deref(),
            Some("0")
        );
        assert_eq!(
            connection_id(&[42, 0, 0, 0, 0, 0, 0, 0]).as_deref(),
            Some("42")
        );
        // Forme textuelle, quand l'hote en rend une.
        assert_eq!(connection_id(b" 987 ").as_deref(), Some("987"));
        assert_eq!(connection_id(b"0"), None);
        assert_eq!(connection_id(b"  "), None);
        assert_eq!(connection_id(b""), None);
    }
}
