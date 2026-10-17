//! Recoupement avec l'implementation de reference.
//!
//! Les constantes viennent de `tests/data/parity_vectors.rs`, genere par
//! `tools/gen_vectors.py`. Ce script implemente le meme algorithme d'apres la
//! version Go d'origine, et non d'apres ce code : l'egalite des octets est donc
//! un vrai recoupement entre deux lectures independantes du format, pas une
//! coherence du code avec lui-meme.
//!
//! Pour regenerer les vecteurs :
//!
//! ```text
//! python3 tools/gen_vectors.py --rust > tests/data/parity_vectors.rs
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use pow_proxy::token::{
    self, ClientContext, SaltDeriver, Solution, TokenError, CLEARANCE_SALT_LEN,
};

include!("data/parity_vectors.rs");

fn key() -> &'static [u8] {
    VECTORS.secret.as_bytes()
}

fn client() -> ClientContext {
    ClientContext::new(VECTORS.ip, VECTORS.conn_id)
}

#[test]
fn salt_derivation_matches_reference() {
    let mut deriver = SaltDeriver::new(key());

    assert_eq!(
        B64.encode(deriver.next_bytes(VECTORS.now, 32)),
        VECTORS.challenge_salt,
        "sel du challenge"
    );

    // Le sel de clearance est le meme flux, tronque.
    let mut deriver = SaltDeriver::new(key());
    assert_eq!(
        B64.encode(deriver.next_bytes(VECTORS.now, CLEARANCE_SALT_LEN)),
        VECTORS.clearance_salt,
        "sel de clearance"
    );
}

#[test]
fn issued_challenge_matches_reference_byte_for_byte() {
    let salt = SaltDeriver::new(key()).derive(0, VECTORS.now, 32);
    let issued = token::issue_challenge(key(), VECTORS.difficulty, &client(), VECTORS.now, &salt);

    assert_eq!(issued.c, VECTORS.challenge, "challenge");
    assert_eq!(issued.s, VECTORS.signature, "signature");
}

#[test]
fn payload_json_matches_reference_including_key_order() {
    let salt = SaltDeriver::new(key()).derive(0, VECTORS.now, 32);
    let issued = token::issue_challenge(key(), VECTORS.difficulty, &client(), VECTORS.now, &salt);

    let decoded =
        String::from_utf8(B64.decode(issued.c.as_bytes()).expect("base64")).expect("utf-8");

    // Comparaison de la chaine entiere : elle couvre l'ordre des cles, les
    // separateurs, et l'absence de champs vides.
    assert_eq!(decoded, VECTORS.payload_json);
}

#[test]
fn issued_clearance_matches_reference() {
    let salt = SaltDeriver::new(key()).derive(0, VECTORS.now, CLEARANCE_SALT_LEN);
    let clearance = token::issue_clearance(key(), VECTORS.clearance_ip, VECTORS.now, &salt);

    assert_eq!(clearance, VECTORS.clearance);
}

#[test]
fn reference_solution_is_accepted() {
    let solution = Solution {
        c: VECTORS.challenge.to_string(),
        s: VECTORS.signature.to_string(),
        n: VECTORS.nonce,
    };

    let payload = token::verify_solution(key(), &solution, &client(), VECTORS.now)
        .expect("la solution de reference doit etre acceptee");

    assert_eq!(payload.diff, VECTORS.difficulty);
    assert_eq!(payload.ts, VECTORS.now);
    assert_eq!(payload.exp, VECTORS.now + 60);
    assert_eq!(payload.ctx, VECTORS.ip);
    assert_eq!(payload.cid, VECTORS.conn_id);
    assert_eq!(payload.salt, VECTORS.challenge_salt);
}

#[test]
fn reference_nonce_satisfies_the_announced_difficulty() {
    let raw = B64.decode(VECTORS.challenge.as_bytes()).expect("base64");
    let mut data = raw.clone();
    data.extend_from_slice(&VECTORS.nonce.to_be_bytes());
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&data);

    // La frontiere est deterministe : on compare au nombre exact de bits de tete
    // a zero calcule par l'implementation de reference, et non a « au moins ».
    assert!(
        token::has_leading_zero_bits(&digest, VECTORS.leading_zero_bits),
        "le seuil exact doit etre accepte"
    );
    assert!(
        !token::has_leading_zero_bits(&digest, VECTORS.leading_zero_bits + 1),
        "un bit de plus doit etre refuse, sinon le controle est trop permissif"
    );
}

#[test]
fn reference_clearance_is_accepted_and_bound_to_its_ip() {
    token::verify_clearance(key(), VECTORS.clearance, VECTORS.clearance_ip, VECTORS.now)
        .expect("la clearance de reference doit etre acceptee");

    assert_eq!(
        token::verify_clearance(key(), VECTORS.clearance, "203.0.113.1", VECTORS.now),
        Err(TokenError::ContextMismatch)
    );

    assert_eq!(
        token::verify_clearance(
            key(),
            VECTORS.clearance,
            VECTORS.clearance_ip,
            VECTORS.now + 1801
        ),
        Err(TokenError::Expired)
    );
}

#[test]
fn tampering_with_reference_values_is_refused() {
    // Signature alteree.
    let mut bad_sig = Solution {
        c: VECTORS.challenge.to_string(),
        s: VECTORS.signature.to_string(),
        n: VECTORS.nonce,
    };
    bad_sig.s = B64.encode([0u8; 32]);
    assert_eq!(
        token::verify_solution(key(), &bad_sig, &client(), VECTORS.now),
        Err(TokenError::BadSignature)
    );

    // Nonce altere : on prend le premier nonce voisin refuse, pour ne pas
    // dependre d'une coincidence de hachage.
    let rejected = (1..16u64).find(|offset| {
        let candidate = Solution {
            c: VECTORS.challenge.to_string(),
            s: VECTORS.signature.to_string(),
            n: VECTORS.nonce.wrapping_add(*offset),
        };
        token::verify_solution(key(), &candidate, &client(), VECTORS.now).is_err()
    });
    assert!(rejected.is_some(), "un nonce voisin doit etre refuse");

    // Contexte different.
    let solution = Solution {
        c: VECTORS.challenge.to_string(),
        s: VECTORS.signature.to_string(),
        n: VECTORS.nonce,
    };
    assert_eq!(
        token::verify_solution(
            key(),
            &solution,
            &ClientContext::new("9.9.9.9", VECTORS.conn_id),
            VECTORS.now
        ),
        Err(TokenError::ContextMismatch)
    );

    // Clearance alteree.
    let mut forged = VECTORS.clearance.to_string();
    forged.push('x');
    assert!(token::verify_clearance(key(), &forged, VECTORS.clearance_ip, VECTORS.now).is_err());
}
