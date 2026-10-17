#!/usr/bin/env python3
"""Vecteurs de reference pour le plugin pow-proxy.

Implementation independante de l'algorithme, ecrite d'apres la version Go
d'origine (kubewaf-io/pow-proxy-wasm) et non d'apres la version Rust. Le but est
de disposer d'un deuxieme avis : si Rust et Python produisent les memes octets,
c'est que la lecture du format est la bonne dans les deux, et pas seulement
coherente avec elle-meme.

Usage :
    python3 tools/gen_vectors.py            # affiche les vecteurs
    python3 tools/gen_vectors.py --json     # sortie JSON, pour un test Rust

Ce script ne sert qu'aux tests et a la documentation : il n'est jamais embarque
dans le module wasm.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json

# Valeurs figees, partagees avec tests/parity.rs.
SECRET = b"0123456789abcdef0123456789abcdef"
NOW = 1_700_000_000
DIFFICULTY = 18
CHALLENGE_LIFETIME = 60
CLEARANCE_LIFETIME = 1800
CLEARANCE_SALT_LEN = 16
SALT_LABEL = b"exoledge/pow/salt/v1"

IP = "1.2.3.4"
CONN_ID = "99"
CLEARANCE_IP = "10.0.0.1"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def derive_salt(secret: bytes, seq: int, now: int, length: int) -> bytes:
    """Derivation du sel, en mode compteur, telle que documentee cote Rust.

    HMAC(secret, etiquette || seq_be64 || now_be64 || compteur_be32), concatene
    jusqu'a obtenir `length` octets.
    """
    out = b""
    block = 0
    while len(out) < length:
        message = SALT_LABEL + seq.to_bytes(8, "big") + now.to_bytes(8, "big", signed=True)
        message += block.to_bytes(4, "big")
        out += hmac.new(secret, message, hashlib.sha256).digest()
        block += 1
    return out[:length]


def issue_challenge(secret: bytes, difficulty: int, ip: str, cid: str, now: int, salt: bytes):
    """Emet un challenge signe, format identique a la version Go."""
    payload = {
        "ts": now,
        "exp": now + CHALLENGE_LIFETIME,
        "diff": difficulty,
        "salt": b64u(salt),
        "ctx": ip,
        "cid": cid,
    }
    # Ordre des cles fixe : serde et encoding/json serialisent dans l'ordre de
    # declaration de la structure.
    if not ip:
        del payload["ctx"]
    if not cid:
        del payload["cid"]
    raw = json.dumps(payload, separators=(",", ":")).encode()
    challenge = b64u(raw)
    signature = b64u(hmac.new(secret, challenge.encode(), hashlib.sha256).digest())
    return payload, challenge, signature


def has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    if bits == 0:
        return True
    whole, rest = divmod(bits, 8)
    if len(digest) < whole:
        return False
    if any(b != 0 for b in digest[:whole]):
        return False
    if rest == 0:
        return True
    if whole >= len(digest):
        return False
    return digest[whole] >> (8 - rest) == 0


def count_leading_zero_bits(digest: bytes) -> int:
    """Nombre exact de bits de tete a zero, pour verifier la frontiere du seuil."""
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        for shift in range(7, -1, -1):
            if byte >> shift & 1:
                return count
            count += 1
        break
    return count


def solve(challenge: str, difficulty: int, max_iterations: int = 1 << 24) -> int:
    """Cherche un nonce : SHA-256(challenge || nonce_be64) avec `difficulty` bits
    de tete a zero. Meme boucle que le solveur JavaScript du navigateur."""
    raw = base64.urlsafe_b64decode(challenge + "=" * (-len(challenge) % 4))
    for nonce in range(max_iterations):
        if has_leading_zero_bits(hashlib.sha256(raw + nonce.to_bytes(8, "big")).digest(), difficulty):
            return nonce
    raise RuntimeError("aucune solution trouvee")


def verify_solution(secret: bytes, challenge: str, signature: str, nonce: int,
                    ip: str, cid: str, now: int) -> None:
    """Verifie une solution comme le ferait le plugin, en levant une exception
    au premier refus."""
    raw = base64.urlsafe_b64decode(challenge + "=" * (-len(challenge) % 4))
    expected = hmac.new(secret, challenge.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))):
        raise ValueError("signature invalide")
    payload = json.loads(raw)
    if now > payload["exp"]:
        raise ValueError("jeton expire")
    digest = hashlib.sha256(raw + nonce.to_bytes(8, "big")).digest()
    if not has_leading_zero_bits(digest, payload["diff"]):
        raise ValueError("preuve de travail invalide")
    if ip and payload.get("ctx") != ip:
        raise ValueError("contexte IP different")
    if payload.get("cid") and cid and payload.get("cid") != cid:
        raise ValueError("contexte de connexion different")


def issue_clearance(secret: bytes, ip: str, now: int, salt: bytes) -> str:
    """Jeton de clearance : corps. HMAC(corps), corps = exp_be64 || sel || ip."""
    body = (now + CLEARANCE_LIFETIME).to_bytes(8, "big") + salt[:CLEARANCE_SALT_LEN] + ip.encode()
    encoded = b64u(body)
    return encoded + "." + b64u(hmac.new(secret, encoded.encode(), hashlib.sha256).digest())


def verify_clearance(secret: bytes, token: str, ip: str, now: int) -> None:
    body, _, signature = token.partition(".")
    if not body or not signature:
        raise ValueError("jeton illisible")
    expected = hmac.new(secret, body.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))):
        raise ValueError("signature invalide")
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    if len(raw) < 8 + CLEARANCE_SALT_LEN:
        raise ValueError("jeton illisible")
    exp = int.from_bytes(raw[:8], "big")
    if now > exp:
        raise ValueError("jeton expire")
    got_ip = raw[8 + CLEARANCE_SALT_LEN:].decode()
    if ip and got_ip != ip:
        raise ValueError("contexte IP different")


def build_vectors() -> dict:
    challenge_salt = derive_salt(SECRET, 0, NOW, 32)
    clearance_salt = derive_salt(SECRET, 0, NOW, CLEARANCE_SALT_LEN)

    payload, challenge, signature = issue_challenge(
        SECRET, DIFFICULTY, IP, CONN_ID, NOW, challenge_salt
    )
    nonce = solve(challenge, DIFFICULTY)
    clearance = issue_clearance(SECRET, CLEARANCE_IP, NOW, clearance_salt)

    # Nombre exact de bits de tete a zero du nonce retenu : c'est la frontiere
    # exacte du seuil, et elle est deterministe, contrairement a l'idee qu'un
    # nonce de difficulte 18 en satisferait forcement moins de 19.
    raw_challenge = base64.urlsafe_b64decode(challenge + "=" * (-len(challenge) % 4))
    digest = hashlib.sha256(raw_challenge + nonce.to_bytes(8, "big")).digest()
    exact_bits = count_leading_zero_bits(digest)
    if exact_bits < DIFFICULTY:
        raise AssertionError("le nonce ne satisfait pas la difficulte annoncee")

    # Controle interne : les fonctions de verification acceptent ce qu'elles
    # viennent de produire, et refusent une alteration.
    verify_solution(SECRET, challenge, signature, nonce, IP, CONN_ID, NOW)
    verify_clearance(SECRET, clearance, CLEARANCE_IP, NOW)
    try:
        verify_clearance(SECRET, clearance, "10.0.0.2", NOW)
        raise AssertionError("une clearance doit etre liee a son IP")
    except ValueError:
        pass
    try:
        verify_solution(SECRET, challenge, signature, nonce, "9.9.9.9", CONN_ID, NOW)
        raise AssertionError("une solution doit etre liee a son IP")
    except ValueError:
        pass

    return {
        "secret": SECRET.decode(),
        "now": NOW,
        "difficulty": DIFFICULTY,
        "ip": IP,
        "conn_id": CONN_ID,
        "clearance_ip": CLEARANCE_IP,
        "challenge_salt_b64": b64u(challenge_salt),
        "clearance_salt_b64": b64u(clearance_salt),
        "challenge": challenge,
        "signature": signature,
        "payload_json": json.dumps(payload, separators=(",", ":")),
        "nonce": nonce,
        "leading_zero_bits": exact_bits,
        "clearance": clearance,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="sortie JSON")
    parser.add_argument(
        "--rust",
        action="store_true",
        help="constantes Rust, ecrites dans tests/data/parity_vectors.rs",
    )
    args = parser.parse_args()

    vectors = build_vectors()

    if args.rust:
        print("// Fichier genere par tools/gen_vectors.py : ne pas modifier a la main.")
        print("// Implementation de reference : voir le script, ecrit d'apres la version Go.")
        print("")
        print("struct Vector {")
        print("    secret: &'static str,")
        print("    now: i64,")
        print("    difficulty: u32,")
        print("    ip: &'static str,")
        print("    conn_id: &'static str,")
        print("    clearance_ip: &'static str,")
        print("    challenge_salt: &'static str,")
        print("    clearance_salt: &'static str,")
        print("    challenge: &'static str,")
        print("    signature: &'static str,")
        print("    payload_json: &'static str,")
        print("    nonce: u64,")
        print("    leading_zero_bits: u32,")
        print("    clearance: &'static str,")
        print("}")
        print("")
        print("const VECTORS: Vector = Vector {")
        for key, rust_type in [
            ("secret", str),
            ("now", int),
            ("difficulty", int),
            ("ip", str),
            ("conn_id", str),
            ("clearance_ip", str),
            ("challenge_salt_b64", str),
            ("clearance_salt_b64", str),
            ("challenge", str),
            ("signature", str),
            ("payload_json", str),
            ("nonce", int),
            ("leading_zero_bits", int),
            ("clearance", str),
        ]:
            name = key.replace("_b64", "")
            if rust_type is int:
                print(f"    {name}: {vectors[key]},")
            else:
                print(f'    {name}: r#"{vectors[key]}"#,')
        print("};")
        return

    if args.json:
        print(json.dumps(vectors, indent=2))
        return

    print("secret            :", vectors["secret"])
    print("horodatage        :", vectors["now"])
    print("charge utile      :", vectors["payload_json"])
    print("sel du challenge  :", vectors["challenge_salt_b64"])
    # Coupe en deux : la valeur fait 180 caracteres et se lit mieux ainsi.
    print("challenge (1/2)   :", vectors["challenge"][:90])
    print("challenge (2/2)   :", vectors["challenge"][90:])
    print("signature         :", vectors["signature"])
    print("nonce resolu      :", vectors["nonce"])
    print("sel de clearance  :", vectors["clearance_salt_b64"])
    print("clearance         :", vectors["clearance"])
    print()
    print("Toutes les verifications internes passent.")


if __name__ == "__main__":
    main()
