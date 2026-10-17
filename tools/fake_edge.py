#!/usr/bin/env python3
"""Edge de test : emule le plugin avec l'implementation de reference.

Ce serveur ne sert qu'aux tests. Il applique le meme protocole que le plugin,
avec l'implementation Python de `gen_vectors.py`, pour verifier le client Rust
(`powcli`) de bout en bout, sur de vraies sockets.

Il emule aussi la liaison a la connexion : l'identifiant utilise est le
descripteur de socket, comme Envoy le fait avec `connection.id`. Deux requetes
successives sur la meme connexion TCP portent donc le meme identifiant, ce qui
est exactement la propriete dont depend le flux navigateur.

Usage :
    python3 tools/fake_edge.py --port 18081
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gen_vectors import (  # noqa: E402
    CLEARANCE_LIFETIME,
    CLEARANCE_SALT_LEN,
    CHALLENGE_LIFETIME,
    derive_salt,
    issue_challenge,
    issue_clearance,
    verify_clearance,
    verify_solution,
)

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets")
with open(os.path.join(ASSETS, "challenge.html"), "rb") as handle:
    CHALLENGE_HTML = handle.read()


def parse_cookies(header: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not header:
        return out
    for part in header.split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            out[name.strip()] = unquote(value.strip())
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fake-edge"
    secret: bytes = b""
    difficulty: int = 6
    now_override: int | None = None

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        sys.stderr.write("fake-edge: " + format % args + "\n")

    # --- outils ---------------------------------------------------------

    def _send(self, status: int, body: bytes, cookies: list[str]) -> None:
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _connection_id(self) -> str:
        # Emule `connection.id` : stable pour une meme connexion TCP.
        return str(self.connection.fileno())

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _now(self) -> int:
        import time

        return self.now_override if self.now_override is not None else int(time.time())

    # --- traitement -----------------------------------------------------

    def do_GET(self) -> None:
        now = self._now()
        ip = self._client_ip()
        cid = self._connection_id()
        cookies = parse_cookies(self.headers.get("cookie"))

        # 1) clearance
        clearance = cookies.get("challenge-clearance")
        if clearance:
            try:
                verify_clearance(self.secret, clearance, ip, now)
                self.log_message("clearance valide pour %s", ip)
                self._grant(ip, now, already=True)
                return
            except ValueError as err:
                self.log_message("clearance refusee : %s", err)

        # 2) solution, par cookie ou par en-tete
        solution = None
        if all(k in cookies for k in ("challenge", "challenge-sig", "challenge-nonce")):
            try:
                solution = (
                    cookies["challenge"],
                    cookies["challenge-sig"],
                    int(cookies["challenge-nonce"]),
                )
            except ValueError:
                solution = None
        elif self.headers.get("challenge-token"):
            try:
                raw = json.loads(self.headers["challenge-token"])
                solution = (raw["c"], raw["s"], int(raw["n"]))
            except (ValueError, KeyError, TypeError) as err:
                self.log_message("en-tete challenge-token illisible : %s", err)

        if solution:
            try:
                verify_solution(self.secret, solution[0], solution[1], solution[2], ip, cid, now)
                self.log_message("solution acceptee pour %s (cid=%s)", ip, cid)
                self._grant(ip, now, already=False)
                return
            except ValueError as err:
                self.log_message("solution refusee : %s", err)

        # 3) challenge
        salt = derive_salt(self.secret, 0, now, 32)
        _, challenge, signature = issue_challenge(self.secret, self.difficulty, ip, cid, now, salt)
        self.log_message("challenge emis (difficulte %d, cid=%s)", self.difficulty, cid)
        self._send(
            403,
            CHALLENGE_HTML,
            [
                f"challenge={challenge}; Path=/; Max-Age={CHALLENGE_LIFETIME}; SameSite=Lax",
                f"challenge-sig={signature}; Path=/; Max-Age={CHALLENGE_LIFETIME}; SameSite=Lax",
                f"challenge-sig: {signature}",
            ],
        )

    def _grant(self, ip: str, now: int, already: bool) -> None:
        if already:
            self._send(200, b"bonjour\n", [])
            return

        salt = derive_salt(self.secret, 0, now, CLEARANCE_SALT_LEN)
        clearance = issue_clearance(self.secret, ip, now, salt)
        self._send(
            200,
            b"bonjour\n",
            [
                f"challenge-clearance={clearance}; Path=/; Max-Age={CLEARANCE_LIFETIME}; "
                "SameSite=Lax; HttpOnly",
                "challenge=; Path=/; Max-Age=0; SameSite=Lax",
                "challenge-sig=; Path=/; Max-Age=0; SameSite=Lax",
                "challenge-nonce=; Path=/; Max-Age=0; SameSite=Lax",
            ],
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--secret", default="0123456789abcdef0123456789abcdef")
    parser.add_argument(
        "--difficulty",
        type=int,
        default=6,
        help="volontairement basse : ce serveur sert a tester le client, pas a resister",
    )
    args = parser.parse_args()

    Handler.secret = args.secret.encode()
    Handler.difficulty = args.difficulty

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"fake-edge en ecoute sur http://127.0.0.1:{args.port} (difficulte {args.difficulty})")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
