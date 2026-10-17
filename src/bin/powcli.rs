//! Client de verification, pour diagnostic et test d'integration.
//!
//! Equivalent de `test/tools/powcli` du depot d'origine, en Rust. Il fait ce que
//! fait le navigateur, en deux temps sur **une seule connexion TCP** :
//!
//! 1. requete qui recoit le 403 et les cookies de challenge ;
//! 2. resolution du PoW, puis seconde requete portant l'en-tete
//!    `challenge-token`, sur la meme connexion.
//!
//! La seconde requete doit rester sur la meme connexion : le challenge est lie a
//! l'identifiant de connexion Envoy en plus de l'adresse du client. C'est la
//! meme raison qui pousse le solveur JavaScript du navigateur a faire un
//! `fetch()` avant de naviguer.
//!
//! Ce binaire ne se compile que pour la machine hote :
//! `cargo build --release --bin powcli`. La construction du module wasm passe
//! par `--lib` (voir le Makefile).
//!
//! ```text
//! powcli --url http://127.0.0.1:18080/protege
//! ```

use std::error::Error;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use pow_proxy::token::{solve, ChallengePayload, Solution};

/// Plafond d'iterations, pour ne pas boucler indefiniment sur une difficulte
/// volontairement enorme.
const MAX_ITERATIONS: u64 = 1 << 30;

struct Response {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        let prefix = format!("{name}=");
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .filter_map(|(_, v)| v.split(';').next())
            .find_map(|pair| pair.trim().strip_prefix(&prefix))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut url = String::from("http://127.0.0.1:18080/");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--url" => {
                index += 1;
                url = args.get(index).ok_or("--url attend une valeur")?.clone();
            }
            "--help" | "-h" => {
                println!("usage: powcli --url http://hote:port/chemin");
                return Ok(());
            }
            other => return Err(format!("argument inconnu : {other}").into()),
        }
        index += 1;
    }

    let (addr, path) = split_url(&url)?;
    println!("cible : {url}");

    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    println!("connexion a {addr}");

    // 1) Premiere requete : on attend le challenge.
    send_request(&mut stream, &path, &addr, None)?;
    let first = read_response(&mut stream)?;
    println!("1re reponse : {} {}", first.status, first.reason);

    if first.status != 403 {
        if let Some(clearance) = first.cookie("challenge-clearance") {
            println!(
                "deja autorise, clearance presente ({} octets)",
                clearance.len()
            );
        } else {
            println!("rien a resoudre : le filtre ne protege pas cette route");
        }
        return Ok(());
    }

    let challenge = first
        .cookie("challenge")
        .ok_or("cookie `challenge` absent de la reponse 403")?
        .to_string();
    println!("page de challenge : {} octets", first.body.len());
    let signature = first
        .cookie("challenge-sig")
        .or_else(|| first.header("challenge-sig"))
        .ok_or("signature du challenge absente (cookie et en-tete)")?
        .to_string();

    let raw = B64.decode(challenge.as_bytes())?;
    let payload: ChallengePayload = serde_json::from_slice(&raw)?;
    println!(
        "challenge recu : difficulte {}, expire a {}, contexte {:?}",
        payload.diff, payload.exp, payload.ctx
    );

    // 2) Resolution, puis seconde requete sur la meme connexion.
    let started = Instant::now();
    let nonce = solve(&challenge, payload.diff, MAX_ITERATIONS)
        .ok_or("aucune solution trouvee dans le plafond d'iterations")?;
    let elapsed = started.elapsed();
    let hashes_per_second = if elapsed.as_secs_f64() > 0.0 {
        nonce as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    println!(
        "solution trouvee : nonce {nonce} en {:.2} s ({:.0} h/s)",
        elapsed.as_secs_f64(),
        hashes_per_second
    );

    let token = serde_json::to_string(&Solution {
        c: challenge,
        s: signature,
        n: nonce,
    })?;
    send_request(&mut stream, &path, &addr, Some(&token))?;
    let second = read_response(&mut stream)?;
    println!("2e reponse  : {} {}", second.status, second.reason);

    match second.status {
        403 => {
            println!("refuse : nouvelle requete sans clearance (contexte client different ?)");
            if !second.body.is_empty() {
                let snippet: String = second.body.chars().take(200).collect();
                println!("corps de la reponse : {snippet}");
            }
            std::process::exit(1);
        }
        status => {
            if let Some(clearance) = second.cookie("challenge-clearance") {
                println!(
                    "clearance recue : {} octets, Max-Age {}",
                    clearance.len(),
                    header_max_age(&second, "challenge-clearance")
                        .as_deref()
                        .unwrap_or("?")
                );
                println!("succes : {status}");
            } else {
                println!("succes : {status}, sans clearance dans cette reponse");
            }
            Ok(())
        }
    }
}

fn header_max_age(response: &Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    response
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter(|(_, v)| v.trim_start().starts_with(&prefix))
        .find_map(|(_, v)| {
            v.split(';')
                .map(|part| part.trim())
                .find_map(|part| part.strip_prefix("Max-Age=").map(|s| s.to_string()))
        })
}

fn split_url(url: &str) -> Result<(String, String), Box<dyn Error>> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("seul le schema http:// est gere par cet outil de test")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    Ok((addr, path))
}

fn send_request(
    stream: &mut TcpStream,
    path: &str,
    host: &str,
    challenge_token: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: text/html\r\nConnection: keep-alive\r\n"
    );
    if let Some(token) = challenge_token {
        request.push_str(&format!("challenge-token: {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn read_response(stream: &mut TcpStream) -> Result<Response, Box<dyn Error>> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default().to_string();
    let status: u16 = parts.next().ok_or("ligne de statut illisible")?.parse()?;
    let reason = parts.collect::<Vec<_>>().join(" ");

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body)?;
    }

    let _ = version;
    Ok(Response {
        status,
        reason,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}
