//! Challenge proof-of-work a l'edge, en Proxy-WASM.
//!
//! Reecriture en Rust du plugin Go `kubewaf-io/pow-proxy-wasm` (Apache-2.0).
//! Le format sur le fil est identique : memes cookies, meme charge utile, meme
//! derivation de signature. Un navigateur ou un client deja ecrit pour la
//! version Go fonctionne sans modification.
//!
//! # Decoupage
//!
//! La crate est separee en deux mondes :
//!
//! - `token`, `cookie`, `client`, `config`, `protocol` : logique pure, aucun
//!   appel a l'hote, aucun etat global. C'est la que vivent toutes les
//!   decisions. `cargo test` les exerce nativement, sans Envoy, sans Wasm.
//! - `plugin`, `http`, `entry` : l'adaptateur Proxy-WASM, compile uniquement
//!   pour `wasm32-wasip1`. Il lit les faits de la requete, appelle
//!   `protocol::handle`, puis applique le verdict par des hostcalls.
//!
//! Ce decoupage est la raison d'etre de la reecriture : dans la version Go, la
//! verification du PoW, la lecture du cookie et l'envoi de la reponse vivent
//! dans la meme fonction, donc la seule facon de la tester est de monter Envoy.
//! Ici, `protocol::handle` prend une vue de la requete et rend un verdict, ce
//! qui permet de verifier le comportement complet en test unitaire.

pub mod client;
pub mod config;
pub mod cookie;
pub mod protocol;
pub mod token;

#[cfg(target_arch = "wasm32")]
mod entry;
#[cfg(target_arch = "wasm32")]
mod http;
#[cfg(target_arch = "wasm32")]
pub mod log;
#[cfg(target_arch = "wasm32")]
mod plugin;

/// Nombre de secondes avant expiration du challenge, aligne avec le Max-Age du
/// cookie cote navigateur (`challenge.html`).
pub const CHALLENGE_LIFETIME_SECS: u64 = 60;

/// Duree de validite d'un cookie de clearance, en secondes.
pub const CLEARANCE_LIFETIME_SECS: u64 = 1800;

/// Taille minimale acceptee pour le secret HMAC.
pub const MIN_SECRET_LEN: usize = 32;
