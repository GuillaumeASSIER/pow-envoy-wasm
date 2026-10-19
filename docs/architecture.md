# Architecture du crate

Comment le code est organise, et pourquoi il est organise comme ca.

## Modules

```
src/lib.rs        constantes de duree de vie, point d'entree de la crate
src/token.rs      challenge, preuve, clearance : crypto et format
src/cookie.rs     lecture et ecriture des cookies
src/client.rs     adresse du client, identifiant de connexion
src/config.rs     configuration, bornes et valeurs par defaut
src/protocol.rs   moteur de decision, sans aucun appel a l'hote
src/log.rs        journalisation a seuil
src/plugin.rs     contexte racine Proxy-WASM
src/http.rs       adaptateur Proxy-WASM
src/entry.rs      point d'entree du module
src/bin/powcli.rs client de diagnostic, natif
```

## La separation qui compte

Le crate est coupe en deux, et la frontiere est stricte :

**Du Rust portable**, sans dependance a l'hote et sans etat global : `config`,
`token`, `cookie`, `client`, `protocol`. C'est la partie qui porte toutes les
decisions, et c'est elle que `cargo test` exerce sur la machine, sans Envoy.

**L'adaptateur Proxy-WASM**, compile uniquement pour `wasm32` : `entry`, `log`,
`plugin`, `http`. Il lit les faits de la requete et applique le verdict. Aucune
regle metier n'y vit.

Le contrat entre les deux est un trait, `protocol::HostView`. Le moteur demande
une vue de la requete : l'en-tete `Cookie`, l'en-tete `challenge-token`, l'adresse
du pair, `X-Forwarded-For`, `X-Real-IP`, l'identifiant de connexion, le schema.
L'adaptateur les fournit avec les hostcalls, les tests avec des doublures.

Cette frontiere est ce qui rend le projet verifiable. Sans elle, la seule facon
de tester le comportement du filtre est de monter un Envoy complet : on ne teste
donc rien, ou presque. Avec elle, 58 tests couvrent le protocole complet, la
liaison a l'adresse, le refus des jetons alteres, l'expiration et la difficulte
dynamique, en une fraction de seconde.

## Proprietes verifiees explicitement

Trois garanties ne sont pas des espoirs, elles sont testees :

- **Chemin chaud minimal.** Le chemin de la clearance ne lit que l'adresse du
  client. Un test verifie qu'aucun autre fait n'est demande : ni l'identifiant de
  connexion, ni le schema, ni l'en-tete de difficulte. C'est ce qui garde le
  trafic legitime le moins cher possible.
- **Parite avec l'implementation d'origine.** Les vecteurs de recoupement sont
  produits par une implementation Python **independante**, ecrite d'apres la
  version Go et non d'apres ce Rust. Le test compare octet pour octet : le
  challenge, sa signature, la charge utile JSON (ordre des cles compris) et le
  jeton de clearance.
- **Surface d'imports du module.** `tools/inspect_wasm.py` lit la section
  d'import du wasm compile et refuse tout ce qui sort du sous-ensemble attendu.
  C'est ce controle qui evite de decouvrir, au chargement dans Envoy, qu'un
  import WASI n'est pas fourni.

## Construire et verifier

```bash
make test          # 58 tests natifs
make lint          # formatage et Clippy, avertissements bloquants
make wasm-build    # module + imports + empreinte
make wasm-oci      # artefact OCI local, conforme aux regles d'Istio
make e2e           # client Rust contre l'edge de reference Python
make vectors       # regenere les vecteurs de recoupement
```

Le module fait 269 047 octets, et son empreinte est stable d'un clone neuf a
l'autre. La cible est `wasm32-wasip1` : la macro `main!` du SDK exporte
`_initialize`, donc Envoy instancie le module en mode reacteur, et Rust std
reclame alors quatre fonctions WASI que l'hote fournit (`environ_get`,
`environ_sizes_get`, `fd_write`, `proc_exit`).

`rust-version = "1.80"` dans `Cargo.toml` est verifie, pas annonce : la chaine
d'integration compile et teste aussi avec Rust 1.80.0.

## Ce qui n'est pas couvert

- **Le chargement dans un vrai Envoy.** Les tests couvrent la logique et le
  format ; l'adaptateur n'est exerce que dans un proxy reel. Le premier
  deploiement est le premier vrai test de cette partie.
- **La performance cote bord.** Le cout cote client est connu (un quart de
  seconde a 18 bits), le cout du chemin rapide dans le proxy non.
- **Le comportement sous attaque.** La difficulte dynamique est une heuristique
  reprise de l'original, pas un mecanisme valide en production.
