# pow-proxy, en Rust

[![CI](https://github.com/GuillaumeASSIER/pow-envoy-wasm/actions/workflows/ci.yml/badge.svg)](https://github.com/GuillaumeASSIER/pow-envoy-wasm/actions/workflows/ci.yml)

> Reecriture en Rust du plugin Go
> [kubewaf-io/pow-proxy-wasm](https://github.com/kubewaf-io/pow-proxy-wasm),
> sous Apache-2.0. Format identique sur le fil.

Filtre Proxy-WASM de challenge proof-of-work, a poser sur la passerelle Istio.

Quand une requete arrive sans preuve, le filtre repond un 403 avec une page de
challenge et deux cookies signes. Le navigateur resout une preuve de travail
(SHA-256 tronque) et reprend sa requete. La resolution donne un cookie de
clearance, valable trente minutes, qui laisse passer la suite du trafic sans
nouvelle preuve.

Le cout retombe sur le client, pas sur le bord : c'est le principe, et c'est ce
qui rend la brique interessante pour un bord qui doit encaisser du trafic
automatise sans investir dans du calcul de son cote.

## Documentation

- [`docs/protocol.md`](docs/protocol.md) : le format exact de ce qui circule, de
  quoi ecrire un client dans un autre langage.
- [`docs/configuration.md`](docs/configuration.md) : chaque cle, sa borne, son
  defaut, et les cas ou le module refuse de se charger.
- [`docs/architecture.md`](docs/architecture.md) : organisation du crate, ce qui
  est verifie et ce qui ne l'est pas.
- [`docs/deployment.md`](docs/deployment.md) : artefact OCI, ressource
  `WasmPlugin`, et les pieges de format qui font echouer un deploiement.
- [`NOTICE`](NOTICE) : attribution de l'amont et perimetre de la reprise.

## Origine et licence

Reecriture en Rust du plugin Go [kubewaf-io/pow-proxy-wasm](https://github.com/kubewaf-io/pow-proxy-wasm),
sous Apache-2.0. La reecriture conserve le format sur le fil : memes cookies,
meme charge utile, memes jetons. Un navigateur ou un client ecrit pour la version
Go fonctionne sans modification contre celle-ci, et l'inverse est vrai.

- `LICENSE` : Apache-2.0, copyright du present depot. Le code d'origine est sous
  la meme licence, donc rien ne s'oppose a redistribuer ce depot sous
  Apache-2.0 ; c'est meme la condition pour reprendre un travail derive.
- `NOTICE` : attribution de l'amont, commit de reference, ce qui a ete repris tel
  quel.
- `assets/challenge.html` : le solveur JavaScript du depot d'origine, repris
  **tel quel**. Il definit le protocole cote client et n'a pas ete reecrit.

## Ce qui change par rapport a la version Go

Le format ne change pas. L'implementation, si, sur sept points, tous motives :

1. **Sel derive par HMAC, pas par `crypto/rand`.** Le sel d'un challenge est
   `HMAC(secret, etiquette || sequence || horodatage || compteur)`. Consequence
   concrete : le module n'importe plus aucune fonction WASI d'alea, donc il se
   charge meme sur un hote qui n'implemente pas `random_get`, et les tests sont
   reproductibles. Le sel reste imprevisible sans le secret, ce qui est la seule
   propriete dont depend le challenge.
2. **Signature verifiee avant l'expiration.** La version Go lisait `exp` avant de
   verifier le MAC, donc prenait une decision sur un champ que personne n'avait
   signe. L'ordre est inverse ici.
3. **Logique de decision extraite du code de transport.** `protocol::handle`
   prend une vue de la requete et rend un verdict ; `http.rs` ne fait que lire
   les en-tetes et appliquer le verdict. C'est ce qui permet de tester le
   comportement complet en `cargo test`, sans Envoy.
4. **Niveau de journalisation respecte avant formatage.** La version Go formate
   ses messages de debogage a chaque requete pour que l'hote les jette ensuite.
5. **Plus de chemin « fail open » interne a l'emission.** Ce chemin existait
   parce que `crypto/rand` peut echouer. L'emission n'a plus d'etape faillible,
   donc la question ne se pose plus ; c'est `failStrategy` du `WasmPlugin` qui
   tranche en cas de plantage du module.
6. **`connection.id` manipule en octets bruts.** L'ABI rend huit octets
   petit-boutistes qui ne sont pas de l'UTF-8 valide ; passer par une chaine
   avant decodage perdrait l'identifiant une fois sur deux environ.
7. **Plus d'en-tete de difficulte pilote par le client.** La version Go lit
   `x-challenge-difficulty` sur la requete du client et l'applique apres bornage :
   le client choisissait donc son plancher de difficulte. Ici la difficulte ne
   vient que de la pression mesuree et de la configuration. La seule entree
   exterieure est la remediation, `drop`, `captcha` ou `pow`, dans un en-tete
   interne que le bord ecrase, et qui retombe sur `pow` s'il est absent.


## Structure

```
src/token.rs      challenge, solution, clearance : crypto et format
src/cookie.rs     lecture et ecriture des cookies
src/client.rs     adresse client, identifiant de connexion
src/config.rs     configuration du plugin, bornes de difficulte
src/protocol.rs   moteur de decision, sans aucun appel a l'hote
src/plugin.rs     contexte racine Proxy-WASM (wasm uniquement)
src/http.rs       adaptateur Proxy-WASM (wasm uniquement)
src/log.rs        journalisation avec seuil (wasm uniquement)
src/entry.rs      point d'entree du module (wasm uniquement)
src/bin/powcli.rs client de diagnostic, natif
tools/            implementation de reference, serveur de test, outil d'inspection
tests/            recoupement avec la reference
```

Les quatre premiers modules et `protocol` sont du Rust portable : aucune
dependance a l'hote, aucun etat global. C'est la partie qui porte les decisions,
et c'est elle que `cargo test` exerce.

## Commandes

```bash
make test          # tests natifs : 58 tests
make lint          # formatage + Clippy, avertissements bloquants
make wasm-build    # module wasm + controle des imports + empreinte
make wasm-oci      # artefact OCI local, verifiable sans registre
make e2e           # client Rust contre l'edge de test Python
make vectors       # regenere les vecteurs de recoupement
```

Prerequis : `rustup target add wasm32-wasip1`, `oras` pour l'artefact OCI,
`python3` pour les outils de test (bibliotheque standard uniquement).

## Ce qui a ete verifie, et ce qui ne l'a pas ete

Verifie pour de vrai, dans ce depot :

- **58 tests natifs** : protocole complet, cookies, adresses, difficulte
  dynamique, clearance liee a l'IP, refus des jetons alteres, expiration.
- **Recoupement octet pour octet** avec une implementation independante en Python
  (`tools/gen_vectors.py`), ecrite d'apres la version Go : challenge, signature,
  charge utile JSON (ordre des cles compris), jeton de clearance.
- **Propriete de chemin chaud** : un test verifie que le chemin de la clearance
  ne lit ni l'identifiant de connexion, ni le schema, ni la difficulte.
- **Bout en bout sur sockets** : `powcli` resout un challenge emis par le serveur
  de reference Python et obtient une clearance, sur une seule connexion TCP.
- **Module wasm** : 263 Kio (269 047 octets), construit pour `wasm32-wasip1`,
  imports verifies (ABI `env` plus `environ_get`, `environ_sizes_get`, `fd_write`,
  `proc_exit`).
- **Artefact OCI** : conforme aux regles du recuperateur d'Istio, lues dans
  `pkg/wasm/imagefetcher.go` de la version 1.30.6. La variante OCI exige
  **exactement deux couches** : une de configuration
  (`application/vnd.module.wasm.config.v1+json`) et une du module
  (`application/vnd.module.wasm.content.layer.v1+wasm`), dont le contenu est lu
  brut, sans decompression. `tools/check_oci_manifest.py` verifie ces trois
  regles et `make wasm-oci` echoue si elles ne tiennent pas. Un artefact a une
  seule couche, ce que produit `oras push` par defaut, est refuse au chargement.

Pas verifie, et il faut le savoir :

- **Aucun test sous Envoy ou Istio.** L'adaptateur `http.rs` n'est exerce que dans
  un vrai proxy. Les tests couvrent la logique, pas le branchement des hostcalls.
  Le premier `apply` avec `pow_enabled = true` est donc la premiere fois que
  cette partie tourne ; le journal du proxy et `x-request-id` sont tes amis.
- **Aucune mesure de performance.** La difficulte par defaut (18 bits) demande
  environ un quart de seconde a un poste de bureau, mais le cout cote bord du
  chemin rapide n'a pas ete mesure. Mesure-le avant de generaliser.

## Deploiement

Cote infrastructure, le plugin se pose par la couche de bord du depot
`poc-exoledge` (`tofu/edge/wasm-plugin.tf`) :

```hcl
pow_enabled   = true
pow_wasm_url  = "oci://ghcr.io/guillaumeassier/pow-proxy-rust:0.1.0"
pow_wasm_sha256 = "<somme affichee par make wasm-build>"
```

`pow_secret` est engendre si tu ne le fournis pas. Il atterrit dans le state
OpenTofu, comme la configuration du plugin : le state doit donc etre protege.
`make wasm-publish` pousse l'artefact ; `oras login ghcr.io` est necessaire, avec
un jeton qui porte `write:packages`.

Le format de l'artefact OCI a ete verifie contre le code d'Istio 1.30.6, mais
aucun chargement n'a encore eu lieu dans un vrai proxy. Si `istiod` refuse
l'artefact, le repli est `http://` ou `https://` avec `sha256` : sers le module
depuis n'importe quel hebergement statique, c'est le schema le mieux documente
par Istio.
