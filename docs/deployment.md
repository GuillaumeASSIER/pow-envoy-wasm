# Deploiement

Comment livrer le module a Istio, et les regles de format qui font echouer un
deploiement quand on les ignore.

## Construire et publier

```bash
make wasm-build     # compile, verifie les imports, affiche l'empreinte
make wasm-oci       # artefact OCI local, verifiable sans registre
make wasm-publish   # poussee vers le registre
```

`make wasm-publish` a besoin d'une session `oras login ghcr.io` avec un jeton
qui porte `write:packages`. L'image cible se change par `IMAGE=` :

```bash
make wasm-publish IMAGE=ghcr.io/guillaumeassier/pow-proxy-rust:0.1.1
```

## L'artefact OCI, et ses deux couches

Istio recupere le module depuis un registre OCI (`pkg/wasm/imagefetcher.go`).
Sa variante OCI accepte **trois formats**, dans cet ordre, et il faut en
satisfaire un :

1. **image Docker** : media type du manifeste `application/vnd.docker.distribution.manifest.v2+json`,
   derniere couche en `application/vnd.docker.image.rootfs.diff.tar.gzip` ;
2. **variante compat** : une seule couche `application/vnd.oci.image.layer.v1.tar+gzip` ;
3. **variante OCI**, celle que produit ce depot : **exactement deux couches**,
   une de configuration et une du module.

La variante OCI exige precisement deux couches, et le message d'erreur d'Istio le
dit : `number of layers must be 2 but got 1`. C'est le piege du sujet, parce que
`oras push` avec un seul fichier produit une couche unique et un artefact qui a
l'air correct :

```bash
printf '{}' > build/module-config.json
cp target/wasm32-wasip1/release/pow_proxy.wasm build/pow-proxy.wasm
cd build && oras push "$IMAGE" \
  module-config.json:application/vnd.module.wasm.config.v1+json \
  pow-proxy.wasm:application/vnd.module.wasm.content.layer.v1+wasm
```

Deux details du format :

- le contenu de la couche du module est le **wasm brut, non compresse** : Istio
  lit la couche avec `Compressed()` et ne decompresse pas. Un module passe par
  `gzip` ou range dans une archive tar ne se charge pas ;
- la couche de configuration n'est jamais lue par Istio, mais elle doit etre la.
  `{}` suffit.

`make wasm-oci` effectue ces controles et **echoue** si l'artefact n'est pas
conforme, avec `tools/check_oci_manifest.py`. Ces regles ont ete lues dans le
code d'Istio 1.30.6, pas devinees.

## Poser le filtre

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: pow-challenge
  namespace: edge
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: edge-gateway
  url: oci://ghcr.io/guillaumeassier/pow-proxy-rust:0.1.0
  sha256: <somme du module, facultatif mais recommande>
  phase: AUTHN
  type: HTTP
  priority: 10
  failStrategy: FAIL_OPEN
  pluginConfig:
    secret: "<32 octets minimum>"
    base_difficulty: 18
    client_ip_source: source_address
```

Les choix qui comptent :

- **`phase: AUTHN`** : le filtre s'execute avant l'authentification et avant
  l'application. Un client qui ne paie pas sa preuve de travail est arrete tot.
- **`failStrategy: FAIL_OPEN`** : si le module ne se charge pas ou panique, le
  trafic passe. Pour un anti-robot, une panne du filtre ne doit pas devenir une
  panne de service. Contrepartie : une protection absente ne se voit pas dans les
  codes de reponse, elle se voit dans les journaux.
- **`targetRefs`** : la passerelle entiere ici. Istio accepte aussi un
  `HTTPRoute`, pour ne proteger qu'une route.
- **`sha256`** : l'empreinte du **module**, pas du manifeste OCI. Elle evite de
  charger un artefact qui ne correspond pas a ce qui a ete construit.
- **`priority`** : ordre entre plugins d'une meme phase, le plus petit passe en
  premier.

Le `pluginConfig` est documente cle par cle dans `docs/configuration.md`.

## Routes internes a router vers le service de verification

Quand le scoring demande un captcha, le filtre sert une page qui a besoin de
trois routes. Elles ne doivent **jamais** atteindre l'origine :

| Route | Methode | Role |
| --- | --- | --- |
| `/__challenge/altcha.js` | GET | le composant de captcha, servi par votre infrastructure |
| `/__challenge/altcha-challenge` | GET | emission d'un challenge de captcha |
| `/__challenge/captcha` | POST | verification du jeton, puis pose de la clearance |

Ces routes appartiennent au service de verification, pas au module : un filtre
WASM n'a pas de sortie reseau garantie, et la cle de verification d'un captcha
n'a rien a faire dans un binaire distribue. Meme logique que CrowdSec, qui fait
router `/crowdsec-internal/challenge/*` vers son composant AppSec.

Deux regles qui evitent les pannes silencieuses : la requete `POST` doit
conserver son corps jusqu'au service, et la reponse du service doit pouvoir
poser un `Set-Cookie` (la clearance) sans que le proxy la reecrive.

## Verifier que le filtre tourne

Au chargement, le module journalise sa configuration effective :

```
pow-proxy: difficulte base=18 min=12 max=26, source_ip=Peer, secret=48 octets, log=Info
pow-proxy: fenetre challenge=60s clearance=1800s
```

Si ces lignes n'apparaissent pas dans le journal du proxy, le module n'est pas
charge. Dans l'ordre : l'URL de l'artefact est-elle joignable par istiod, le
`sha256` correspond-il, le `pluginConfig` porte-t-il un secret d'au moins 32
octets.

Ensuite, une requete sans preuve doit recevoir un **403** avec les quatre cookies
de challenge :

```bash
curl -i https://edge.example.com/ | head -20
```

Si tu obtiens un 200 direct, le filtre n'est pas actif sur cette route.

## Repli si Istio refuse l'artefact

Istio accepte aussi une URL `http://` ou `https://` avec un `sha256`. Sers le
module depuis n'importe quel hebergement statique :

```yaml
  url: https://exemple.fr/pow-proxy.wasm
  sha256: 706e5c0afb43f71bb93675c8eef7f39ed57998e3ba9370af8097e2dc0c89a21c
```

C'est le schema le mieux documente par Istio, et il evite completement la
question du format OCI. Le prix est une dependance a un hebergement au lieu d'un
registre.

## Ce qui reste non verifie

Aucun chargement de ce module dans un vrai Envoy n'a encore eu lieu. Le format de
l'artefact, lui, a ete verifie contre le code d'Istio 1.30.6, et les tests natifs
couvrent la logique et le protocole. Le premier deploiement reel reste le premier
essai du branchement des hostcalls.
