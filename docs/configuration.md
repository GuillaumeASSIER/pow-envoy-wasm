# Configuration

La configuration arrive en JSON, dans le champ `pluginConfig` de la ressource
`WasmPlugin` d'Istio. Le module la lit une fois, au chargement.

```json
{
  "secret": "une-chaine-de-32-octets-minimum",
  "base_difficulty": 18,
  "min_difficulty": 12,
  "max_difficulty": 26,
  "client_ip_source": "source_address",
  "log_level": "info"
}
```

## Cles

**`secret`** (chaine, obligatoire)

Cle HMAC qui signe les challenges et les clearances. **32 octets minimum**,
verifie au chargement : un secret plus court fait echouer le chargement du module
plutot que d'accepter une signature faible. Il n'est jamais journalise, meme en
`debug`.

Rien n'est stocke cote bord : ce secret est la seule autorite. Le changer
invalide toutes les clearances en cours, ce qui est sans consequence, et les
clients resolvent simplement un nouveau challenge.

**`base_difficulty`** (entier, defaut 18)

Difficulte de depart, en bits de tete a zero du SHA-256. Zero ou absent prend 18,
puis la valeur est ramenee dans `[min_difficulty, max_difficulty]`.

Ordre de grandeur : 18 bits, environ un quart de seconde sur un poste de bureau.
Chaque bit supplementaire double le travail demande.

**`min_difficulty`** (entier, defaut 12)

Borne basse. Zero ou absent prend 12. C'est le plancher sous charge faible : un
client ne resout jamais moins que ca.

**`max_difficulty`** (entier, defaut 26)

Borne haute. Zero, absent, ou inferieur a `min_difficulty` : remplace par 26. 26
bits, c'est plusieurs dizaines de secondes sur un poste de bureau : a ne relever
qu'en connaissance de cause, sous peine d'exclure de vrais visiteurs.

**`client_ip_source`** (chaine, defaut `auto`)

- `source_address` (ou `peer`, ou `source`) : l'adresse du pair TCP, et aucun
  en-tete de transfert n'est cru.
- toute autre valeur, dont `auto` : `source.address`, puis `X-Forwarded-For`,
  puis `X-Real-IP`.

Sur un bord qui termine lui-meme les connexions, `source_address` est le bon
reglage : un `X-Forwarded-For` peut etre ecrit par le client. Ne passe en `auto`
que si un equipement de confiance est devant le filtre.

**`log_level`** (chaine, defaut `info`)

`error`, `warn` (ou `warning`), `info`, `debug`, `trace`. Toute valeur inconnue
donne `info`. Le niveau est verifie **avant** de formater le message, donc un
niveau eleve ne coute rien sur le chemin chaud.

**`header`** et **`value`** (chaines, defaut vide)

Si `header` est non vide, le module ajoute cet en-tete, avec la valeur `value`, a
**chaque reponse qui traverse le filtre**. Sert a marquer le trafic pour
l'origine ou pour une sonde. Desactive quand `header` est vide, ce qui est le
defaut.

## Quand la configuration est refusee

Le module refuse de se charger si le JSON est absent, illisible, ou si le secret
est trop court. Le journal du proxy porte alors une ligne explicite :

```
pow-proxy: configuration obligatoire, attendu un JSON avec au moins {"secret":"<32 octets ou plus>"}
pow-proxy: configuration du plugin absente
pow-proxy: configuration du plugin illisible (JSON attendu)
pow-proxy: secret obligatoire, longueur minimale 32 octets
```

Un plugin qui ne charge pas ne protege rien, et le `failStrategy` de la ressource
`WasmPlugin` decide de la suite : avec `FAIL_OPEN`, le trafic passe **en
silence**. C'est le bon compromis pour un anti-robot, mais ca veut dire qu'un
chargement rate ne se voit pas dans les codes de reponse. Balaie le journal apres
chaque changement de configuration.

## Exemple en OpenTofu

```hcl
resource "kubectl_manifest" "pow_wasm_plugin" {
  yaml_body = yamlencode({
    apiVersion = "extensions.istio.io/v1alpha1"
    kind       = "WasmPlugin"
    metadata = {
      name      = "pow-challenge"
      namespace = "edge"
    }
    spec = {
      targetRefs = [{
        group = "gateway.networking.k8s.io"
        kind  = "Gateway"
        name  = "edge-gateway"
      }]
      url   = "oci://ghcr.io/guillaumeassier/pow-proxy-rust:0.1.0"
      phase = "AUTHN"
      type  = "HTTP"

      priority     = 10
      failStrategy = "FAIL_OPEN"

      pluginConfig = {
        secret           = var.pow_secret
        base_difficulty  = 18
        min_difficulty   = 12
        max_difficulty   = 26
        client_ip_source = "source_address"
        log_level        = "info"
      }
    }
  })
}
```

Attention : `pluginConfig` est stocke en clair dans la ressource, et donc dans le
state OpenTofu. Le state est un secret.

## Regler la difficulte

Le reglage se fait sur du trafic reel, jamais a l'aveugle :

1. commencer a `base_difficulty = 18` et lire les journaux en `debug` ;
2. regarder combien de challenges sont emis par fenetre de 5 secondes : c'est ce
   chiffre qui pilote l'ajustement automatique, pas le nombre de requetes ;
3. si la difficulte monte trop vite, remonter les seuils ou la borne haute ;
4. si des visiteurs legitimes se plaignent d'attendre, baisser `base_difficulty`
   d'un ou deux bits avant de toucher aux bornes.

La difficulte est recalculee a chaque battement de 5 secondes, en repartant de
`base` plus l'ajustement du moment. Elle redescend donc d'elle-meme des que la
pression retombe, sans memoire du pic : deux battements calmes suffisent a
revenir a `base`. C'est ce qui la rend utilisable en production, et c'est aussi
pourquoi un pic court n'a pas besoin d'etre anticipe dans le reglage.
