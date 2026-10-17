# Protocole

Le format exact de ce qui circule sur le fil. C'est le document a lire avant de
modifier le code, et celui qui permet d'ecrire un client dans un autre langage.

Le protocole est **identique a celui de la version Go**
[kubewaf-io/pow-proxy-wasm](https://github.com/kubewaf-io/pow-proxy-wasm), dont
ce filtre est une reecriture. Un client ecrit pour l'un fonctionne avec l'autre.

## Le cycle

```
client                                  filtre
  |                                       |
  |  GET /page                            |
  |-------------------------------------->|
  |                                       |  aucune preuve valable
  |  403 + page de challenge              |
  |  Set-Cookie: challenge=<j>            |
  |  Set-Cookie: challenge-sig=<sig>      |
  |  Set-Cookie: challenge-nonce= (vide)  |
  |  Set-Cookie: challenge-clearance= (vide)
  |<--------------------------------------|
  |                                       |
  |  resolution de la preuve de travail   |
  |  (JavaScript dans la page, ou powcli) |
  |                                       |
  |  GET /page                            |
  |  Cookie: challenge=<j>; challenge-sig=<sig>;
  |          challenge-nonce=<n>          |
  |-------------------------------------->|
  |                                       |  preuve valide
  |  200                                  |
  |  Set-Cookie: challenge-clearance=<c>  |
  |<--------------------------------------|
  |                                       |
  |  GET /page                            |
  |  Cookie: challenge-clearance=<c>      |
  |-------------------------------------->|
  |                                       |  clearance valide, chemin rapide
  |  200                                  |
  |<--------------------------------------|
```

## Les jetons

Trois objets, tous en base64url sans remplissage.

```
challenge  = base64url(JSON {ts, exp, diff, salt, ctx, cid})
signature  = base64url(HMAC-SHA256(secret, challenge))
preuve     = SHA-256(base64url_decode(challenge) || nonce_be64)
clearance  = corps "." base64url(HMAC-SHA256(secret, corps))
corps      = base64url(exp_be64 || salt16 || ip_utf8)
```

**Le challenge** est un JSON en clair : ce n'est pas un secret, c'est un ordre de
travail signe. Il porte l'horodatage d'emission (`ts`), l'expiration (`exp`), la
difficulte demandee (`diff`), le sel (`salt`), et le contexte client (`ctx`
l'adresse, `cid` l'identifiant de connexion). Le hachage se fait sur la forme
encodee, pas sur le JSON decode.

**La signature** couvre la chaine base64url telle qu'elle est transmise. Elle
n'est pas un secret non plus : elle empeche de fabriquer un challenge sur mesure
avec une difficulte faible.

**La preuve** hache le challenge decode suivi du nonce en 8 octets gros-boutistes.
Le client cherche un nonce dont le SHA-256 a au moins `diff` bits de tete a zero.
C'est le travail a fournir, et il n'y a pas de raccourci.

**La clearance** est auto-portante : son corps contient l'expiration, un sel de 16
octets et l'adresse du client, le tout signe. Rien n'est stocke cote bord, donc
aucun etat a partager entre instances pour valider une clearance. Le sel evite
que deux clearances du meme client a la meme seconde soient identiques.

## Cookies

| Nom | Role | Duree |
| --- | --- | --- |
| `challenge` | le challenge signe | 60 s |
| `challenge-sig` | sa signature | 60 s |
| `challenge-nonce` | la solution trouvee | 60 s |
| `challenge-clearance` | la preuve de resolution | 1800 s |

Format d'ecriture, attributs dans cet ordre :

```
name=value; Path=/; Max-Age=<n>; SameSite=Lax[; HttpOnly][; Secure]
```

Le drapeau `Secure` suit le schema de la requete qui presente la preuve : un
client venu en HTTPS recoit un cookie marque `Secure`, un client en HTTP non.

Un challenge est emis en **effacant** le nonce et la clearance precedents : une
nouvelle tentative ne laisse pas de reste de la precedente.

## Forme par en-tete, pour les clients qui ne gerent pas les cookies

Une requete peut porter sa solution dans un en-tete, en JSON :

```
challenge-token: {"c":"<challenge>","s":"<signature>","n":<nonce>}
```

C'est ce que la version Go appelle le mode API, et c'est ce qu'utilise `powcli`.
La clearance revient alors dans un `Set-Cookie`, comme pour un navigateur.

Deux en-tetes sont lus sur la requete :

- `x-challenge-difficulty` : impose la difficulte du challenge emis, dans les
  bornes configurees. Sert aux essais et a un palier negocie cote client.
- `challenge-token` : la solution, decrite ci-dessus.

## Ordre de decision

L'ordre n'est pas cosmetique : il determine ce que coute une requete.

1. **Clearance** presente et valide : passage. Ce chemin ne lit **que** l'adresse
   du client. Ni le cookie de challenge, ni le schema, ni la difficulte ne sont
   lus. C'est le chemin de tout le trafic legitime apres la premiere resolution,
   et un test verifie explicitement cette propriete.
2. **Solution par cookies** (`challenge`, `challenge-sig`, `challenge-nonce`) :
   emission d'une clearance.
3. **Solution par en-tete** `challenge-token` : emission d'une clearance.
4. **Aucune preuve valable** : emission d'un challenge signe, avec effacement des
   restes de la tentative precedente.

## Sel

Le sel n'est pas tire au hasard : il est **derive** par HMAC du secret, ce qui
supprime toute dependance a l'alea de l'hote et rend l'emission reproductible.

```
sel = HMAC-SHA256(secret, "exoledge/pow/salt/v1" || seq_be64 || now_be64 || bloc_be32)
```

L'etiquette est versionnee pour pouvoir tourner un jour sans invalider l'ancien
format d'un coup. `seq` est un compteur qui avance a chaque tirage, ce qui suffit
a rendre deux sels differents a la meme seconde. Le bloc permet de produire plus
de 32 octets si besoin.

Propriete qui compte : sans le secret, le sel est imprevisible. Avec le secret,
il est reproductible, ce qui est exactement ce qu'il faut pour tester l'emission
octet pour octet.

## Difficulte

La difficulte se compte en **bits de tete a zero** du SHA-256. Chaque bit
supplementaire double le travail attendu.

- `base_difficulty` : 18 par defaut, soit environ un quart de seconde sur un poste
  de bureau.
- bornes `min_difficulty` (12) et `max_difficulty` (26).
- un reglage hors bornes est ramene dans l'intervalle ; un `max` incoherent est
  remplace par 26.

La difficulte monte toute seule sous la pression. Toutes les 5 secondes, le
filtre regarde combien de challenges il a emis dans la fenetre, remet le compteur
a zero, et ajoute :

| Challenges emis en 5 s | Ajustement |
| --- | --- |
| 800 et plus | +6 |
| 400 et plus | +4 |
| 180 et plus | +3 |
| 80 et plus | +2 |
| 35 et plus | +1 |
| moins de 35 | 0 |

La difficulte courante est publiee dans les donnees partagees de l'hote sous la
cle `challenge:current_difficulty`, et relue au demarrage : plusieurs machines
virtuelles Wasm d'un meme proxy se coordonnent ainsi sans service externe. Les
seuils viennent de la version Go ; ce sont des heuristiques de depart, a ajuster
sur du trafic reel.

## Ce qui lie un jeton a un client

Un challenge lie **l'adresse du client et l'identifiant de connexion** : une
solution trouvee sur une connexion ne se rejoue pas sur une autre, ce qui empeche
de resoudre une fois et de distribuer la reponse a un parc.

Une clearance, elle, ne lie **que l'adresse**. C'est voulu : elle doit survivre a
la fermeture de la connexion, sinon un simple rechargement de page couterait une
nouvelle preuve de travail.

L'adresse retenue depend de `client_ip_source` : `source_address` prend l'adresse
du pair TCP, `auto` accepte en plus `X-Forwarded-For` puis `X-Real-IP`. Sur un
bord qui termine lui-meme les connexions, `source_address` est le bon reglage.

## Comment verifier sans cluster

- `cargo test` : 58 tests, dont le protocole complet, la liaison a l'adresse, le
  refus des jetons alteres et l'expiration.
- `python3 tools/gen_vectors.py` : une implementation de reference independante,
  ecrite d'apres la version Go. `--json` pour lire les vecteurs, `--rust` pour
  regenerer le fichier utilise par les tests de recoupement.
- `python3 tools/fake_edge.py --port 18081` : un bord de test qui applique le
  protocole avec l'implementation de reference.
- `cargo run --bin powcli -- --url http://127.0.0.1:18081/` : un client de bout
  en bout, sur une seule connexion. `make e2e` enchaine les deux.
