#!/usr/bin/env python3
"""Verifie qu'un artefact OCI est chargeable par Istio.

Regles tirees de la lecture du recuperateur d'Istio 1.30.6
(`pkg/wasm/imagefetcher.go`, fonctions `extractOCIArtifactImage` et
`extractOCIStandardImage`) :

  - la variante OCI exige exactement deux couches ;
  - dont une au type `application/vnd.module.wasm.content.layer.v1+wasm` ;
  - et une couche de configuration au type
    `application/vnd.module.wasm.config.v1+json` ;
  - le contenu de la couche wasm est lu brut (non decompresse) : c'est le
    module tel quel, pas une archive.

Ces controles evitent de decouvrir le probleme au premier `apply`, quand istiod
refuse l'artefact et que le filtre ne se charge pas.

Usage : oras manifest fetch ... | python3 tools/check_oci_manifest.py
"""

import json
import sys

WASM_MEDIA_TYPE = "application/vnd.module.wasm.content.layer.v1+wasm"
CONFIG_MEDIA_TYPE = "application/vnd.module.wasm.config.v1+json"


def main() -> int:
    raw = sys.stdin.read().strip()
    if not raw:
        print("manifeste vide", file=sys.stderr)
        return 1

    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"manifeste illisible : {exc}", file=sys.stderr)
        return 1

    layers = manifest.get("layers") or []
    types = [layer.get("mediaType") for layer in layers]
    problems = []

    if len(layers) != 2:
        problems.append(
            f"la variante OCI exige exactement deux couches, l'artefact en a {len(layers)}"
        )
    if WASM_MEDIA_TYPE not in types:
        problems.append(f"aucune couche au type {WASM_MEDIA_TYPE}")
    if CONFIG_MEDIA_TYPE not in types:
        problems.append(f"aucune couche de configuration au type {CONFIG_MEDIA_TYPE}")

    for layer in layers:
        if layer.get("mediaType") == WASM_MEDIA_TYPE:
            annotations = layer.get("annotations") or {}
            title = annotations.get("org.opencontainers.image.title", "?")
            size = layer.get("size", 0)
            print(f"couche wasm   : {title}, {size} octets")

    if problems:
        for problem in problems:
            print(f"PROBLEME : {problem}", file=sys.stderr)
        print(
            "istiod refuserait cet artefact : "
            "« could not parse as oci variant »",
            file=sys.stderr,
        )
        return 1

    print("artefact conforme : istiod peut en extraire le module")
    return 0


if __name__ == "__main__":
    sys.exit(main())
