#!/usr/bin/env python3
"""Inspecte un module wasm : sections, exports et imports exiges de l'hote.

Sert a verifier une propriete precise du module construit : quelles fonctions il
demande a l'hote. Un module Proxy-WASM doit se limiter a l'import `env`, et ne
devrait pas reclamer d'import WASI inutile, sinon il ne se charge pas sur un hote
qui ne l'implemente pas.

Usage :
    python3 tools/inspect_wasm.py chemin/vers/module.wasm
"""

from __future__ import annotations

import sys

# Sections de l'entete wasm que l'on sait lire.
SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}


# Sous-ensemble WASI que l'hote Envoy fournit et que le modele reacteur de Rust
# std reclame : initialisation (environ), sortie d'erreur (fd_write), arret
# (proc_exit). Verifier explicitement cette liste a un interet : Go 1.25 a fait
# apparaitre `path_filestat_get`, qu'Envoy n'implemente pas, et le module refuse
# alors de se charger. Un import hors de cette liste doit donc etre regarde avant
# toute mise en production.
ALLOWED_WASI = {
    "environ_get",
    "environ_sizes_get",
    "fd_write",
    "fd_close",
    "fd_seek",
    "fd_fdstat_get",
    "proc_exit",
    "clock_time_get",
    "random_get",
    "sched_yield",
}


def read_uleb(data: bytes, offset: int) -> tuple[int, int]:
    """Lit un entier LEB128 non signe."""
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Lit une chaine longueur-prefixee."""
    length, offset = read_uleb(data, offset)
    return data[offset : offset + length].decode("utf-8", "replace"), offset + length


def parse(data: bytes) -> dict:
    if data[:4] != b"\x00asm":
        raise ValueError("ce n'est pas un module wasm")
    version = int.from_bytes(data[4:8], "little")

    offset = 8
    imports: list[tuple[str, str, str]] = []
    exports: list[tuple[str, str]] = []
    sections: list[tuple[str, int]] = []
    memory_pages = 0

    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, offset = read_uleb(data, offset)
        end = offset + size
        name = SECTION_NAMES.get(section_id, f"inconnue({section_id})")
        sections.append((name, size))

        if section_id == 2:
            count, cursor = read_uleb(data, offset)
            for _ in range(count):
                module, cursor = read_name(data, cursor)
                field, cursor = read_name(data, cursor)
                kind = data[cursor]
                cursor += 1
                if kind == 0x00:
                    _, cursor = read_uleb(data, cursor)
                    kind_name = "func"
                elif kind == 0x01:
                    cursor += 1  # reftype
                    flags = data[cursor]
                    cursor += 1
                    _, cursor = read_uleb(data, cursor)
                    if flags & 0x01:
                        _, cursor = read_uleb(data, cursor)
                    kind_name = "table"
                elif kind == 0x02:
                    flags = data[cursor]
                    cursor += 1
                    _, cursor = read_uleb(data, cursor)
                    if flags & 0x01:
                        _, cursor = read_uleb(data, cursor)
                    kind_name = "memory"
                else:
                    cursor += 2
                    kind_name = "global"
                imports.append((module, field, kind_name))

        elif section_id == 5:
            count, cursor = read_uleb(data, offset)
            for _ in range(count):
                flags = data[cursor]
                cursor += 1
                pages, cursor = read_uleb(data, cursor)
                if flags & 0x01:
                    _, cursor = read_uleb(data, cursor)
                memory_pages += pages

        elif section_id == 7:
            count, cursor = read_uleb(data, offset)
            for _ in range(count):
                field, cursor = read_name(data, cursor)
                kind = data[cursor]
                cursor += 1
                _, cursor = read_uleb(data, cursor)
                exports.append((field, {0: "func", 1: "table", 2: "memory", 3: "global"}[kind]))

        offset = end

    return {
        "version": version,
        "size": len(data),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "memory_pages": memory_pages,
    }


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)

    with open(sys.argv[1], "rb") as handle:
        data = handle.read()

    info = parse(data)

    print(f"module     : {sys.argv[1]}")
    print(f"taille     : {info['size']} octets ({info['size'] / 1024:.1f} Kio)")
    print(f"memoire    : {info['memory_pages']} pages ({info['memory_pages'] * 64} Kio)")
    print(f"sections   : {', '.join(f'{n} {s}o' for n, s in info['sections'])}")

    print()
    print(f"imports ({len(info['imports'])}) :")
    by_module: dict[str, list[str]] = {}
    for module, field, kind in info["imports"]:
        by_module.setdefault(module, []).append(f"{field} ({kind})")
    for module, fields in sorted(by_module.items()):
        print(f"  {module} : {len(fields)}")
        for field in sorted(fields):
            print(f"    - {field}")

    print()
    print(f"exports ({len(info['exports'])}) :")
    for field, kind in info["exports"]:
        print(f"  - {field} ({kind})")

    modules = sorted({module for module, _, _ in info["imports"]})
    unexpected_modules = [m for m in modules if m not in {"env", "wasi_snapshot_preview1"}]
    unexpected_wasi = sorted(
        field
        for module, field, _ in info["imports"]
        if module == "wasi_snapshot_preview1" and field not in ALLOWED_WASI
    )

    print()
    if unexpected_modules:
        print(f"REFUS : imports hors de `env` et du WASI attendu : {unexpected_modules}")
        raise SystemExit(1)

    if unexpected_wasi:
        print(f"REFUS : fonctions WASI non attendues : {unexpected_wasi}")
        print("Verifie qu'Envoy les implemente avant de deployer.")
        raise SystemExit(1)

    wasi_used = sorted(
        field for module, field, _ in info["imports"] if module == "wasi_snapshot_preview1"
    )
    print(f"WASI attendu et present : {wasi_used}")
    print("Aucun import hors du sous-ensemble autorise : le module peut se charger.")


if __name__ == "__main__":
    main()
