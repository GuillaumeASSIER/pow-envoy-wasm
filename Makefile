# Construction et publication du filtre Proxy-WASM pow-proxy.
#
# Le module est bati pour wasm32-wasip1, en mode reacteur (`_initialize`), ce
# qu'Envoy attend d'un module charge par Istio.

SHELL := /bin/bash

TARGET   := wasm32-wasip1
LIBNAME  := pow_proxy
WASM     := target/$(TARGET)/release/$(LIBNAME).wasm
IMAGE    ?= ghcr.io/guillaumeassier/pow-proxy-rust:0.1.0
CARGO    ?= cargo
ORAS     ?= oras

# Deux types de media, imposes par le format que lit Istio :
#   - la couche de configuration, application/vnd.module.wasm.config.v1+json ;
#   - la couche du module, application/vnd.module.wasm.content.layer.v1+wasm.
# Istio exige exactement ces deux couches et cherche le module par son type de
# media. Un seul type de media, ou une couche en plus, et le chargement echoue
# avec « could not parse as oci variant ».
WASM_MEDIA_TYPE   := application/vnd.module.wasm.content.layer.v1+wasm
CONFIG_MEDIA_TYPE := application/vnd.module.wasm.config.v1+json

.DEFAULT_GOAL := help

.PHONY: help fmt lint test vectors wasm-build wasm-oci wasm-publish e2e clean

help:
	@echo "Cibles :"
	@echo "  make test         - tests unitaires et de recoupement, en natif"
	@echo "  make lint         - formatage et Clippy, avertissements bloquants"
	@echo "  make wasm-build   - module wasm + controle des imports + empreinte"
	@echo "  make wasm-oci     - artefact OCI local (build/oci), sans registre"
	@echo "  make wasm-publish - poussee vers le registre ($(IMAGE))"
	@echo "  make e2e          - client Rust contre l'edge de test Python"
	@echo "  make vectors      - regenere les vecteurs de recoupement"
	@echo "  make clean"

## Met en forme le code.
fmt:
	$(CARGO) fmt

## Verifie le formatage et passe Clippy, avertissements bloquants.
lint:
	$(CARGO) fmt --check
	$(CARGO) clippy --all-targets -- -D warnings

## Tests natifs : logique pure, protocole, recoupement avec la reference Python.
test:
	$(CARGO) test
	@python3 tools/gen_vectors.py > /dev/null && echo "vecteurs de reference OK"

## Regenere tests/data/parity_vectors.rs depuis l'implementation de reference.
vectors:
	python3 tools/gen_vectors.py --rust > tests/data/parity_vectors.rs
	@echo "vecteurs regeneres"

## Construit le module, verifie ses imports, affiche son empreinte.
wasm-build:
	$(CARGO) build --lib --release --target $(TARGET)
	@python3 tools/inspect_wasm.py $(WASM)
	@echo
	@echo "module   : $(WASM)"
	@echo "sha256   : $$(sha256sum $(WASM) | cut -d' ' -f1)"

## Construit un artefact OCI chargeable par Istio, verifiable sans registre.
##
## La couche poussee est le module brut, non compresse : Istio lit le contenu de
## la couche tel quel. Le controle de conformite reproduit les regles de son
## recuperateur.
wasm-oci: wasm-build
	rm -rf build/oci
	mkdir -p build/oci
	cp $(WASM) build/pow-proxy.wasm
	printf '{}' > build/module-config.json
	cd build && $(ORAS) push --oci-layout-path oci $(IMAGE) \
		module-config.json:$(CONFIG_MEDIA_TYPE) \
		pow-proxy.wasm:$(WASM_MEDIA_TYPE)
	@echo
	@cd build && $(ORAS) manifest fetch --oci-layout-path oci $(IMAGE) | python3 ../tools/check_oci_manifest.py

## Pousse l'artefact vers le registre. Identifiants requis : oras login.
wasm-publish: wasm-build
	mkdir -p build
	cp $(WASM) build/pow-proxy.wasm
	printf '{}' > build/module-config.json
	cd build && $(ORAS) push $(IMAGE) \
		module-config.json:$(CONFIG_MEDIA_TYPE) \
		pow-proxy.wasm:$(WASM_MEDIA_TYPE)
	@echo "pousse : $(IMAGE)"

## Verifie le client Rust contre l'implementation de reference Python, sur sockets.
e2e:
	@mkdir -p build
	@python3 tools/fake_edge.py --port 18081 & echo $$! > build/fake-edge.pid; \
	 sleep 1.5; \
	 status=0; \
	 $(CARGO) run --quiet --release --bin powcli -- --url http://127.0.0.1:18081/protege || status=$$?; \
	 kill $$(cat build/fake-edge.pid) 2>/dev/null; \
	 rm -f build/fake-edge.pid; \
	 exit $$status

clean:
	$(CARGO) clean
	rm -rf build
