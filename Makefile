# SPDX-License-Identifier: Apache-2.0

CLUSTER   ?= tephra
NAMESPACE ?= tephra
RELEASE   ?= tephra
IMAGE     ?= tephra/tephrad:dev
COLLECTOR_IMAGE ?= tephra/collector:dev
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

CHART    := deploy/helm/tephra
BPF_SRCS := $(wildcard bpf/*.bpf.c) bpf/common.h
SCRIPTS  := $(wildcard hack/*.sh deploy/vm/*.sh attacks/*/*.sh)

.DEFAULT_GOAL := build

.PHONY: help
help: ## List targets
	@grep -hE '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

# --- build ------------------------------------------------------------------

.PHONY: vmlinux
vmlinux: ## Regenerate bpf/vmlinux.h from the running kernel's BTF
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

.PHONY: generate
generate: ## Compile the BPF programs and generate their Go bindings (bpf2go)
	go generate ./...

# protoc is fetched at a pinned version and checked against a pinned digest.
# The digest is the one the release itself publishes (the "digest" field of
# the asset in the GitHub releases API), not one taken from a first download.
# The two Go plugins are pinned by go.mod (tool directives) and go.sum.
# The generated Go code is committed, so only changing the .proto needs this.
PROTOC_VERSION := 36.2
PROTOC_SHA256  := 121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278
PROTOC         := .tools/protoc/bin/protoc

$(PROTOC):
	mkdir -p .tools
	curl -fsSL -o .tools/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-linux-x86_64.zip
	echo "$(PROTOC_SHA256)  .tools/protoc.zip" | sha256sum -c -
	rm -rf .tools/protoc && mkdir .tools/protoc
	python3 -m zipfile -e .tools/protoc.zip .tools/protoc
	chmod +x $(PROTOC)

.PHONY: proto
proto: $(PROTOC) ## Regenerate the Go code of the agent-to-collector API
	GOBIN=$(CURDIR)/.tools/bin go install google.golang.org/protobuf/cmd/protoc-gen-go google.golang.org/grpc/cmd/protoc-gen-go-grpc
	PATH=$(CURDIR)/.tools/bin:$$PATH $(PROTOC) \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/tephra/v1/tephra.proto

.PHONY: build
build: generate ## Build bin/tephrad, bin/collector and bin/harness
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/tephrad ./cmd/tephrad
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/collector ./cmd/collector
	CGO_ENABLED=0 go build -trimpath -o bin/harness ./cmd/harness

.PHONY: rules-validate
rules-validate: generate ## Check every shipped rule
	go run ./cmd/tephrad rules validate rules

.PHONY: test
test: generate ## Unit tests (unprivileged)
	go test ./...

.PHONY: test-root
test-root: generate ## Tests that load BPF into the running kernel; run in the dev VM only
	go test -c -o bin/loader.test ./internal/loader
	sudo ./bin/loader.test -test.v

.PHONY: lint
lint: generate ## Go, C and shell lint
	go vet ./...
	golangci-lint run
	clang-format --dry-run --Werror $(BPF_SRCS)
	shellcheck -x $(SCRIPTS)

.PHONY: fmt
fmt: ## Format Go and C sources
	gofmt -w cmd internal
	clang-format -i $(BPF_SRCS)

.PHONY: image
image: ## Build the agent and collector container images
	docker build -f deploy/docker/tephrad.Dockerfile --build-arg VERSION=$(VERSION) -t $(IMAGE) .
	docker build -f deploy/docker/collector.Dockerfile --build-arg VERSION=$(VERSION) -t $(COLLECTOR_IMAGE) .

# --- lab cluster (run inside the dev VM) --------------------------------------

.PHONY: kind-up
kind-up: ## Create the kind lab cluster if it does not exist
	@if kind get clusters 2>/dev/null | grep -qx $(CLUSTER); then \
		echo "kind cluster $(CLUSTER) already exists"; \
	else \
		kind create cluster --name $(CLUSTER) --config deploy/kind/cluster.yaml --wait 120s; \
	fi

.PHONY: kind-down
kind-down: ## Delete the kind lab cluster
	kind delete cluster --name $(CLUSTER)

# The image ID goes into a pod annotation so that a rebuilt image under the
# same tag still rolls the DaemonSet.
.PHONY: dev
dev: kind-up image ## Build, load into kind, install the chart, run the acceptance tests
	kind load docker-image $(IMAGE) $(COLLECTOR_IMAGE) --name $(CLUSTER)
	helm upgrade --install $(RELEASE) $(CHART) \
		--kube-context kind-$(CLUSTER) \
		--namespace $(NAMESPACE) --create-namespace \
		-f $(CHART)/values-kind.yaml \
		--set-string 'agent.podAnnotations.tephra\.dev/image-id='"$$(docker image inspect -f '{{.Id}}' $(IMAGE))" \
		--set-string 'collector.podAnnotations.tephra\.dev/image-id='"$$(docker image inspect -f '{{.Id}}' $(COLLECTOR_IMAGE))"
	$(MAKE) accept

.PHONY: accept
accept: ## Run the acceptance tests of every finished milestone against the cluster
	@# Fresh agents: the checks read start-up log lines and counters, and a
	@# busy agent's log rotates.
	kubectl -n $(NAMESPACE) rollout restart daemonset/$(RELEASE)-agent
	NAMESPACE=$(NAMESPACE) RELEASE=$(RELEASE) hack/accept-m0.sh
	NAMESPACE=$(NAMESPACE) RELEASE=$(RELEASE) hack/accept-m1.sh
	NAMESPACE=$(NAMESPACE) RELEASE=$(RELEASE) hack/accept-m2.sh
	NAMESPACE=$(NAMESPACE) RELEASE=$(RELEASE) hack/accept-m3.sh
	NAMESPACE=$(NAMESPACE) RELEASE=$(RELEASE) hack/accept-m4.sh
	NAMESPACE=$(NAMESPACE) RELEASE=$(RELEASE) hack/accept-m5.sh
	NAMESPACE=$(NAMESPACE) RELEASE=$(RELEASE) hack/accept-m6.sh

# --- attack harness (lab cluster only) ----------------------------------------

.PHONY: coverage
coverage: build ## Run every attack scenario against the lab cluster and write docs/coverage.md
	bin/harness run --all --context kind-$(CLUSTER) --record rules/testdata

.PHONY: false-positives
false-positives: build ## Run ordinary workloads for 30 minutes and list every alert
	bin/harness fp --context kind-$(CLUSTER)

# --- dev VM (run on the laptop) ---------------------------------------------

.PHONY: vm-up vm-sync vm-ssh vm-down vm-destroy
vm-up: ## Create (or start) and provision the dev VM
	deploy/vm/vm.sh up
vm-sync: ## Copy the working tree into the VM
	deploy/vm/vm.sh sync
vm-ssh: ## Open a shell in the VM
	deploy/vm/vm.sh ssh
vm-down: ## Shut the VM down, keeping its disk
	deploy/vm/vm.sh down
vm-destroy: ## Delete the VM and its disk
	deploy/vm/vm.sh destroy
