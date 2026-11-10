# SPDX-License-Identifier: Apache-2.0

CLUSTER   ?= tephra
NAMESPACE ?= tephra
RELEASE   ?= tephra
IMAGE     ?= tephra/tephrad:dev
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

CHART    := deploy/helm/tephra
BPF_SRCS := $(wildcard bpf/*.bpf.c) bpf/common.h
SCRIPTS  := $(wildcard hack/*.sh deploy/vm/*.sh)

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

.PHONY: build
build: generate ## Build bin/tephrad
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/tephrad ./cmd/tephrad

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
	shellcheck $(SCRIPTS)

.PHONY: fmt
fmt: ## Format Go and C sources
	gofmt -w cmd internal
	clang-format -i $(BPF_SRCS)

.PHONY: image
image: ## Build the agent container image
	docker build -f deploy/docker/tephrad.Dockerfile --build-arg VERSION=$(VERSION) -t $(IMAGE) .

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
dev: kind-up image ## Build, load into kind, install the chart, run the acceptance check
	kind load docker-image $(IMAGE) --name $(CLUSTER)
	helm upgrade --install $(RELEASE) $(CHART) \
		--kube-context kind-$(CLUSTER) \
		--namespace $(NAMESPACE) --create-namespace \
		-f $(CHART)/values-kind.yaml \
		--set-string 'agent.podAnnotations.tephra\.dev/image-id='"$$(docker image inspect -f '{{.Id}}' $(IMAGE))"
	NAMESPACE=$(NAMESPACE) RELEASE=$(RELEASE) hack/accept-m0.sh

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
