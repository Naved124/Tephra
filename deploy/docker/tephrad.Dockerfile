# SPDX-License-Identifier: Apache-2.0
# Build context is the repository root.

FROM golang:1.27.3 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY internal/ internal/
ARG VERSION=dev
RUN go generate ./... \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/tephrad ./cmd/tephrad

# The agent needs root for BPF, so this is the root variant of distroless.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/tephrad /tephrad
ENTRYPOINT ["/tephrad"]
