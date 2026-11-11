# SPDX-License-Identifier: Apache-2.0
# Build context is the repository root.

FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api/ api/
COPY cmd/collector/ cmd/collector/
COPY internal/ internal/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/collector ./cmd/collector

# The collector needs no privilege at all: the non-root variant.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/collector /collector
ENTRYPOINT ["/collector"]
