# syntax=docker/dockerfile:1
# CI builds the `final` target (pipeline passes --target final):
#   web   - node:22 + pnpm builds the frontend into /src/frontend/build
#   go    - golang cross-compiles the community backend into ./target/linux-amd64/
#   final - alpine runtime, backend binary + templates + web assets
# The legacy `base` stage (expects prebuilt frontend/build + target/) is gone:
# `final` supersedes it; build locally with `make go-build-community` + docker
# target final as well.

FROM golang:1.25-alpine AS go
RUN apk add --no-cache git make
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Reproduce the upstream CI ldflags (build-community.yaml / .goreleaser.yaml):
# version metadata + analytics key are injected at build time; the binary
# prints and uses them at startup.
RUN GOOS=linux GOARCH=amd64 go build -C ./cmd/community -tags timetzdata \
	-o /src/target/linux-amd64/signoz-community \
	-ldflags "-s -w \
	-X github.com/SigNoz/signoz/pkg/version.version=dev-$(date -u +%Y%m%d%H%M%S) \
	-X github.com/SigNoz/signoz/pkg/version.variant=community \
	-X github.com/SigNoz/signoz/pkg/version.hash=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) \
	-X github.com/SigNoz/signoz/pkg/version.time=$(git log -1 --format=%ct 2>/dev/null || echo 0) \
	-X github.com/SigNoz/signoz/pkg/version.branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown) \
	-X github.com/SigNoz/signoz/pkg/analytics.key=9kRrJ7oPCGPEJLF6QjMPLt5bljFhRQBr"

FROM node:22-alpine AS web
RUN corepack enable
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
# Build-script approvals are committed in pnpm-workspace.yaml (allowBuilds).
COPY frontend/ ./
RUN pnpm install --frozen-lockfile && pnpm build

FROM alpine:3.20.3 AS final
LABEL maintainer="signoz"
WORKDIR /root

ARG OS="linux"
ARG TARGETARCH

RUN apk update && \
	apk add ca-certificates && \
	rm -rf /var/cache/apk/*


COPY --from=go /src/target/${OS}-${TARGETARCH}/signoz-community /root/signoz
COPY ./templates /root/templates
COPY --from=web /src/frontend/build/ /etc/signoz/web/

RUN chmod 755 /root /root/signoz

ENTRYPOINT ["./signoz", "server"]