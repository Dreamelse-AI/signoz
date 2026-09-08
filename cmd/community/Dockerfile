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
RUN GOOS=linux GOARCH=amd64 go build -C ./cmd/community -tags timetzdata \
	-o /src/target/linux-amd64/signoz-community -ldflags "-s -w"

FROM node:22-alpine AS web
RUN corepack enable
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
# CI: allow chokidar@4.0.3 past the no-downgrade trust policy (repo policy flags it,
# lockfile is pinned and audited). Build-script approvals are granted the same way.
RUN pnpm config set trustPolicyExclude --location project 'chokidar@4.0.3' && \
	pnpm config set dangerouslyAllowAllBuilds true --location project
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