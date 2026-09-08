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
# Build-script approvals: pnpm v11 only honors `allowBuilds` from
# pnpm-workspace.yaml in non-interactive frozen-lockfile installs — both
# `pnpm config set dangerouslyAllowAllBuilds` and `pnpm approve-builds <pkgs>`
# are ignored on this codepath. Append the approvals to the workspace file.
RUN printf '\nallowBuilds:\n  @parcel/watcher: true\n  @sentry/cli: true\n  core-js: true\n  esbuild: true\n  msw: true\n  unrs-resolver: true\n' >> pnpm-workspace.yaml
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