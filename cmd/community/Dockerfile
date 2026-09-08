# syntax=docker/dockerfile:1
# Final image is the `final` target; build with:
#   docker build -f cmd/community/Dockerfile --target final .
# The `base` stage is kept for reference/local builds where frontend/build
# already exists (it is NOT buildable via CI - the pipeline selects --target final).

FROM node:22-alpine AS web
RUN corepack enable
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
# CI: skip pnpm v11 supply-chain gates (trust downgrade on chokidar, build-script approvals)
RUN pnpm config set trust-policy off --location project && \
	pnpm config set dangerously-allow-all-builds true --location project
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


COPY ./target/${OS}-${TARGETARCH}/signoz-community /root/signoz
COPY ./templates /root/templates
COPY --from=web /src/frontend/build/ /etc/signoz/web/

RUN chmod 755 /root /root/signoz

ENTRYPOINT ["./signoz", "server"]

# ---------------------------------------------------------------------------
# `base` stage: legacy single-stage variant. Only usable when frontend/build
# already exists in the build context. The `final` target above is what CI
# builds; it compiles the frontend itself in the `web` stage.
# ---------------------------------------------------------------------------
FROM alpine:3.20.3 AS base
COPY frontend/build/ /etc/signoz/web/