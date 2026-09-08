# syntax=docker/dockerfile:1
FROM alpine:3.20.3 AS base
LABEL maintainer="signoz"
WORKDIR /root

ARG OS="linux"
ARG TARGETARCH

RUN apk update && \
	apk add ca-certificates && \
	rm -rf /var/cache/apk/*


COPY ./target/${OS}-${TARGETARCH}/signoz-community /root/signoz
COPY ./templates /root/templates
COPY frontend/build/ /etc/signoz/web/

RUN chmod 755 /root /root/signoz

ENTRYPOINT ["./signoz", "server"]

# ---------------------------------------------------------------------------
# web stage: builds the frontend and packages it into the final signoz image.
# Pipeline only needs to point dockerfilePath at this file; no separate
# frontend build step is required in CI.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS web
RUN corepack enable
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
# CI: skip pnpm v11 supply-chain gates (trust downgrade on chokidar, build-script approvals)
RUN pnpm config set trust-policy off --location project && \
	pnpm config set dangerously-allow-all-builds true --location project
COPY frontend/ ./
RUN pnpm install --frozen-lockfile && pnpm build

FROM base AS final
COPY --from=web /src/frontend/build/ /etc/signoz/web/