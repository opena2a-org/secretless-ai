# VHS 0.12.0 with the encode-context regression patched (evaluator.go renders with the
# cancelled recording context, so ffmpeg never starts and the error is swallowed).
# The patch is the committed file next to this Dockerfile; its sha256 goes into the sidecar.
FROM golang:1.26-trixie AS vhsbuild
ENV GOTOOLCHAIN=auto
COPY vhs-0.12.0-render-context.patch /tmp/vhs-0.12.0-render-context.patch
RUN git clone --depth 1 --branch v0.12.0 https://github.com/charmbracelet/vhs /src \
 && cd /src \
 && git apply /tmp/vhs-0.12.0-render-context.patch \
 && grep -n "v.Render(context.Background())" evaluator.go \
 && CGO_ENABLED=0 go build -ldflags "-X main.Version=v0.12.0+render-context-patch" -o /vhs .

FROM node:22.20.0-trixie-slim AS node

FROM ghcr.io/charmbracelet/vhs:latest
COPY --from=vhsbuild /vhs /usr/bin/vhs
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates gifsicle >/dev/null \
 && node --version && npm --version && which gifsicle
# The build under recording. TARBALL names an `npm pack` file beside this Dockerfile in the build
# context; when it is empty the published TOOL@VERSION is installed. Either way the installed build
# must report VERSION. The Dockerfile is copied too so the COPY matches when no tarball is present.
ARG TOOL=secretless-ai
ARG VERSION
ARG TARBALL=
COPY Dockerfile *.tgz /pkg/
RUN if [ -n "$TARBALL" ]; then npm install -g "/pkg/$TARBALL"; else npm install -g "$TOOL@$VERSION"; fi \
 && "$TOOL" --version | grep -F "$VERSION"
ENV OPENA2A_TELEMETRY=off
ENV npm_config_update_notifier=false
ENV npm_config_yes=true
WORKDIR /work
ENTRYPOINT ["vhs"]
