# Common base stage for downloading tools
FROM debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d AS downloader
RUN apt-get update && apt-get install -y --no-install-recommends \
  curl \
  unzip \
  git \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Stage: Download and extract git-delta
FROM downloader AS git-delta
ARG GIT_DELTA_VERSION=0.18.2
ARG GIT_DELTA_CHECKSUM_AMD64=1658c7b61825d411b50734f34016101309e4b6e7f5799944cf8e4ac542cebd7f
ARG GIT_DELTA_CHECKSUM_ARM64=937781aa7788e1510858743fff6c9a8b4a69fe0a22a7c8a69493e633227939a9
RUN ARCH=$(dpkg --print-architecture) && \
  if [ "${ARCH}" = "amd64" ]; then \
    EXPECTED_CHECKSUM="${GIT_DELTA_CHECKSUM_AMD64}"; \
  else \
    EXPECTED_CHECKSUM="${GIT_DELTA_CHECKSUM_ARM64}"; \
  fi && \
  curl -fsSLo /tmp/git-delta.deb "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
  echo "${EXPECTED_CHECKSUM}  /tmp/git-delta.deb" | sha256sum -c - && \
  dpkg-deb -x /tmp/git-delta.deb /opt/delta

# Stage: Download and verify rustup-init
FROM downloader AS rustup
ARG RUSTUP_VERSION=1.29.2
ARG RUSTUP_CHECKSUM_AMD64=5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4
ARG RUSTUP_CHECKSUM_ARM64=a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697
RUN ARCH=$(dpkg --print-architecture) && \
  if [ "${ARCH}" = "amd64" ]; then \
    RUST_ARCH="x86_64-unknown-linux-gnu"; EXPECTED_CHECKSUM="${RUSTUP_CHECKSUM_AMD64}"; \
  else \
    RUST_ARCH="aarch64-unknown-linux-gnu"; EXPECTED_CHECKSUM="${RUSTUP_CHECKSUM_ARM64}"; \
  fi && \
  curl -fsSLo /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUST_ARCH}/rustup-init" && \
  echo "${EXPECTED_CHECKSUM}  /tmp/rustup-init" | sha256sum -c - && \
  mkdir -p /opt/rustup && chmod +x /tmp/rustup-init && mv /tmp/rustup-init /opt/rustup/rustup-init

# Stage: Download oh-my-zsh at pinned commit
FROM downloader AS oh-my-zsh
ARG OHMYZSH_COMMIT=c954bbb168fc645592c50017de0d0e138db8df5f
RUN git init /opt/ohmyzsh \
    && git -C /opt/ohmyzsh remote add origin https://github.com/ohmyzsh/ohmyzsh.git \
    && git -C /opt/ohmyzsh fetch --depth 1 origin ${OHMYZSH_COMMIT} \
    && git -C /opt/ohmyzsh checkout FETCH_HEAD \
    && rm -rf /opt/ohmyzsh/.git

# Stage: Download powerlevel10k at pinned commit (v1.20.0)
FROM downloader AS powerlevel10k
ARG POWERLEVEL10K_COMMIT=35833ea15f14b71dbcebc7e54c104d8d56ca5268
RUN git init /opt/powerlevel10k \
    && git -C /opt/powerlevel10k remote add origin https://github.com/romkatv/powerlevel10k.git \
    && git -C /opt/powerlevel10k fetch --depth 1 origin ${POWERLEVEL10K_COMMIT} \
    && git -C /opt/powerlevel10k checkout FETCH_HEAD \
    && rm -rf /opt/powerlevel10k/.git

# Stage: Download and verify the Claude Code native binary
# This mirrors what https://downloads.claude.ai/claude-code-releases/bootstrap.sh does,
# but pins the version and per-arch checksum instead of following "latest". The base
# image is glibc (Debian), so we use the linux-x64 / linux-arm64 (non-musl) builds.
# Refresh the checksums from the release manifest when bumping the version:
#   curl -fsSL https://downloads.claude.ai/claude-code-releases/${CLAUDE_CODE_VERSION}/manifest.json
FROM downloader AS claude-code
ARG CLAUDE_CODE_VERSION
ARG CLAUDE_CODE_CHECKSUM_AMD64
ARG CLAUDE_CODE_CHECKSUM_ARM64
RUN ARCH=$(dpkg --print-architecture) && \
  if [ "${ARCH}" = "amd64" ]; then \
    PLATFORM="linux-x64"; EXPECTED_CHECKSUM="${CLAUDE_CODE_CHECKSUM_AMD64}"; \
  else \
    PLATFORM="linux-arm64"; EXPECTED_CHECKSUM="${CLAUDE_CODE_CHECKSUM_ARM64}"; \
  fi && \
  curl -fsSLo /tmp/claude \
    "https://downloads.claude.ai/claude-code-releases/${CLAUDE_CODE_VERSION}/${PLATFORM}/claude" && \
  echo "${EXPECTED_CHECKSUM}  /tmp/claude" | sha256sum -c - && \
  mkdir -p /opt/claude && \
  mv /tmp/claude /opt/claude/claude && \
  chmod +x /opt/claude/claude

# Base stage for VS Code extension downloads — provides the download-vsix.sh helper.
FROM downloader AS vscode-downloader
COPY .devcontainer/download-vsix.sh /usr/local/bin/download-vsix.sh
RUN chmod +x /usr/local/bin/download-vsix.sh

# VS Code extension stages — one per extension so each version bump only busts its own cache layer.

# Stage: anthropic.claude-code
FROM vscode-downloader AS vscode-ext-claude-code
ARG CLAUDE_CODE_EXT_VERSION
ARG CLAUDE_CODE_EXT_SHA256
RUN download-vsix.sh anthropic claude-code "${CLAUDE_CODE_EXT_VERSION}" "${CLAUDE_CODE_EXT_SHA256}"

# Stage: rust-lang.rust-analyzer
FROM vscode-downloader AS vscode-ext-rust-analyzer
ARG RUST_ANALYZER_EXT_VERSION
ARG RUST_ANALYZER_EXT_SHA256
RUN download-vsix.sh rust-lang rust-analyzer "${RUST_ANALYZER_EXT_VERSION}" "${RUST_ANALYZER_EXT_SHA256}"

# Stage: tamasfe.even-better-toml
FROM vscode-downloader AS vscode-ext-even-better-toml
ARG EVEN_BETTER_TOML_EXT_VERSION
ARG EVEN_BETTER_TOML_EXT_SHA256
RUN download-vsix.sh tamasfe even-better-toml "${EVEN_BETTER_TOML_EXT_VERSION}" "${EVEN_BETTER_TOML_EXT_SHA256}"

# Stage: vadimcn.vscode-lldb (CodeLLDB)
FROM vscode-downloader AS vscode-ext-codelldb
ARG CODELLDB_EXT_VERSION
ARG CODELLDB_EXT_SHA256
RUN download-vsix.sh vadimcn vscode-lldb "${CODELLDB_EXT_VERSION}" "${CODELLDB_EXT_SHA256}"

# Stage: fill-labs.dependi
FROM vscode-downloader AS vscode-ext-dependi
ARG DEPENDI_EXT_VERSION
ARG DEPENDI_EXT_SHA256
RUN download-vsix.sh fill-labs dependi "${DEPENDI_EXT_VERSION}" "${DEPENDI_EXT_SHA256}"

# Stage: eamodio.gitlens
FROM vscode-downloader AS vscode-ext-gitlens
ARG GITLENS_EXT_VERSION
ARG GITLENS_EXT_SHA256
RUN download-vsix.sh eamodio gitlens "${GITLENS_EXT_VERSION}" "${GITLENS_EXT_SHA256}"

# Stage: build castellan from source (context root = workspace root).
# Uses a minimal toolchain — no clippy/rustfmt needed for the release binary.
FROM debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d AS castellan-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  libc6-dev \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=rustup /opt/rustup/rustup-init /usr/local/bin/rustup-init
ARG RUST_VERSION
ENV RUSTUP_HOME=/usr/local/rustup \
  CARGO_HOME=/usr/local/cargo \
  PATH=/usr/local/cargo/bin:$PATH
RUN rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
  && rm /usr/local/bin/rustup-init
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src/
RUN cargo build --release

# Stage: the egress firewall's own image (the `firewall` and `resolv-init` services in
# docker-compose.yml). Not the last stage: the dev image below is, which is what compose builds
# without a target.
FROM debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d AS firewall
# nftables: castellan runs `nft`. iproute2: `ip route`, for --allow-host-network. curl and
# ca-certificates: `castellan verify`. libcap2-bin: `setcap`, below, and removed again.
RUN apt-get update && apt-get install -y --no-install-recommends \
  nftables \
  iproute2 \
  curl \
  ca-certificates \
  libcap2-bin \
  && rm -rf /var/lib/apt/lists/*
COPY --from=castellan-builder --chown=root:root /build/target/release/castellan /usr/local/bin/castellan
# The user the daemon runs as. A fixed uid, far from the dev container's `node` (1000): the
# firewall's rules name the daemon by uid, and both containers share one network namespace.
RUN groupadd --system --gid 65532 castellan && \
  useradd --system --uid 65532 --gid castellan --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin castellan
# The allow-list is baked in at the path castellan reads by default; edits need an image
# rebuild. Modes are set, not taken from the checkout, where they can be 0666. Everything the
# daemon runs from is root's; only the directory it writes its ready file in is its own.
RUN mkdir -p /usr/local/share/castellan /run/castellan
COPY .devcontainer/allowed-domains.txt /usr/local/share/castellan/allowed-domains.txt
COPY .devcontainer/castellan-supervisor.sh /usr/local/bin/castellan-supervisor.sh
RUN chmod 0644 /usr/local/share/castellan/allowed-domains.txt && \
  chmod 0755 /usr/local/bin/castellan /usr/local/bin/castellan-supervisor.sh && \
  chown castellan:castellan /run/castellan
# The daemon runs as `castellan`, and needs CAP_NET_ADMIN for nft and for nothing else. Docker does
# not give a non-root user a capability it adds with `cap_add`, so the daemon and nft get it from
# the files. Set after the copies above, which would not keep it. The build fails if it is not
# there, and the tool is removed: nothing at run time needs it.
RUN set -eux; \
  NFT="$(readlink -f "$(command -v nft)")"; \
  setcap cap_net_admin=ep /usr/local/bin/castellan; \
  setcap cap_net_admin=ep "$NFT"
# A layer of its own, so this checks what survives being committed to the image, and so the
# log says which of these steps failed.
RUN set -eux; \
  NFT="$(readlink -f "$(command -v nft)")"; \
  caps="$(getcap /usr/local/bin/castellan "$NFT")"; \
  echo "$caps"; \
  [ "$(printf '%s\n' "$caps" | grep -c cap_net_admin)" = 2 ]
RUN set -eux; apt-get purge -y libcap2-bin; rm -rf /var/lib/apt/lists/*
USER castellan
ENTRYPOINT ["/usr/local/bin/castellan-supervisor.sh"]

# Main stage
FROM node:24@sha256:8fa96264f302f58bbb13aa7339c541547b56975766ce956c875da149452a3e40

ARG TZ
ENV TZ="$TZ"

# Set the locale
ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

ARG CLAUDE_CODE_VERSION

# Install basic development tools. No sudo, iptables or nftables: the egress firewall is its own
# container (the `firewall` stage above), and nothing here holds a network capability or can
# become root.
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --no-install-recommends \
  less \
  git \
  procps \
  fzf \
  zsh \
  man-db \
  unzip \
  gnupg2 \
  gh \
  iproute2 \
  dnsutils \
  jq \
  nano \
  vim \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy git-delta binary from build stage
COPY --from=git-delta /opt/delta/usr/bin/delta /usr/local/bin/delta

# Install the Rust toolchain (rustup-init verified in the rustup stage).
# Toolchain lives under /usr/local so the non-root node user can use it; the
# `default` rustup profile bundles rustfmt and clippy.
COPY --from=rustup /opt/rustup/rustup-init /usr/local/bin/rustup-init
ENV RUSTUP_HOME=/usr/local/rustup \
  CARGO_HOME=/usr/local/cargo \
  PATH=/usr/local/cargo/bin:$PATH
ARG RUST_VERSION
RUN rustup-init -y --no-modify-path --profile default --default-toolchain "${RUST_VERSION}" \
  && chmod -R a+w "${RUSTUP_HOME}" "${CARGO_HOME}" \
  && rm /usr/local/bin/rustup-init

# Ensure default node user has access to /usr/local/share/npm-global
RUN mkdir -p /usr/local/share/npm-global && \
  chown -R node:node /usr/local/share/npm-global

ARG USERNAME=node

# Persist bash history.
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
  && mkdir /commandhistory \
  && touch /commandhistory/.bash_history \
  && chown -R $USERNAME /commandhistory

# Set `DEVCONTAINER` environment variable to help with orientation
ENV DEVCONTAINER=true

# Create workspace and config directories and set permissions
RUN mkdir -p /workspace /home/node/.claude && \
  chown -R node:node /workspace /home/node/.claude

WORKDIR /workspace

# Set up non-root user
USER node

# Install global packages
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin

# Set the default shell to zsh rather than sh
ENV SHELL=/bin/zsh

# Set the default editor and visual
ENV EDITOR=nano
ENV VISUAL=nano

# Install oh-my-zsh and powerlevel10k theme from pinned stages
COPY --chown=node:node --from=oh-my-zsh /opt/ohmyzsh /home/node/.oh-my-zsh
COPY --chown=node:node --from=powerlevel10k /opt/powerlevel10k /home/node/.oh-my-zsh/custom/themes/powerlevel10k
COPY --chown=node:node .devcontainer/node-zshrc /home/node/.zshrc

# Install Claude Code from the SHA-verified native binary. It is a single self-contained
# executable, so we drop it straight onto PATH (root-owned, non-writable by node) rather
# than running `claude install`, which would set up a user-writable auto-updating launcher.
COPY --from=claude-code /opt/claude/claude /usr/local/bin/claude

# The egress firewall is not in this image: it is the `firewall` service (the `firewall` stage
# above). This script runs as `postStartCommand`, as `node`, so it is baked in root-owned and not
# run from the workspace.
USER root
COPY .devcontainer/check-firewall.sh /usr/local/bin/check-firewall.sh
RUN chmod 0755 /usr/local/bin/check-firewall.sh

# VS Code extensions (baked in for version pinning; installed at folderOpen via .vscode/tasks.json)
RUN mkdir -p /opt/vscode-extensions
COPY --from=vscode-ext-claude-code      /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-rust-analyzer    /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-even-better-toml /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-codelldb         /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-dependi          /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-gitlens          /opt/ext /opt/vscode-extensions/

USER node
