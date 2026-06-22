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
ARG RUSTUP_VERSION=1.29.0
ARG RUSTUP_CHECKSUM_AMD64=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
ARG RUSTUP_CHECKSUM_ARM64=9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792
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

# Stage: Download and verify claude-code npm package
FROM node:24@sha256:bb20cf73b3ad7212834ec48e2174cdcb5775f6550510a5336b842ae32741ce6c AS claude-code-npm
ARG CLAUDE_CODE_VERSION
ARG CLAUDE_CODE_SHA512
RUN npm pack @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} --pack-destination /tmp \
    && echo "${CLAUDE_CODE_SHA512}  /tmp/anthropic-ai-claude-code-${CLAUDE_CODE_VERSION}.tgz" | sha512sum -c

# Base stage for VS Code extension downloads — provides the download-vsix.sh helper.
FROM downloader AS vscode-downloader
COPY download-vsix.sh /usr/local/bin/download-vsix.sh
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

# Main stage
FROM node:24@sha256:bb20cf73b3ad7212834ec48e2174cdcb5775f6550510a5336b842ae32741ce6c

ARG TZ
ENV TZ="$TZ"

# Set the locale
ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

ARG CLAUDE_CODE_VERSION

# Install basic development tools and iptables/ipset
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --no-install-recommends \
  less \
  git \
  procps \
  sudo \
  fzf \
  zsh \
  man-db \
  unzip \
  gnupg2 \
  gh \
  iptables \
  nftables \
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

# Ensure default node user has access to /usr/local/share
RUN mkdir -p /usr/local/share/npm-global && \
  chown -R node:node /usr/local/share

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
COPY --chown=node:node node-zshrc /home/node/.zshrc

# Install Claude Code from SHA-verified npm tarball
COPY --chown=node:node --from=claude-code-npm /tmp/anthropic-ai-claude-code-${CLAUDE_CODE_VERSION}.tgz /tmp/
RUN npm install -g /tmp/anthropic-ai-claude-code-${CLAUDE_CODE_VERSION}.tgz \
    && rm /tmp/anthropic-ai-claude-code-${CLAUDE_CODE_VERSION}.tgz

# Copy and set up the castellan firewall scripts. The `castellan` binary itself is built
# from the workspace crate at postCreate and installed to /usr/local/bin by init-firewall.sh.
USER root
COPY init-firewall.sh castellan-supervisor.sh /usr/local/bin/
RUN mkdir -p /usr/local/share/castellan
COPY allowed-domains.txt /usr/local/share/castellan/allowed-domains.txt
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/castellan-supervisor.sh && \
  echo "node ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" > /etc/sudoers.d/node-firewall && \
  chmod 0440 /etc/sudoers.d/node-firewall

# VS Code extensions (baked in for version pinning; installed at folderOpen via .vscode/tasks.json)
RUN mkdir -p /opt/vscode-extensions
COPY --from=vscode-ext-claude-code      /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-rust-analyzer    /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-even-better-toml /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-codelldb         /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-dependi          /opt/ext /opt/vscode-extensions/
COPY --from=vscode-ext-gitlens          /opt/ext /opt/vscode-extensions/

USER node
