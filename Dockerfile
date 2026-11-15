FROM python:3.12-slim

ARG TARGETARCH=amd64
ARG PIKPAK_CLI_VERSION=v0.6.0
ARG PIKPAK_SHA256_AMD64=59fcbf237bb6523d96a1470a703ae55a2ec97adbd7ec7fc04b99a20112597495
ARG PIKPAK_SHA256_ARM64=3c1edae39d884eeb67a8a9a8cddd6687632c8c898cae8151cd0ffcb9affd52fb

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && case "${TARGETARCH}" in \
         amd64) EXPECTED_SHA="${PIKPAK_SHA256_AMD64}" ;; \
         arm64) EXPECTED_SHA="${PIKPAK_SHA256_ARM64}" ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://download.mypikpak.com/cli/release/${PIKPAK_CLI_VERSION}/pikpak_linux_${TARGETARCH}" -o /usr/local/bin/pikpak \
    && echo "${EXPECTED_SHA}  /usr/local/bin/pikpak" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/pikpak \
    && groupadd --gid 101 yunbot \
    && useradd --uid 101 --gid 101 --home-dir /app/data --no-create-home --shell /usr/sbin/nologin yunbot \
    && mkdir -p /app /app/data/pikpak /var/tmp/yunbot-uploads \
    && chown -R 101:101 /app /var/tmp/yunbot-uploads \
    && chmod 0700 /app/data /app/data/pikpak

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-deps -r /app/requirements.txt

COPY --chown=101:101 src /app/src

USER 101:101

EXPOSE 8082

CMD ["python3", "-m", "yunbot"]
