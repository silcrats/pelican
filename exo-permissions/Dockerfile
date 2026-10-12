# Exchange Online permission exporter: PowerShell 7 + the Exchange Online module.
# Kept separate from the crawler image so PowerShell (large) isn't in every crawler.
FROM ubuntu:24.10

# PowerShell from its GitHub release, checked against the SHA-256 published in
# the release notes. Not mcr.microsoft.com/powershell: those images are no
# longer updated (its :latest is 7.4.2, from 2024). To upgrade, change both.
ARG PWSH_VERSION=7.6.6
ARG PWSH_SHA256=9585f38ab5a026c3fc0995486e26e12050777960fef47a22dca98b577c5d27a7
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL -o /tmp/powershell.deb \
       "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell_${PWSH_VERSION}-1.deb_amd64.deb" \
    && echo "${PWSH_SHA256}  /tmp/powershell.deb" | sha256sum -c - \
    && apt-get install -y --no-install-recommends /tmp/powershell.deb \
    && rm /tmp/powershell.deb \
    && rm -rf /var/lib/apt/lists/*

# ExchangeOnlineManagement 3.10.0+ needs PowerShell 7.6+ (.NET 10); 3.5.0-3.9.2 need
# only 7.4+. Pinned so a module release can't change behaviour unannounced --
# unpinned, a module newer than the image's PowerShell fails with "The given
# assembly name was invalid". 3.10.x is an option now that this is 7.6.
RUN pwsh -NoProfile -Command " \
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module ExchangeOnlineManagement -RequiredVersion 3.9.2 -Scope AllUsers -Force; \
    Install-Module powershell-yaml -RequiredVersion 0.4.12 -Scope AllUsers -Force"

WORKDIR /app
COPY export-mailbox-permissions.ps1 .

# Runs as an unprivileged user (same UID as the other Pelican images). /perm is
# created here so a new volume comes up writable by it.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin pelican \
    && mkdir -p /perm && chown pelican:pelican /perm
USER pelican

# One-shot: exports the permissions file and exits. Scheduled by ofelia.
ENTRYPOINT ["pwsh", "-NoProfile", "-File", "/app/export-mailbox-permissions.ps1"]
