# Exchange Online permission exporter: PowerShell 7 + the Exchange Online module.
# Kept separate from the crawler image so PowerShell (large) isn't in every crawler.
FROM mcr.microsoft.com/powershell:latest

# ExchangeOnlineManagement 3.10.0+ needs PowerShell 7.6+ (.NET 10); 3.5.0-3.9.2 need
# only 7.4+. Pinned so the module always loads on whatever PowerShell this image
# has -- unpinned, "latest" module + older image fails with "The given assembly
# name was invalid". To move to 3.10.x, also move the base image to PowerShell 7.6+.
RUN pwsh -NoProfile -Command " \
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module ExchangeOnlineManagement -RequiredVersion 3.9.2 -Scope AllUsers -Force; \
    Install-Module powershell-yaml -Scope AllUsers -Force"

WORKDIR /app
COPY export-mailbox-permissions.ps1 .

# One-shot: exports the permissions file and exits. Scheduled by ofelia.
ENTRYPOINT ["pwsh", "-NoProfile", "-File", "/app/export-mailbox-permissions.ps1"]
