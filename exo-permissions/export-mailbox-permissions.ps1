# Exports who has Full Access to each mailbox in exchange.yaml, so the crawler can
# give those people search access to that mailbox's mail (see full_access_roles()
# in crawl_exchange.py).
#
# Runs as a one-shot container (exo-permissions) on a schedule. It only
# READS from Exchange Online, using the same Entra app as the mail crawler but
# signing in with a certificate (Exchange Online does not accept client secrets).
#
# Output (JSON, written atomically): for each mailbox `name` in exchange.yaml,
#   principals  - the mailbox owner (user mailboxes) plus everyone with a direct,
#                 non-denied FullAccess grant, as {kind: user|group, object_id,
#                 address, display, type}. object_id is the Entra object id.
#   unresolved  - grants that could not be identified as a user or group
#   error       - set if this mailbox could not be read (crawler then keeps its
#                 last known roles rather than widening or wiping access)
#
# This job deliberately does NOT work out the the search UI username: Exchange Online's
# SamAccountName is a generated placeholder ("$4VCE41-..."), not the AD username.
# The crawler maps each object_id to the real AD name through Entra (Microsoft
# Graph onPremisesSamAccountName / onPremisesDistinguishedName).

#Requires -Version 7
$ErrorActionPreference = 'Stop'

function Get-RequiredEnv([string]$Name) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Missing/empty environment variable: $Name"
    }
    return $value.Trim()
}

$configPath = $env:EXCHANGE_CONFIG ?? '/app/exchange.yaml'
$appId      = Get-RequiredEnv 'GRAPH_CLIENT_ID'
$org        = Get-RequiredEnv 'EXO_ORGANIZATION'     # the tenant's .onmicrosoft.com domain
$certPath   = Get-RequiredEnv 'EXO_CERT_PATH'
$certPass   = Get-RequiredEnv 'EXO_CERT_PASSWORD'

if (-not (Test-Path -LiteralPath $certPath -PathType Leaf)) {
    throw "Certificate file not found at $certPath (if it exists as a FOLDER, Docker created it because ./secrets/exo.pfx was missing on the host when the container started -- delete that folder and put the real .pfx file there)"
}

$exoVersion = (Get-Module ExchangeOnlineManagement -ListAvailable | Select-Object -First 1).Version
Write-Host "PowerShell $($PSVersionTable.PSVersion), ExchangeOnlineManagement $exoVersion"

Import-Module powershell-yaml
$config = ConvertFrom-Yaml (Get-Content -Raw -Path $configPath)
$outPath = $env:EXCHANGE_PERMISSIONS_FILE
if ([string]::IsNullOrWhiteSpace($outPath)) { $outPath = $config['permissions_file'] }
if ([string]::IsNullOrWhiteSpace($outPath)) { $outPath = '/perm/exchange-permissions.json' }
$mailboxes = @($config['mailboxes'])

Write-Host "Connecting to Exchange Online ($org) as app $appId ..."
Connect-ExchangeOnline `
    -CertificateFilePath $certPath `
    -CertificatePassword (ConvertTo-SecureString $certPass -AsPlainText -Force) `
    -AppID $appId `
    -Organization $org `
    -CommandName 'Get-MailboxPermission', 'Get-Recipient' `
    -SkipLoadingFormatData `
    -ShowBanner:$false

# Cache of principal lookups (the same admin group is often granted on many mailboxes).
$recipientCache = @{}

function Resolve-Principal([string]$Identity) {
    if ($recipientCache.ContainsKey($Identity)) { return $recipientCache[$Identity] }
    $result = $null
    try {
        $r = Get-Recipient -Identity $Identity -ErrorAction Stop
        $type = [string]$r.RecipientTypeDetails
        $kind = if ($type -match 'Group') { 'group' } else { 'user' }
        $objectId = [string]$r.ExternalDirectoryObjectId
        if (-not [string]::IsNullOrWhiteSpace($objectId)) {
            $result = [ordered]@{
                kind      = $kind
                object_id = $objectId
                address   = [string]$r.PrimarySmtpAddress
                display   = [string]$r.DisplayName
                type      = $type
            }
        }
    } catch {
        $result = $null
    }
    $recipientCache[$Identity] = $result
    return $result
}

$results = [ordered]@{}

foreach ($mb in $mailboxes) {
    $name = [string]$mb['name']
    $upn  = [string]$mb['user']
    Write-Host "Mailbox '$name' ($upn)"

    $principals = [System.Collections.Generic.List[object]]::new()
    $unresolved = [System.Collections.Generic.List[string]]::new()
    $seen       = [System.Collections.Generic.HashSet[string]]::new()
    $error_msg  = $null

    try {
        # The mailbox owner (only meaningful for real user mailboxes, not shared/room).
        $owner = Resolve-Principal $upn
        if ($owner -and $owner.type -eq 'UserMailbox' -and $seen.Add("$($owner.kind):$($owner.object_id)")) {
            $principals.Add($owner)
        }

        $grants = Get-MailboxPermission -Identity $upn -ResultSize Unlimited -ErrorAction Stop | Where-Object {
            $rights = @($_.AccessRights | ForEach-Object { $_.ToString() })
            ($rights -contains 'FullAccess') -and (-not $_.IsInherited) -and (-not $_.Deny) -and
            ([string]$_.User -ne 'NT AUTHORITY\SELF')
        }

        foreach ($g in $grants) {
            $identity = [string]$g.User
            if ($identity -like 'S-1-*') { $unresolved.Add($identity); continue }   # deleted account (bare SID)
            $p = Resolve-Principal $identity
            if ($null -eq $p) { $unresolved.Add($identity); continue }
            if ($seen.Add("$($p.kind):$($p.object_id)")) { $principals.Add($p) }
        }
        Write-Host "  $($principals.Count) principal(s), $($unresolved.Count) unresolved"
    } catch {
        $error_msg = $_.Exception.Message
        Write-Warning "  failed: $error_msg"
    }

    $results[$name] = [ordered]@{
        user       = $upn
        principals = $principals.ToArray()
        unresolved = $unresolved.ToArray()
        error      = $error_msg
    }
}

Disconnect-ExchangeOnline -Confirm:$false | Out-Null

$doc = [ordered]@{
    generated_at       = (Get-Date).ToUniversalTime().ToString('o')
    generated_at_epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    mailboxes          = $results
}

$dir = Split-Path -Parent $outPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$tmp = "$outPath.tmp"
$doc | ConvertTo-Json -Depth 8 | Set-Content -Path $tmp -Encoding utf8NoBOM
Move-Item -Path $tmp -Destination $outPath -Force
Write-Host "Wrote $outPath"
