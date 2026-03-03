[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z0-9_.-]+$')]
    [string]$Org,

    [Parameter(Mandatory = $false)]
    [string[]]$Repos
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Write-Err {
    param([string]$Message)
    [Console]::Error.WriteLine("[ERROR] $Message")
}

function Get-GhCommand {
    $cmd = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $cmd = Get-Command gh.exe -ErrorAction SilentlyContinue
    }
    if (-not $cmd) {
        throw "GitHub CLI ('gh' or 'gh.exe') is not available in PATH."
    }
    return $cmd.Source
}

function Test-RepoSlug {
    param([string]$Value)
    return [bool]($Value -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
}

function Get-RepoFromOrigin {
    $remote = (& git config --get remote.origin.url 2>$null | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($remote)) {
        throw "Could not read git remote origin URL in single-repo mode."
    }

    $repo = $null
    if ($remote -match '^git@github\.com:(.+?)(?:\.git)?$') {
        $repo = $Matches[1]
    }
    elseif ($remote -match '^https://github\.com/(.+?)(?:\.git)?$') {
        $repo = $Matches[1]
    }
    elseif ($remote -match '^ssh://git@github\.com/(.+?)(?:\.git)?$') {
        $repo = $Matches[1]
    }
    else {
        throw "Unsupported remote origin URL: $remote"
    }

    if (-not (Test-RepoSlug -Value $repo)) {
        throw "Invalid repository slug parsed from origin: $repo"
    }
    return $repo
}

function Normalize-RepoInput {
    param(
        [string]$Value,
        [string]$OrgName
    )

    $normalized = if ($Value.Contains("/")) { $Value } else { "$OrgName/$Value" }
    if (-not (Test-RepoSlug -Value $normalized)) {
        throw "Invalid repository value: $Value"
    }
    return $normalized
}

function Invoke-GhApi {
    param(
        [string[]]$Arguments,
        [string]$InputJson
    )

    if ($PSBoundParameters.ContainsKey("InputJson")) {
        $tempFile = New-TemporaryFile
        try {
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($tempFile.FullName, $InputJson, $utf8NoBom)
            $output = & $script:GhCmd api @Arguments -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" --input $tempFile.FullName 2>&1
        }
        finally {
            Remove-Item -Path $tempFile.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        $output = & $script:GhCmd api @Arguments -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        throw "gh api call failed: $($Arguments -join ' ') $output"
    }
    return $output
}

function Test-BranchExists {
    param(
        [string]$RepoSlug,
        [string]$BranchName
    )

    & $script:GhCmd api "repos/$RepoSlug/branches/$BranchName" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" *> $null
    return ($LASTEXITCODE -eq 0)
}

function Ensure-BranchExists {
    param(
        [string]$RepoSlug,
        [string]$BranchName
    )

    if (Test-BranchExists -RepoSlug $RepoSlug -BranchName $BranchName) {
        Write-Info "${RepoSlug}: branch '$BranchName' already exists."
        return
    }

    $mainSha = (& $script:GhCmd api "repos/$RepoSlug/branches/main" --jq ".commit.sha" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($mainSha)) {
        throw "${RepoSlug}: could not resolve main branch SHA. Ensure 'main' exists."
    }

    & $script:GhCmd api -X POST "repos/$RepoSlug/git/refs" -f "ref=refs/heads/$BranchName" -f "sha=$mainSha" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" *> $null
    if ($LASTEXITCODE -ne 0 -and -not (Test-BranchExists -RepoSlug $RepoSlug -BranchName $BranchName)) {
        throw "${RepoSlug}: failed to create branch '$BranchName'."
    }

    Write-Info "${RepoSlug}: created branch '$BranchName' from 'main'."
}

function New-MainProtectionPayload {
    return @{
        required_status_checks = @{
            strict   = $true
            contexts = @("ci", "branch-policy")
        }
        enforce_admins                   = $true
        required_pull_request_reviews    = @{
            dismiss_stale_reviews           = $true
            required_approving_review_count = 1
        }
        restrictions                    = $null
        required_conversation_resolution = $true
        allow_force_pushes               = $false
        allow_deletions                  = $false
    }
}

function New-StagingProtectionPayload {
    return @{
        required_status_checks = @{
            strict   = $true
            contexts = @("ci", "branch-policy")
        }
        enforce_admins                   = $true
        required_pull_request_reviews    = @{
            dismiss_stale_reviews           = $true
            required_approving_review_count = 0
        }
        restrictions                    = $null
        required_conversation_resolution = $true
        allow_force_pushes               = $false
        allow_deletions                  = $false
    }
}

function New-CiCdProtectionPayload {
    return @{
        required_status_checks = @{
            strict   = $false
            contexts = @("ci")
        }
        enforce_admins                   = $true
        required_pull_request_reviews    = $null
        restrictions                    = $null
        required_conversation_resolution = $false
        allow_force_pushes               = $false
        allow_deletions                  = $false
    }
}

function Set-BranchProtection {
    param(
        [string]$RepoSlug,
        [string]$BranchName,
        [hashtable]$Payload
    )

    $json = $Payload | ConvertTo-Json -Depth 10 -Compress
    Invoke-GhApi -Arguments @("--method", "PUT", "repos/$RepoSlug/branches/$BranchName/protection") -InputJson $json | Out-Null
}

function Configure-Repository {
    param([string]$RepoSlug)

    if (-not (Test-RepoSlug -Value $RepoSlug)) {
        throw "Invalid repository slug: $RepoSlug"
    }

    Write-Info "Configuring branch protections for $RepoSlug"

    $mainSha = (& $script:GhCmd api "repos/$RepoSlug/branches/main" --jq ".commit.sha" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($mainSha)) {
        throw "${RepoSlug}: branch 'main' not found."
    }

    Ensure-BranchExists -RepoSlug $RepoSlug -BranchName "staging"
    Ensure-BranchExists -RepoSlug $RepoSlug -BranchName "ci-cd"

    Set-BranchProtection -RepoSlug $RepoSlug -BranchName "main" -Payload (New-MainProtectionPayload)
    Set-BranchProtection -RepoSlug $RepoSlug -BranchName "staging" -Payload (New-StagingProtectionPayload)
    Set-BranchProtection -RepoSlug $RepoSlug -BranchName "ci-cd" -Payload (New-CiCdProtectionPayload)

    Write-Info "${RepoSlug}: protections updated for main, staging, ci-cd."
}

$script:GhCmd = Get-GhCommand

& $script:GhCmd auth status *> $null
if ($LASTEXITCODE -ne 0) {
    throw "gh is not authenticated. Run 'gh auth login' or set GH_TOKEN."
}

$repoTargets = @()
if ([string]::IsNullOrWhiteSpace($Org)) {
    if ($Repos -and $Repos.Count -gt 0) {
        throw "-Repos can only be used with -Org."
    }
    $repoTargets = @(Get-RepoFromOrigin)
}
else {
    if ($Repos -and $Repos.Count -gt 0) {
        foreach ($repo in $Repos) {
            if ([string]::IsNullOrWhiteSpace($repo)) {
                continue
            }
            $repoTargets += Normalize-RepoInput -Value $repo.Trim() -OrgName $Org
        }
    }
    else {
        $discoveredRepos = & $script:GhCmd repo list $Org --json name,isArchived --limit 500 --jq ".[] | select(.isArchived == false) | .name" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to discover repositories for org '$Org': $discoveredRepos"
        }
        foreach ($name in $discoveredRepos) {
            $trimmed = "$name".Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                $repoTargets += Normalize-RepoInput -Value $trimmed -OrgName $Org
            }
        }
    }
}

if (-not $repoTargets -or $repoTargets.Count -eq 0) {
    throw "No repositories selected."
}

$failures = @()
foreach ($repoSlug in $repoTargets) {
    try {
        Configure-Repository -RepoSlug $repoSlug
    }
    catch {
        Write-Err "$repoSlug failed: $($_.Exception.Message)"
        $failures += $repoSlug
    }
}

if ($failures.Count -gt 0) {
    Write-Err "Completed with $($failures.Count) failure(s)."
    exit 1
}

Write-Info "Completed successfully for $($repoTargets.Count) repo(s)."
exit 0
