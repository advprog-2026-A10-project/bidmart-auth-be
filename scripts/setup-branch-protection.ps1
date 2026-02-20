param(
    [string]$Owner = "",
    [string]$Repo = "",
    [string[]]$Branches = @("main", "staging"),
    [string[]]$RequiredChecks = @("CI / Rust Test + Quality"),
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-CommandExists {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Command '$Name' was not found. Install it and try again."
    }
}

function Resolve-Repository {
    param(
        [string]$OwnerInput,
        [string]$RepoInput
    )

    if ($OwnerInput -and $RepoInput) {
        return @{
            Owner = $OwnerInput
            Repo = $RepoInput
        }
    }

    $nameWithOwner = gh repo view --json nameWithOwner --jq .nameWithOwner
    if (-not $nameWithOwner) {
        throw "Could not resolve owner/repo from current gh context."
    }

    $parts = $nameWithOwner.Trim().Split("/", 2)
    if ($parts.Count -ne 2) {
        throw "Unexpected repository format returned by gh: '$nameWithOwner'"
    }

    return @{
        Owner = $parts[0]
        Repo = $parts[1]
    }
}

$needsGh = (-not $DryRun) -or (-not ($Owner -and $Repo))
if ($needsGh) {
    Assert-CommandExists -Name "gh"
}

$repoRef = Resolve-Repository -OwnerInput $Owner -RepoInput $Repo
$resolvedOwner = $repoRef.Owner
$resolvedRepo = $repoRef.Repo

Write-Host "Configuring branch protection for $resolvedOwner/$resolvedRepo"
Write-Host "Required checks: $($RequiredChecks -join ', ')"

foreach ($branch in $Branches) {
    $payload = @{
        required_status_checks = @{
            strict = $true
            contexts = $RequiredChecks
        }
        enforce_admins = $true
        required_pull_request_reviews = @{
            dismiss_stale_reviews = $true
            require_code_owner_reviews = $false
            required_approving_review_count = 1
        }
        restrictions = $null
        required_linear_history = $true
        allow_force_pushes = $false
        allow_deletions = $false
        block_creations = $false
        required_conversation_resolution = $true
        lock_branch = $false
        allow_fork_syncing = $true
    } | ConvertTo-Json -Depth 10

    if ($DryRun) {
        Write-Host ""
        Write-Host "[DryRun] Branch: $branch"
        Write-Host $payload
        continue
    }

    $payloadFile = New-TemporaryFile
    try {
        Set-Content -Path $payloadFile -Value $payload -NoNewline
        gh api `
            --method PUT `
            -H "Accept: application/vnd.github+json" `
            "repos/$resolvedOwner/$resolvedRepo/branches/$branch/protection" `
            --input $payloadFile | Out-Null
        Write-Host "Applied protection to '$branch'"
    }
    finally {
        Remove-Item -Path $payloadFile -Force -ErrorAction SilentlyContinue
    }
}
