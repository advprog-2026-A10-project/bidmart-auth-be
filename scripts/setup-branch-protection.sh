#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/setup-branch-protection.sh
  ./scripts/setup-branch-protection.sh --org ORG [--repos repo1 repo2 ...]

Modes:
  - Single-repo mode: no --org. Detects owner/repo from git remote origin.
  - Org-wide mode: --org ORG. If --repos is omitted, auto-discovers up to 500 non-archived repos.

Examples:
  ./scripts/setup-branch-protection.sh
  ./scripts/setup-branch-protection.sh --org bidmart
  ./scripts/setup-branch-protection.sh --org bidmart --repos bidmart-core-be bidmart-web-fe
EOF
}

log_info() {
  printf '[INFO] %s\n' "$*"
}

log_error() {
  printf '[ERROR] %s\n' "$*" >&2
}

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Required command not found: $cmd"
    exit 127
  fi
}

validate_org_name() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9_.-]+$ ]]
}

validate_repo_slug() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]
}

parse_origin_repo_slug() {
  local remote_url="$1"
  local repo_slug

  case "$remote_url" in
    git@github.com:*)
      repo_slug="${remote_url#git@github.com:}"
      ;;
    https://github.com/*)
      repo_slug="${remote_url#https://github.com/}"
      ;;
    ssh://git@github.com/*)
      repo_slug="${remote_url#ssh://git@github.com/}"
      ;;
    *)
      log_error "Unsupported remote origin URL: $remote_url"
      return 1
      ;;
  esac

  repo_slug="${repo_slug%.git}"
  if ! validate_repo_slug "$repo_slug"; then
    log_error "Invalid repository slug from origin: $repo_slug"
    return 1
  fi
  printf '%s\n' "$repo_slug"
}

normalize_repo_input() {
  local input_repo="$1"
  local org_name="$2"
  local normalized

  if [[ "$input_repo" == */* ]]; then
    normalized="$input_repo"
  else
    normalized="$org_name/$input_repo"
  fi

  if ! validate_repo_slug "$normalized"; then
    log_error "Invalid repository value: $input_repo"
    return 1
  fi

  printf '%s\n' "$normalized"
}

gh_api() {
  gh api -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

branch_exists() {
  local repo_slug="$1"
  local branch_name="$2"
  gh_api "repos/$repo_slug/branches/$branch_name" >/dev/null 2>&1
}

ensure_branch_exists() {
  local repo_slug="$1"
  local branch_name="$2"

  if branch_exists "$repo_slug" "$branch_name"; then
    log_info "$repo_slug: branch '$branch_name' already exists."
    return 0
  fi

  local main_sha
  main_sha="$(gh_api "repos/$repo_slug/branches/main" --jq '.commit.sha' 2>/dev/null || true)"
  if [[ -z "$main_sha" ]]; then
    log_error "$repo_slug: could not resolve main branch SHA. Ensure 'main' exists."
    return 1
  fi

  if gh_api -X POST "repos/$repo_slug/git/refs" -f "ref=refs/heads/$branch_name" -f "sha=$main_sha" >/dev/null 2>&1; then
    log_info "$repo_slug: created branch '$branch_name' from 'main'."
    return 0
  fi

  if branch_exists "$repo_slug" "$branch_name"; then
    log_info "$repo_slug: branch '$branch_name' now exists."
    return 0
  fi

  log_error "$repo_slug: failed to create branch '$branch_name'."
  return 1
}

main_payload() {
  cat <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci", "branch-policy"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
}

staging_payload() {
  cat <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci", "branch-policy"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "required_approving_review_count": 0
  },
  "restrictions": null,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
}

cicd_payload() {
  cat <<'EOF'
{
  "required_status_checks": {
    "strict": false,
    "contexts": ["ci"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_conversation_resolution": false,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
}

apply_protection() {
  local repo_slug="$1"
  local branch_name="$2"
  local payload_json="$3"

  if ! printf '%s\n' "$payload_json" | gh_api -X PUT "repos/$repo_slug/branches/$branch_name/protection" --input - >/dev/null; then
    log_error "$repo_slug: failed to apply protection to branch '$branch_name'."
    return 1
  fi
}

configure_repo() {
  local repo_slug="$1"

  if ! validate_repo_slug "$repo_slug"; then
    log_error "Invalid repository slug: $repo_slug"
    return 1
  fi

  log_info "Configuring branch protections for $repo_slug"

  local main_sha
  main_sha="$(gh_api "repos/$repo_slug/branches/main" --jq '.commit.sha' 2>/dev/null || true)"
  if [[ -z "$main_sha" ]]; then
    log_error "$repo_slug: branch 'main' not found. Cannot continue."
    return 1
  fi

  ensure_branch_exists "$repo_slug" "staging"
  ensure_branch_exists "$repo_slug" "ci-cd"

  apply_protection "$repo_slug" "main" "$(main_payload)"
  apply_protection "$repo_slug" "staging" "$(staging_payload)"
  apply_protection "$repo_slug" "ci-cd" "$(cicd_payload)"

  log_info "$repo_slug: protections updated for main, staging, ci-cd."
}

ORG_NAME=""
declare -a INPUT_REPOS=()

while (($# > 0)); do
  case "$1" in
    --org)
      if (($# < 2)); then
        log_error "--org requires a value."
        usage
        exit 2
      fi
      ORG_NAME="$2"
      shift 2
      ;;
    --repos)
      shift
      while (($# > 0)) && [[ "$1" != --* ]]; do
        INPUT_REPOS+=("$1")
        shift
      done
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log_error "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

require_command gh
require_command git

if ! gh auth status >/dev/null 2>&1; then
  log_error "gh is not authenticated. Run 'gh auth login' or set GH_TOKEN."
  exit 1
fi

declare -a REPO_TARGETS=()

if [[ -z "$ORG_NAME" ]]; then
  if ((${#INPUT_REPOS[@]} > 0)); then
    log_error "--repos can only be used with --org."
    exit 2
  fi

  origin_url="$(git config --get remote.origin.url 2>/dev/null || true)"
  if [[ -z "${origin_url:-}" ]]; then
    log_error "Could not read git remote origin URL in single-repo mode."
    exit 1
  fi

  detected_repo="$(parse_origin_repo_slug "$origin_url")"
  REPO_TARGETS+=("$detected_repo")
else
  if ! validate_org_name "$ORG_NAME"; then
    log_error "Invalid organization name: $ORG_NAME"
    exit 2
  fi

  if ((${#INPUT_REPOS[@]} > 0)); then
    for repo_item in "${INPUT_REPOS[@]}"; do
      normalized_repo="$(normalize_repo_input "$repo_item" "$ORG_NAME")"
      REPO_TARGETS+=("$normalized_repo")
    done
  else
    while IFS= read -r repo_name; do
      [[ -n "$repo_name" ]] || continue
      normalized_repo="$(normalize_repo_input "$repo_name" "$ORG_NAME")"
      REPO_TARGETS+=("$normalized_repo")
    done < <(gh repo list "$ORG_NAME" --json name,isArchived --limit 500 --jq '.[] | select(.isArchived == false) | .name')
  fi
fi

if ((${#REPO_TARGETS[@]} == 0)); then
  log_error "No repositories selected."
  exit 1
fi

failures=0
for repo_slug in "${REPO_TARGETS[@]}"; do
  if ! configure_repo "$repo_slug"; then
    failures=$((failures + 1))
  fi
done

if ((failures > 0)); then
  log_error "Completed with $failures failure(s)."
  exit 1
fi

log_info "Completed successfully for ${#REPO_TARGETS[@]} repo(s)."
exit 0
