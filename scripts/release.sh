#!/usr/bin/env bash
# Maintainer release helper. Does not publish unless explicit flags are passed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION=""
CREATE_TAG=0
PUSH=0
CREATE_RELEASE_LOCAL=0
SKIP_SCAN=0

usage() {
  cat <<'EOF'
Usage: release.sh --version X.Y.Z [options]

  --version X.Y.Z     Required release version (no leading v)
  --tag               Create annotated tag vX.Y.Z locally
  --push              Push main and the tag (implies GitHub Release via CI)
  --create-release    Also create GitHub Release locally with gh (optional)
  --skip-scan         Skip local gitleaks if not installed (not for real releases)
  -h, --help          Show help

Always runs repository validation first. Never runs git add -A.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --tag) CREATE_TAG=1; shift ;;
    --push) PUSH=1; shift ;;
    --create-release) CREATE_RELEASE_LOCAL=1; shift ;;
    --skip-scan) SKIP_SCAN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "--version is required" >&2
  exit 1
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must be semver X.Y.Z without leading v" >&2
  exit 1
fi

TAG="v${VERSION}"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean" >&2
  git status --porcelain >&2
  exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "main" ]]; then
  echo "Refusing to release from branch '$BRANCH' (expected main)" >&2
  exit 1
fi

echo "==> validate repository"
python "$ROOT/scripts/validate_repository.py"

echo "==> extract changelog for $VERSION"
NOTES="$(python "$ROOT/scripts/validate_repository.py" --extract-changelog "$VERSION")"
echo "$NOTES" | head -n 5
echo "..."

if [[ "$SKIP_SCAN" -eq 0 ]]; then
  if command -v gitleaks >/dev/null 2>&1; then
    echo "==> gitleaks"
    gitleaks detect --source "$ROOT" --config "$ROOT/.gitleaks.toml" --verbose
  else
    echo "gitleaks not installed; install it or pass --skip-scan for a dry local check" >&2
    exit 1
  fi
else
  echo "==> secret scan skipped (--skip-scan)"
fi

if [[ "$CREATE_TAG" -eq 1 ]]; then
  if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Tag already exists: $TAG" >&2
    exit 1
  fi
  echo "==> git tag -a $TAG"
  git tag -a "$TAG" -m "$VERSION"
fi

if [[ "$PUSH" -eq 1 ]]; then
  if [[ "$CREATE_TAG" -ne 1 ]]; then
    echo "--push requires --tag" >&2
    exit 1
  fi
  echo "==> push main and $TAG (CI release workflow creates the GitHub Release)"
  git push origin main
  git push origin "$TAG"
fi

if [[ "$CREATE_RELEASE_LOCAL" -eq 1 ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "gh not installed" >&2
    exit 1
  fi
  TMP="$(mktemp)"
  printf '%s' "$NOTES" > "$TMP"
  echo "==> gh release create $TAG"
  gh release create "$TAG" --title "$TAG" --notes-file "$TMP"
  rm -f "$TMP"
fi

echo "Release helper finished for $TAG"
