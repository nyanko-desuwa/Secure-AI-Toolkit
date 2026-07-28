#!/usr/bin/env bash
# Install production skills from this checkout into Claude Code skill dirs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="$ROOT/catalog/skills.json"

SCOPE="user"
MODE="copy"
ALL=0
DRY_RUN=0
VERIFY=0
FORCE=0
SKILLS_CSV=""
DEST_OVERRIDE=""

usage() {
  cat <<'EOF'
Usage: install-skills.sh [options]

  --scope user|project   Install to ~/.claude/skills or ./.claude/skills (default: user)
  --skills a,b,c         Install named production skills only
  --all                  Install every production skill from the catalog
  --mode copy|symlink    Copy or symlink (default: copy)
  --dest DIR             Override destination skills directory
  --dry-run              Print actions without changing disk
  --force                Replace an existing destination directory
  --verify               After install, check each target has SKILL.md
  -h, --help             Show this help

Never installs skills/shared or the authoring scaffold.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --skills) SKILLS_CSV="${2:-}"; shift 2 ;;
    --all) ALL=1; shift ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --dest) DEST_OVERRIDE="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --force) FORCE=1; shift ;;
    --verify) VERIFY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -f "$CATALOG" ]]; then
  echo "Missing catalog: $CATALOG" >&2
  exit 1
fi

if [[ "$MODE" != "copy" && "$MODE" != "symlink" ]]; then
  echo "--mode must be copy or symlink" >&2
  exit 1
fi

if [[ -n "$DEST_OVERRIDE" ]]; then
  DEST="$DEST_OVERRIDE"
elif [[ "$SCOPE" == "user" ]]; then
  DEST="${HOME}/.claude/skills"
elif [[ "$SCOPE" == "project" ]]; then
  DEST="$(pwd)/.claude/skills"
else
  echo "--scope must be user or project" >&2
  exit 1
fi

mapfile -t ALL_NAMES < <(CATALOG_PATH="$CATALOG" python -c '
import json, os
from pathlib import Path
data = json.loads(Path(os.environ["CATALOG_PATH"]).read_text(encoding="utf-8"))
for skill in data["skills"]:
    print(skill["name"])
')

declare -A NAME_TO_PATH
while IFS=$'\t' read -r name path; do
  path="${path%$'\r'}"
  NAME_TO_PATH["$name"]="$path"
done < <(CATALOG_PATH="$CATALOG" python -c '
import json, os
from pathlib import Path
data = json.loads(Path(os.environ["CATALOG_PATH"]).read_text(encoding="utf-8"))
for skill in data["skills"]:
    print(skill["name"] + "\t" + skill["path"])
')

SELECTED=()
if [[ "$ALL" -eq 1 ]]; then
  SELECTED=("${ALL_NAMES[@]}")
elif [[ -n "$SKILLS_CSV" ]]; then
  IFS=',' read -ra SELECTED <<< "$SKILLS_CSV"
else
  echo "Specify --all or --skills name1,name2" >&2
  exit 1
fi

# trim whitespace
CLEAN=()
for s in "${SELECTED[@]}"; do
  s="$(echo "$s" | xargs)"
  [[ -z "$s" ]] && continue
  if [[ -z "${NAME_TO_PATH[$s]+x}" ]]; then
    echo "Unknown or non-production skill: $s" >&2
    exit 1
  fi
  CLEAN+=("$s")
done
SELECTED=("${CLEAN[@]}")

if [[ ${#SELECTED[@]} -eq 0 ]]; then
  echo "No skills selected" >&2
  exit 1
fi

echo "Destination: $DEST"
echo "Mode: $MODE"
echo "Skills (${#SELECTED[@]}): ${SELECTED[*]}"

if [[ "$DRY_RUN" -eq 0 ]]; then
  mkdir -p "$DEST"
fi

for name in "${SELECTED[@]}"; do
  src="$ROOT/${NAME_TO_PATH[$name]}"
  dst="$DEST/$name"
  if [[ ! -d "$src" ]]; then
    echo "Source missing: $src" >&2
    exit 1
  fi
  if [[ -e "$dst" || -L "$dst" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
      echo "Replace: $dst"
      if [[ "$DRY_RUN" -eq 0 ]]; then
        rm -rf "$dst"
      fi
    else
      echo "Collision (use --force to replace): $dst" >&2
      exit 1
    fi
  fi
  echo "$MODE $src -> $dst"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    continue
  fi
  if [[ "$MODE" == "copy" ]]; then
    cp -R "$src" "$dst"
  else
    ln -s "$src" "$dst"
  fi
done

if [[ "$VERIFY" -eq 1 && "$DRY_RUN" -eq 0 ]]; then
  for name in "${SELECTED[@]}"; do
    if [[ ! -f "$DEST/$name/SKILL.md" ]]; then
      echo "Verify failed: $DEST/$name/SKILL.md missing" >&2
      exit 1
    fi
  done
  echo "Verify OK"
fi

echo "Done."
