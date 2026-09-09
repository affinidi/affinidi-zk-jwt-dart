#!/usr/bin/env bash
# Download debug symbol archives for triples listed in prebuilds/manifest.json.
#
# Usage examples:
#   ./tool/download_prebuild_symbols.sh
#   ./tool/download_prebuild_symbols.sh --triple aarch64-apple-darwin --triple x86_64-linux-android
#   ./tool/download_prebuild_symbols.sh --output-dir ./.native-symbols
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/prebuilds/manifest.json"
OUT_DIR="$ROOT/.zk_jwt_symbols"
TRIPLES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --output-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --triple)
      TRIPLES+=("$2")
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Download zk_jwt native symbol archives from manifest release URLs.

Options:
  --manifest <path>    Path to manifest.json (default: prebuilds/manifest.json)
  --output-dir <dir>   Where to save archives (default: ./.zk_jwt_symbols)
  --triple <triple>    Restrict to one triple (repeatable)
  -h, --help           Show help
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

mkdir -p "$OUT_DIR"

python3 - "$MANIFEST" "$OUT_DIR" "${TRIPLES[@]:-}" <<'PY'
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

manifest_path = sys.argv[1]
out_dir = sys.argv[2]
requested = set(sys.argv[3:])

with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)

if not isinstance(manifest, dict) or not manifest:
    raise SystemExit(f"Manifest must be a non-empty object: {manifest_path}")

triples = sorted(manifest.keys())
if requested:
    unknown = sorted(requested - set(triples))
    if unknown:
        raise SystemExit(f"Unknown triples: {unknown}. Known: {triples}")
    triples = [t for t in triples if t in requested]

def derive_symbol_url(binary_url: str, triple: str) -> tuple[str, str]:
    if binary_url.endswith(".dylib"):
        return f"{binary_url.rsplit('/', 1)[0]}/rust_eddsa_helper-{triple}.dSYM.zip", "dsym"
    if binary_url.endswith(".so"):
        return f"{binary_url.rsplit('/', 1)[0]}/rust_eddsa_helper-{triple}.so.debug.zip", "elf_debug"
    raise ValueError(f"Cannot infer symbol URL from binary URL: {binary_url}")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

downloaded = 0
skipped = 0
for triple in triples:
    entry = manifest[triple]
    if not isinstance(entry, dict):
        raise SystemExit(f"{triple}: manifest entry must be object")

    symbols = entry.get("symbols")
    if isinstance(symbols, dict):
        url = symbols.get("url")
        expected = symbols.get("sha256")
        kind = symbols.get("kind", "unknown")
        if not isinstance(url, str) or not url:
            print(f"[skip] {triple}: symbols.url missing")
            skipped += 1
            continue
    else:
        binary_url = entry.get("url")
        if not isinstance(binary_url, str) or not binary_url:
            print(f"[skip] {triple}: no url and no symbols.url")
            skipped += 1
            continue
        try:
            url, kind = derive_symbol_url(binary_url, triple)
        except ValueError as e:
            print(f"[skip] {triple}: {e}")
            skipped += 1
            continue
        expected = None

    filename = url.rsplit("/", 1)[-1]
    target = os.path.join(out_dir, filename)
    print(f"[download] {triple}: {kind} -> {filename}")

    try:
        with urllib.request.urlopen(url, timeout=120) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            data = resp.read()
    except urllib.error.HTTPError as e:
        print(f"[warn] {triple}: failed to download {url} ({e.code})")
        skipped += 1
        continue
    except Exception as e:
        print(f"[warn] {triple}: failed to download {url} ({e})")
        skipped += 1
        continue

    digest = sha256_bytes(data)
    if isinstance(expected, str) and expected:
        if digest != expected.lower():
            raise SystemExit(
                f"{triple}: SHA mismatch for {filename}: expected {expected.lower()}, got {digest}"
            )
    else:
        print(f"[note] {triple}: no symbols.sha256 in manifest; downloaded hash {digest}")

    with open(target, "wb") as f:
        f.write(data)
    print(f"[ok] {triple}: {target}")
    downloaded += 1

print(f"Done. downloaded={downloaded}, skipped={skipped}, out_dir={out_dir}")
PY
