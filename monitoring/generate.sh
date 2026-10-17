#!/usr/bin/env bash
# SLO の定義（monitoring/sloth/authserver.yml）から Prometheus のルールを作る（docs/SLO.md §6）。
# 使い方: monitoring/generate.sh            … ルールを作り直す
#         monitoring/generate.sh --check    … 作り直して、コミット済みのものと違えば失敗する（CI）
# sloth と promtool は PATH にあるものを使う（CI は版とハッシュを固定して入れる：.github/workflows/ci.yml）。
set -euo pipefail
cd "$(dirname "$0")"
out=prometheus/slo-rules.yml
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
sloth generate --default-slo-period=28d -i sloth/authserver.yml -o "$tmp" >/dev/null
{
  echo "# 生成物。直接直さない：monitoring/sloth/authserver.yml を直して monitoring/generate.sh を流す"
  cat "$tmp"
} > "$tmp.out"
if [[ "${1:-}" == "--check" ]]; then
  if ! diff -u "$out" "$tmp.out"; then
    echo "monitoring/prometheus/slo-rules.yml が定義と食い違っている。monitoring/generate.sh を流してコミットする" >&2
    rm -f "$tmp.out"; exit 1
  fi
  rm -f "$tmp.out"
else
  mv "$tmp.out" "$out"
fi
promtool check rules "$out"
promtool test rules prometheus/tests/*.yml
