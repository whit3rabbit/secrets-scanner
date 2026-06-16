#!/usr/bin/env bash
# benchmark.sh — reproduce the README runtime-ruleset table.
#
# Scans a benign corpus N times per ruleset variant and reports medians of:
#   wall  (full CLI process time, incl. rule load + automaton construction)
#   scan  (the scanner's logged time, after rule construction)
#   throughput (corpus_bytes / scan)
#   RSS   (peak resident set size)
#   CPU   ((user+sys)/wall; >100% means multiple cores)
#
# Portable across macOS (BSD `/usr/bin/time -l`) and Linux (GNU `/usr/bin/time -v`),
# so the identical script runs natively and inside the Docker image.
#
# Usage:
#   CORPUS=<dir> RUNS=3 BIN=<path> scripts/benchmark.sh "Label|rules.toml" ...
#
# Each positional arg is "Display label|/path/to/rules.toml". Pass them smallest
# ruleset first to match the README ordering.
set -euo pipefail

BIN=${BIN:-target/release/secrets-scanner}
CORPUS=${CORPUS:?set CORPUS to the corpus directory}
RUNS=${RUNS:-3}
MAXFS=${MAXFS:-2000000}   # per-file size cap; corpus files are ~1 MiB

# ── time(1) flavor detection ────────────────────────────────────────────────
# macOS: `/usr/bin/time -l` (RSS in bytes). GNU: `/usr/bin/time -v` (RSS in KiB).
if /usr/bin/time -l true >/dev/null 2>&1; then
  TIME_FLAVOR=bsd
elif /usr/bin/time -v true >/dev/null 2>&1; then
  TIME_FLAVOR=gnu
else
  echo "no usable /usr/bin/time (need BSD -l or GNU -v)" >&2
  exit 1
fi

# ── stat flavor (file size) ─────────────────────────────────────────────────
if stat -f%z "$0" >/dev/null 2>&1; then STAT='stat -f%z'; else STAT='stat -c%s'; fi

corpus_bytes() {
  local total=0 sz
  for f in "$CORPUS"/*; do sz=$($STAT "$f"); total=$((total + sz)); done
  echo "$total"
}

# Convert a Rust Duration string (e.g. "77.51ms", "1.65s", "1.23µs") to milliseconds.
dur_to_ms() {
  awk -v s="$1" 'BEGIN{
    if (s ~ /µs$/ || s ~ /us$/) { sub(/[µu]s$/,"",s); printf "%.4f", s/1000; }
    else if (s ~ /ns$/)         { sub(/ns$/,"",s);    printf "%.6f", s/1000000; }
    else if (s ~ /ms$/)         { sub(/ms$/,"",s);    printf "%.4f", s; }
    else if (s ~ /s$/)          { sub(/s$/,"",s);     printf "%.4f", s*1000; }
    else                        { printf "%.4f", s; }
  }'
}

median() { sort -n | awk '{a[NR]=$1} END{ if(NR%2){print a[(NR+1)/2]} else {print (a[NR/2]+a[NR/2+1])/2} }'; }

# Bootstrap the corpus if the directory is missing or empty (FILES * ~1 MiB).
if [ ! -d "$CORPUS" ] || [ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]; then
  echo "# generating corpus at $CORPUS (${FILES:-512} x ~1 MiB)" >&2
  sh "$(dirname "$0")/gen_corpus.sh" "$CORPUS" "${FILES:-512}"
fi

CORPUS_BYTES=$(corpus_bytes)
echo "# corpus: $CORPUS  ($((CORPUS_BYTES/1024/1024)) MiB, $(ls "$CORPUS" | wc -l | tr -d ' ') files), runs=$RUNS, time=$TIME_FLAVOR, bin=$BIN" >&2

# warm the page cache
cat "$CORPUS"/* >/dev/null 2>&1 || true

printf '| %s | %s | %s | %s | %s | %s |\n' "Runtime ruleset" "wall" "scan" "Throughput" "Peak RSS" "CPU"
printf '|---|--:|--:|--:|--:|--:|\n'

for spec in "$@"; do
  label=${spec%%|*}
  rules=${spec#*|}
  walls=(); scans=(); rsss=(); cpus=()
  # one untimed warm-up
  "$BIN" scan "$CORPUS" --rules "$rules" --max-file-size "$MAXFS" --no-fail >/dev/null 2>&1 || true
  for _ in $(seq 1 "$RUNS"); do
    err=$(/usr/bin/time ${TIME_FLAVOR:+$([ "$TIME_FLAVOR" = bsd ] && echo -l || echo -v)} \
      "$BIN" scan "$CORPUS" --rules "$rules" --max-file-size "$MAXFS" --no-fail 2>&1 >/dev/null)
    scan_ms=$(dur_to_ms "$(echo "$err" | grep -oE 'Scanned .* in [0-9.]+(ns|µs|us|ms|s)' | grep -oE '[0-9.]+(ns|µs|us|ms|s)$' | tail -1)")
    if [ "$TIME_FLAVOR" = bsd ]; then
      real=$(echo "$err" | grep -oE '[0-9.]+ real' | grep -oE '^[0-9.]+')
      user=$(echo "$err" | grep -oE '[0-9.]+ user' | grep -oE '^[0-9.]+')
      sys=$(echo  "$err" | grep -oE '[0-9.]+ sys'  | grep -oE '^[0-9.]+')
      rss_bytes=$(echo "$err" | grep -i 'maximum resident set size' | grep -oE '[0-9]+' | head -1)
    else
      # GNU: Elapsed "m:ss.ss" or "ss.ss"; RSS in KiB.
      el=$(echo "$err" | grep -i 'Elapsed' | grep -oE '[0-9:.]+' | tail -1)
      real=$(awk -v t="$el" 'BEGIN{n=split(t,p,":"); if(n==2)printf"%.2f",p[1]*60+p[2]; else printf"%.2f",p[1]}')
      user=$(echo "$err" | grep -i 'User time' | grep -oE '[0-9.]+')
      sys=$(echo  "$err" | grep -i 'System time' | grep -oE '[0-9.]+')
      rss_bytes=$(( $(echo "$err" | grep -i 'Maximum resident set size' | grep -oE '[0-9]+' | head -1) * 1024 ))
    fi
    cpu=$(awk -v u="$user" -v s="$sys" -v r="$real" 'BEGIN{printf "%.0f", (u+s)/r*100}')
    walls+=("$real"); scans+=("$scan_ms"); rsss+=("$rss_bytes"); cpus+=("$cpu")
  done
  mwall=$(printf '%s\n' "${walls[@]}" | median)
  mscan=$(printf '%s\n' "${scans[@]}" | median)
  mrss=$(printf  '%s\n' "${rsss[@]}"  | median)
  mcpu=$(printf  '%s\n' "${cpus[@]}"  | median)
  tput=$(awk -v b="$CORPUS_BYTES" -v ms="$mscan" 'BEGIN{printf "%.1f", (b/(ms/1000))/1073741824}')
  rss_mib=$(awk -v b="$mrss" 'BEGIN{printf "%.0f", b/1048576}')
  # render wall in s, scan in ms
  printf '| %s | %.2f s | %.1f ms | %s GiB/s | %s MiB | %s%% |\n' \
    "$label" "$(awk -v w="$mwall" 'BEGIN{print w}')" "$mscan" "$tput" "$rss_mib" "$mcpu"
done
