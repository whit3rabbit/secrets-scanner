#!/bin/sh
# gen_corpus.sh <dir> <count> — write <count> ~1 MiB benign zero-finding files.
# Same low-keyword-density content as the native run (per-line counter varies
# lines without introducing rule-keyword collisions or high-entropy tokens).
set -e
dir=$1; count=$2
mkdir -p "$dir"
i=1
while [ "$i" -le "$count" ]; do
  awk -v base="$i" 'BEGIN{
    n=0; j=0;
    while (n < 1048576) {
      line="benign configuration value lorem ipsum dolor sit amet consectetur adipiscing elit " (base*100000 + j);
      print line; n += length(line)+1; j++;
    }
  }' > "$dir/f$i.txt"
  i=$((i+1))
done
