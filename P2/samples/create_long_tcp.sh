#!/bin/bash
# Create file with 20000 'a', then 20000 'b', ..., till 'f'

output="data.txt"
> "$output"

for ch in {a..f}; do
  yes "$ch" | tr -d '\n' | head -c 20000 >> "$output"
done

# Verify
echo "File size (should be 120000): $(wc -c < "$output") bytes"
echo "MD5: $(md5sum "$output")"

