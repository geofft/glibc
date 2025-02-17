#!/usr/bin/env bash
#
# Usage: conglomerate.sh <input-binary> <output-binary>
#
# Creates a copy of <input-binary> that has a self-contained ld.so.

type readelf &>/dev/null || PATH="$PATH:$(nix-build --no-out-link -E '(import <nixpkgs> {}).binutils')/bin"

set -eu

declare -i DT_GNU_OFFSET=0x6ffffdf3

# We assume a 64-bit, little-endian, 4kB-page platform.

# First, create a file consisting of our ld.so, followed by our input
# binary aligned to the next page.
cp build/elf/ld.so "$2"
truncate -s %4096 "$2"
offset=$(stat -c %s "$2")
cat "$1" >> "$2"

# Find the location and size of the dynamic section. There should
# generally be 5 DT_NULL entries at the end (ld --spare-dynamic-tags
# defaults to 5).  For validity, there needs to actually be one DT_NULL
# entry, so we _should_ have four actually unused entries and we can
# grab one of them. Make sure that the dynamic section has room for at
# least one unused entry. (readelf will print/count the first DT_NULL
# one but not the rest.)
< <(readelf -l "$2" | grep -A1 DYNAMIC | awk '{print $2}') readarray vals
declare -i dynamic_start=${vals[0]}
declare -i dynamic_size=${vals[1]}
entries=$(readelf -d "$2" | sed -n 's/.*contains \([0-9]*\) entries.*/\1/p')
if [ "$((entries * 16 ))" -ge "$dynamic_size" ]; then
  echo "No more room in dynamic section!" >&2
  exit 1
fi

# Add our entry overwriting the DT_NULL entry at the end (so at location
# entries - 1), and to be safe, add a DT_NULL entry afterwards to be
# explicit. We need to do an endianness conversion by looping through
# xxd -e.
printf "%016x" "$DT_GNU_OFFSET" "$offset" 0 0 | xxd -r -p | xxd -e -g 8 | xxd -r | dd of="$2" conv=notrunc bs=8 seek="$((dynamic_start / 8 + 2 * (entries - 1)))" status=none
