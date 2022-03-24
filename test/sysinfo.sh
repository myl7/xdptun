#!/usr/bin/env bash
set -euo pipefail

# From https://github.com/tdulcet/Linux-System-Information/blob/master/info.sh
# Copyright (c) 2019 Teal Dulcet
# SPDX-License-Identifier: MIT

# Modification Copyright (c) 2022 myl7
# Relicensed with SPDX-License-Identifier: Apache-2.0

# Teal Dulcet
# Outputs system information
# wget https://raw.github.com/tdulcet/Linux-System-Information/master/info.sh -qO - | bash -s --
# ./info.sh

if [[ $# -ne 0 ]]; then
  echo "Usage: $0" >&2
  exit 1
fi

# Check if on Linux
if ! echo "$OSTYPE" | grep -iq "linux"; then
  echo "Error: This script must be run on Linux." >&2
  exit 1
fi

# toiec <KiB>
toiec() {
  echo "$(printf "%'d" $(( $1 / 1024 ))) MiB$([[ $1 -ge 1048576 ]] && echo " ($(numfmt --from=iec --to=iec-i "${1}K")B)")"
}

# tosi <KiB>
tosi() {
  echo "$(printf "%'d" $(( (($1 * 1024) / 1000) / 1000 ))) MB$([[ $1 -ge 1000000 ]] && echo " ($(numfmt --from=iec --to=si "${1}K")B)")"
}

source /etc/os-release

echo -e "Linux Distribution: ${PRETTY_NAME:-$ID-$VERSION_ID}"

KERNEL=$(</proc/sys/kernel/osrelease) # uname -r
echo -e "Linux Kernel: $KERNEL"

file=/sys/class/dmi/id # /sys/devices/virtual/dmi/id
if [[ -d "$file" ]]; then
  if [[ -r "$file/sys_vendor" ]]; then
    MODEL=$(<"$file/sys_vendor")
  elif [[ -r "$file/board_vendor" ]]; then
    MODEL=$(<"$file/board_vendor")
  elif [[ -r "$file/chassis_vendor" ]]; then
    MODEL=$(<"$file/chassis_vendor")
  fi
  if [[ -r "$file/product_name" ]]; then
    MODEL+=" $(<"$file/product_name")"
  fi
  if [[ -r "$file/product_version" ]]; then
    MODEL+=" $(<"$file/product_version")"
  fi
elif [[ -r /sys/firmware/devicetree/base/model ]]; then
  read -r -d '' MODEL </sys/firmware/devicetree/base/model
fi
if [[ -n "$MODEL" ]]; then
  echo -e "Computer Model: $MODEL"
fi

mapfile -t CPU < <(sed -n 's/^model name[[:blank:]]*: *//p' /proc/cpuinfo | uniq)
if [[ -n "$CPU" ]]; then
  echo -e "Processor (CPU): ${CPU[0]}$([[ ${#CPU[*]} -gt 1 ]] && printf '\n %s' "${CPU[@]:1}")"
fi

CPU_THREADS=$(nproc --all) # $(lscpu | grep -i '^cpu(s)' | sed -n 's/^.\+:[[:blank:]]*//p')
CPU_CORES=$(( CPU_THREADS / $(lscpu | grep -i '^thread(s) per core' | sed -n 's/^.\+:[[:blank:]]*//p') ))
echo -e "CPU Cores/Threads: $CPU_CORES/$CPU_THREADS"

ARCHITECTURE=$(getconf LONG_BIT)
echo -e "Architecture: $HOSTTYPE (${ARCHITECTURE}-bit)"

MEMINFO=$(</proc/meminfo)
TOTAL_PHYSICAL_MEM=$(echo "$MEMINFO" | awk '/^MemTotal:/ {print $2}')
echo -e "Total Memory (RAM): $(toiec "$TOTAL_PHYSICAL_MEM") ($(tosi "$TOTAL_PHYSICAL_MEM"))"

TOTAL_SWAP=$(echo "$MEMINFO" | awk '/^SwapTotal:/ {print $2}')
echo -e "Total Swap Space: $(toiec "$TOTAL_SWAP") ($(tosi "$TOTAL_SWAP"))"

echo -e "Hostname: $HOSTNAME"
