#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
./reset-db.sh
./seed-db.sh

