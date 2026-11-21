#!/usr/bin/env bash
# Owner-invoked rollback. This script belongs in the timestamped rollback folder.
set -Eeuo pipefail
umask 077
[[ "$(hostname | tr '[:upper:]' '[:lower:]')" == oracle && "$(id -un)" == tomo ]] || { echo 'BLOCKED: wrong host/user'; exit 3; }
backup="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
base="$HOME/.local/share/batcave-worker"
for name in batcave_linux_worker.py oracle_cloud_bridge.py; do
 [[ -f "$backup/$name" ]] || { echo 'BLOCKED: missing rollback source'; exit 4; }
done
[[ "$(sha256sum "$base/batcave_linux_worker.py" | cut -d' ' -f1)" == "$(cat "$backup/installed-worker.sha256")" ]] || { echo 'BLOCKED: newer worker modification detected'; exit 4; }
[[ "$(sha256sum "$base/oracle_cloud_bridge.py" | cut -d' ' -f1)" == "$(cat "$backup/installed-bridge.sha256")" ]] || { echo 'BLOCKED: newer bridge modification detected'; exit 4; }
# No service changes if a job is in flight.
if [[ -d "$base/cloud-pending" ]] && find "$base/cloud-pending" -maxdepth 1 -name '*.json' -print -quit | grep -q .; then
 echo 'BLOCKED: outstanding cloud work; reconcile first'; exit 4
fi
cp -p -- "$backup/batcave_linux_worker.py" "$base/batcave_linux_worker.py"
cp -p -- "$backup/oracle_cloud_bridge.py" "$base/oracle_cloud_bridge.py"
rm -f -- "$base/model_capability.py"
systemctl --user restart batcave-worker.service batcave-oracle-bridge.service
[[ "$(systemctl --user is-active batcave-worker.service)" == active ]]
[[ "$(systemctl --user is-active batcave-oracle-bridge.service)" == active ]]
echo 'ORACLE_MODEL_WORKER_ROLLBACK_VERIFIED_LOCAL'
