#!/usr/bin/env bash
# Versioned owner-executed upgrade of the existing Oracle user worker and bridge.
# NEVER runs on Cortana, never resets credentials, never changes host security.
set -Eeuo pipefail
umask 077
mode="${1:---check}"
[[ "$mode" == --check || "$mode" == --install ]] || { echo 'USAGE: bash install-on-oracle.sh [--check|--install]'; exit 2; }
[[ "${HOSTNAME,,}" == 'oracle' && "$(id -un)" == 'tomo' ]] || { echo 'BLOCKED: expected tomo@Oracle'; exit 3; }
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
base="$HOME/.local/share/batcave-worker"
agent="$HOME/Downloads/Oracle_Local_AI_POC_v0.1/agent.py"
agent_sha='e60ec797966fd0055cc9c4e2cde2638599695539c8bd681b6def73ff4ab7020a'
for filename in batcave_linux_worker.py oracle_cloud_bridge.py; do
  src="$root/patch/$filename"; dst="$base/$filename"; expected="$(cat "$root/patch/$filename.before.sha256")"
  [[ -f "$dst" && ! -L "$dst" ]] || { echo "BLOCKED: source absent or symlinked $filename"; exit 4; }
  actual="$(sha256sum "$dst" | cut -d' ' -f1)"
  [[ "$actual" == "$expected" ]] || { echo "BLOCKED: source drift $filename"; exit 4; }
  [[ -f "$src" && ! -L "$src" ]] || { echo 'BLOCKED: stage source missing'; exit 4; }
done
[[ ! -e "$base/model_capability.py" ]] || { echo 'BLOCKED: model capability already present; no overwrite'; exit 4; }
[[ -f "$agent" && ! -L "$agent" ]] || { echo 'BLOCKED: pinned model agent unavailable'; exit 4; }
[[ "$(sha256sum "$agent" | cut -d' ' -f1)" == "$agent_sha" ]] || { echo 'BLOCKED: reviewed model agent drift'; exit 4; }
python3 -m py_compile "$root/patch/batcave_linux_worker.py" "$root/patch/oracle_cloud_bridge.py" "$root/patch/model_capability.py"
[[ "$(systemctl --user is-active batcave-worker.service)" == active ]] || { echo 'BLOCKED: existing worker not active'; exit 4; }
[[ "$(systemctl --user is-active batcave-oracle-bridge.service)" == active ]] || { echo 'BLOCKED: existing cloud bridge not active'; exit 4; }
# The model-enabled RPC/Edge must be deployed first; test a read-only capabilities op.
python3 - "$base" <<'PY'
import json, pathlib, sys, urllib.request
base=pathlib.Path(sys.argv[1]);token=(pathlib.Path.home()/'.config/batcave-oracle/device-token').read_text().strip()
assert len(token)==64 and all(c in '0123456789abcdef' for c in token), 'invalid token format'
request=urllib.request.Request('https://wizflveeptzeajsdybzs.supabase.co/functions/v1/batcave-oracle-bridge-v1',
 data=b'{"op":"capabilities"}',headers={'content-type':'application/json','x-batcave-device-token':token},method='POST')
try:
 with urllib.request.urlopen(request,timeout=12) as response: result=json.loads(response.read(2000))
except Exception as ex:
 raise SystemExit('BLOCKED: cloud model capability not available; no files modified') from ex
if result.get('ok') is not True or 'model_generate_and_verify_v1' not in result.get('capabilities',[]):
 raise SystemExit('BLOCKED: cloud does not advertise reviewed model capability')
print('CLOUD_TYPED_MODEL_CAPABILITY=READY')
PY
[[ "$mode" == --check ]] && { echo 'PREDEPLOY_PREFLIGHT_PASS'; exit 0; }
# Never restart a worker while it has a recent claimed job or outstanding local cloud receipts.
if [[ -d "$base/cloud-pending" ]] && find "$base/cloud-pending" -maxdepth 1 -name '*.json' -print -quit | grep -q .; then
 echo 'BLOCKED: outstanding cloud pending receipt(s); reconcile before change'; exit 4
fi
if [[ -d "$base/claimed" ]] && find "$base/claimed" -maxdepth 1 -name '*.json' -mmin -10 -print -quit | grep -q .; then
 echo 'BLOCKED: recently claimed local worker job; try only after it finishes'; exit 4
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$base/rollback-model-v0.3-$stamp"
mkdir -m 0700 -- "$backup"
cp -p -- "$base/batcave_linux_worker.py" "$backup/"
cp -p -- "$base/oracle_cloud_bridge.py" "$backup/"
cp -- "$root/rollback-on-oracle.sh" "$backup/restore-v0.3.sh"
chmod 0700 "$backup/restore-v0.3.sh"
printf '%s\n' "$(sha256sum "$root/patch/batcave_linux_worker.py" | cut -d' ' -f1)" > "$backup/installed-worker.sha256"
printf '%s\n' "$(sha256sum "$root/patch/oracle_cloud_bridge.py" | cut -d' ' -f1)" > "$backup/installed-bridge.sha256"
rollback_failure(){
 echo 'INSTALL_FAILED_ATTEMPTING_RESTORE' >&2
 cp -p -- "$backup/batcave_linux_worker.py" "$base/batcave_linux_worker.py"
 cp -p -- "$backup/oracle_cloud_bridge.py" "$base/oracle_cloud_bridge.py"
 rm -f -- "$base/model_capability.py"
 systemctl --user restart batcave-worker.service batcave-oracle-bridge.service || true
 echo 'RESTORE_ATTEMPTED_VERIFY_SERVICES' >&2
}
trap rollback_failure ERR
install -m 0600 -- "$root/patch/model_capability.py" "$base/model_capability.py"
install -m 0600 -- "$root/patch/batcave_linux_worker.py" "$base/batcave_linux_worker.py"
install -m 0600 -- "$root/patch/oracle_cloud_bridge.py" "$base/oracle_cloud_bridge.py"
python3 -m py_compile "$base/model_capability.py" "$base/batcave_linux_worker.py" "$base/oracle_cloud_bridge.py"
systemctl --user restart batcave-worker.service batcave-oracle-bridge.service
sleep 3
[[ "$(systemctl --user is-active batcave-worker.service)" == active ]]
[[ "$(systemctl --user is-active batcave-oracle-bridge.service)" == active ]]
trap - ERR
printf 'ORACLE_MODEL_WORKER_STAGED_CONFIG_VERIFIED=1\nBACKUP=%s\n' "$backup"
echo 'NEXT: independently verify cloud model job receipt before declaring production success'
