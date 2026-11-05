#!/usr/bin/env bash
# ------------------------------------------------------------
# GSP382 - Mitigate Threats and Vulnerabilities with Security
#          Command Center: Challenge Lab
# Author : Jutapen
# License: MIT
#
# DISCLAIMER: Untuk tujuan pembelajaran. Gunakan dengan bijak.
# Penulis TIDAK bertanggung jawab atas akun yang diblokir/banned,
# skill badge yang dibatalkan, atau konsekuensi lain akibat
# penggunaan script ini. Risiko ditanggung pengguna.
# ------------------------------------------------------------
set -euo pipefail

PROJECT_ID="${1:-$(gcloud config get-value project 2>/dev/null)}"
[ -n "$PROJECT_ID" ] || { echo "Project ID tidak ditemukan. Jalankan: bash scc_lab.sh <PROJECT_ID>"; exit 1; }
BUCKET="scc-export-bucket-${PROJECT_ID}"
FW_RANGE="35.235.240.0/20"
gcloud config set project "$PROJECT_ID" >/dev/null 2>&1

pause() { echo; read -r -p ">>> Klik 'Check my progress' untuk: $1. Lalu tekan ENTER..." _; }

echo "== Task 2: Static mute rules =="
mute() {
  if gcloud scc muteconfigs describe "$1" --project="$PROJECT_ID" --location=global >/dev/null 2>&1; then
    echo "[skip] $1 sudah ada"
  else
    gcloud scc muteconfigs create "$1" --project="$PROJECT_ID" --location=global \
      --description="$3" --filter="$2" --type=STATIC
  fi
}
mute muting-flow-log-findings      'category="FLOW_LOGS_DISABLED"'     "Rule for muting VPC Flow Logs"
mute muting-audit-logging-findings 'category="AUDIT_LOGGING_DISABLED"' "Rule for muting audit logs"
mute muting-admin-sa-findings      'category="ADMIN_SERVICE_ACCOUNT"'  "Rule for muting admin service account findings"
pause "Task 2 (Create static mute rules)"

echo "== Task 3: Fix open SSH & RDP =="
fix_port() {
  local port="$1" names n
  names=$(gcloud compute firewall-rules list --project="$PROJECT_ID" --format=json | jq -r --arg p "$port" '
    .[] | select(.direction=="INGRESS" and (.disabled|not))
        | select((.sourceRanges // []) | index("0.0.0.0/0"))
        | select([.allowed[]? | select(.IPProtocol=="tcp") | (.ports // [])[]] | any(. == $p))
        | .name')
  if [ -z "$names" ]; then echo "[skip] tidak ada rule publik untuk port $port"; return; fi
  for n in $names; do
    echo "Update $n (port $port) -> $FW_RANGE"
    gcloud compute firewall-rules update "$n" --project="$PROJECT_ID" --source-ranges="$FW_RANGE"
  done
}
fix_port 22
fix_port 3389
pause "Task 3 (Fix high vulnerability findings)"

echo "== Task 4: Static IP + Web Security Scan =="
ZONE=$(gcloud compute instances list --filter="name=cls-vm" --format="value(zone.basename())")
[ -n "$ZONE" ] || { echo "VM cls-vm tidak ditemukan"; exit 1; }
REGION="${ZONE%-*}"
if gcloud compute addresses describe static-ip --region="$REGION" >/dev/null 2>&1; then
  IP=$(gcloud compute addresses describe static-ip --region="$REGION" --format="value(address)")
  echo "[skip] static-ip sudah ada: $IP"
else
  IP=$(gcloud compute instances describe cls-vm --zone="$ZONE" \
        --format="value(networkInterfaces[0].accessConfigs[0].natIP)")
  [ -n "$IP" ] || { echo "cls-vm tidak punya external IP"; exit 1; }
  gcloud compute addresses create static-ip --region="$REGION" --addresses="$IP"
fi
URL="http://${IP}:8080"
echo "URL aplikasi: $URL"

gcloud services enable websecurityscanner.googleapis.com
TOKEN=$(gcloud auth print-access-token)
H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "X-Goog-User-Project: $PROJECT_ID")
BASE="https://websecurityscanner.googleapis.com/v1"

SCAN=$(curl -s "${H[@]}" "$BASE/projects/$PROJECT_ID/scanConfigs" \
  | jq -r --arg u "$URL" '.scanConfigs[]? | select(.startingUrls[]? == $u) | .name' | head -n1)
if [ -z "$SCAN" ]; then
  SCAN=$(curl -s -X POST "${H[@]}" "$BASE/projects/$PROJECT_ID/scanConfigs" \
    -d "{\"displayName\":\"cymbal-scan\",\"startingUrls\":[\"$URL\"],\"userAgent\":\"CHROME_LINUX\",\"maxQps\":15}" \
    | jq -r '.name')
fi
if [ -z "$SCAN" ] || [ "$SCAN" = "null" ]; then echo "Gagal membuat scan config"; exit 1; fi
echo "Scan config: $SCAN"

RUNS=$(curl -s "${H[@]}" "$BASE/$SCAN/scanRuns" | jq -r '.scanRuns[]?.name' | head -n1)
if [ -z "$RUNS" ]; then
  RUNS=$(curl -s -X POST "${H[@]}" "$BASE/$SCAN:start" -d '{}' | jq -r '.name')
  echo "Scan dimulai: $RUNS"
else
  echo "[skip] scan run sudah ada: $RUNS"
fi
for i in $(seq 1 20); do
  STATE=$(curl -s "${H[@]}" "$BASE/$RUNS" | jq -r '.executionState // "UNKNOWN"')
  echo "Status scan: $STATE"
  [ "$STATE" = "FINISHED" ] && break
  sleep 30
done
pause "Task 4 (Run a Web Security Scan)"

echo "== Task 5: Export findings ke GCS =="
if gcloud storage buckets describe "gs://$BUCKET" >/dev/null 2>&1; then
  echo "[skip] bucket sudah ada"
else
  gcloud storage buckets create "gs://$BUCKET" --project="$PROJECT_ID" --location=us-west1
fi
mkdir -p ~/export
if ! gcloud scc findings list "projects/$PROJECT_ID" --format=json > ~/export/findings.json 2>/dev/null; then
  ORG=$(gcloud projects get-ancestors "$PROJECT_ID" --format=json | jq -r '.[] | select(.type=="organization") | .id')
  gcloud scc findings list "organizations/$ORG" --format=json > ~/export/findings.json
fi
jq -c '.[]' ~/export/findings.json > ~/export/findings.jsonl
gcloud storage cp ~/export/findings.jsonl "gs://$BUCKET/findings.jsonl"
pause "Task 5 (Export Findings to Cloud Storage)"
echo "Selesai."
