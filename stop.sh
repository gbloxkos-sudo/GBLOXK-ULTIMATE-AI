#!/usr/bin/env bash
APP_URL="http://127.0.0.1:5050"
curl -s --max-time 5 -X POST "$APP_URL/api/system/kill-all" >/dev/null 2>&1 || true
curl -s --max-time 5 -X POST "$APP_URL/api/scan/stop-all" >/dev/null 2>&1 || true
curl -s --max-time 5 -X POST "$APP_URL/api/agent/stop-all" >/dev/null 2>&1 || true
curl -s --max-time 5 -X POST "$APP_URL/api/shutdown" >/dev/null 2>&1 || true
echo "GBLOXKOS stopped (all jobs killed)."
