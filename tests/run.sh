#!/usr/bin/env bash
#
# KEV-analysis numeric regression suite.
#
#   tests/run.sh               # fast suite (canonical classifier cases only)
#   tests/run.sh --full        # also re-classify the pinned snapshot
#
# Exits 1 on the first failing test. All test scripts are fail-loud — they
# print each failed check before exiting non-zero.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
cd "$REPO"

FULL=""
if [[ "${1:-}" == "--full" ]]; then
    FULL="--full"
fi

# Simple colors if the terminal supports them.
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    BOLD=""; GREEN=""; RED=""; DIM=""; RESET=""
fi

run() {
    local name="$1"; shift
    echo
    echo "${BOLD}== $name ==${RESET}"
    if ! python3 "$@"; then
        echo "${RED}${BOLD}FAILED:${RESET} $name"
        exit 1
    fi
}

run "classifier regression"      tests/test_kev_classifier.py $FULL
run "DATA blob invariants"       tests/test_data_invariants.py
run "http lift table"            tests/test_http_data.py
run "classifications JSON"       tests/test_classifications.py
run "llms.txt freshness"         tests/test_llms_txt.py
run "7-year NP+DI dataset"       tests/test_seven_year_npdi.py
run "12-month per-framework"     tests/test_twelve_month_per_framework.py
run "Mythos baseline"            tests/test_mythos_baseline.py
run "CVE reference page"         tests/test_cve_reference.py
run "EPSS-marginal §15"          tests/test_epss_marginal.py
run "7-year reconciliation"      tests/test_seven_year_reconciliation.py
run "evergreen Java section"     tests/test_evergreen_java.py
run "FOSS sub-7 scoring"         tests/test_foss_sub7_scoring.py
run "post-Apr 1 embed drift"     tests/test_post_apr1_drift.py

echo
echo "${GREEN}${BOLD}All tests passed.${RESET}"
