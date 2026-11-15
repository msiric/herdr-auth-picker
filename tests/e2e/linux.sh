#!/bin/bash
# Linux end-to-end for auth-picker, with made-up logins only. Runs in a
# throwaway container; never point it at a home with real logins.
#
#   docker build -t ap-linux-e2e -f tests/e2e/Dockerfile.linux tests/e2e
#   docker run --rm -v "$PWD":/plugin:ro -e PYTHONDONTWRITEBYTECODE=1 \
#     ap-linux-e2e bash /plugin/tests/e2e/linux.sh
#
# The image installs Claude Code with its official install script, to check
# that Claude reads a slot's credential file; without it that part is skipped.
set -u
PLUGIN=/plugin
AP="/bin/sh $PLUGIN/bin/auth-picker"
pass=0; fail=0
ok()   { echo "PASS $*"; pass=$((pass+1)); }
bad()  { echo "FAIL $*"; fail=$((fail+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

export HOME=/home/tester USER=tester
mkdir -p $HOME/.claude $HOME/.codex
cd $HOME

login() {  # who generation
  python3 - "$1" "$2" <<'EOF'
import sys, json, os
sys.path.insert(0, "/plugin")
from tests.fakes import claude_blob, claude_account, codex_auth
who, gen = sys.argv[1], int(sys.argv[2])
home = os.environ["HOME"]
with open(f"{home}/.claude/.credentials.json", "w") as f: json.dump(claude_blob(who, gen), f)
os.chmod(f"{home}/.claude/.credentials.json", 0o600)
cfg_path = f"{home}/.claude.json"
cfg = json.load(open(cfg_path)) if os.path.exists(cfg_path) else {"projects": {}}
cfg["oauthAccount"] = claude_account(who)
json.dump(cfg, open(cfg_path, "w"), indent=2)
with open(f"{home}/.codex/auth.json", "w") as f: json.dump(codex_auth(who, gen), f)
EOF
}
who() { python3 -c "import json;print(json.load(open('$HOME/.claude.json'))['oauthAccount']['emailAddress'])"; }
mode() { stat -c %a "$1"; }

echo "== versions"; python3 --version; uname -srm; claude --version 2>/dev/null || echo "no claude"

echo "== save, switch, undo"
login alice 1; $AP save --name A >/dev/null
login bob 1;   $AP save --name B >/dev/null
check "two claude profiles" "[ \$($AP status | grep -c '@example.com') -ge 4 ]"
$AP switch claude A >/dev/null; check "switch to A" "[ \"\$(who)\" = alice@example.com ]"
check "credential file stays 0600" "[ \$(mode $HOME/.claude/.credentials.json) = 600 ]"
$AP undo claude >/dev/null;   check "undo back to B" "[ \"\$(who)\" = bob@example.com ]"
$AP switch codex A >/dev/null
check "codex switch" "grep -q ws-alice $HOME/.codex/auth.json"
STATE=$HOME/.local/state/herdr/plugins/msiric.auth-picker
check "state dir 0700" "[ \$(mode $STATE) = 700 ]"
check "secrets are files 0600" "[ -z \"\$(find $STATE/secrets -type f ! -perm 600)\" ] && [ -n \"\$(ls $STATE/secrets)\" ]"
check "no token in state outside secrets" "! grep -rq 'sk-ant-ort01' --exclude-dir=secrets $STATE"

echo "== crash recovery"
python3 - <<'EOF' && ok "recover after a crash mid-install" || bad "recover after a crash mid-install"
import sys, os, json
sys.path.insert(0, "/plugin")
from auth_picker.app import App
app = App.load()
claude = app.backends["claude"]
orig = claude.install
def crash(*a, **k):
    orig(*a, **k); os._exit(9)   # the write happened, then the process died
claude.install = crash
pid = os.fork()
if pid == 0:
    app.switcher.switch("claude", "A")
os.waitpid(pid, 0)
# The crashed process left Claude's lock dirs behind; they count as stale once
# twice their stale period has passed. Age them instead of waiting.
import time
home = os.path.expanduser("~")
old = time.time() - 600
for lock in (".claude/.oauth_refresh.lock", ".claude.lock", ".claude/.storage-write.lock", ".claude.json.lock"):
    if os.path.exists(f"{home}/{lock}"):
        print("crash left", lock)
        os.utime(f"{home}/{lock}", (old, old))
app = App.load()
print(app.switcher.recover("claude"))
who = json.load(open(os.path.expanduser("~/.claude.json")))["oauthAccount"]["emailAddress"]
assert who in ("alice@example.com", "bob@example.com"), who
assert not app.journals.rescues("claude")
EOF

echo "== a session on its own account (slot)"
$AP switch claude A >/dev/null
SLOTDIR=$(python3 - <<'EOF'
import sys
sys.path.insert(0, "/plugin")
from auth_picker.app import App
app = App.load()
print(app.switcher.slots.lend(app.profiles.find("claude", "B")))
app.switcher.slots.release(app.profiles.find("claude", "B").id)
EOF
)
check "slot credential is <dir>/.credentials.json, 0600" "[ \$(mode $SLOTDIR/.credentials.json) = 600 ]"
check "slot holds B's tokens" "grep -q bob-refresh $SLOTDIR/.credentials.json"
# A fake Claude session running in the slot: /proc/<pid>/environ is what the scan reads.
mkdir -p /tmp/fakebin && cp /bin/sleep /tmp/fakebin/claude
env CLAUDE_SECURESTORAGE_CONFIG_DIR="$SLOTDIR" /tmp/fakebin/claude 300 & FAKE=$!
sleep 0.5
check "a session in the slot blocks switching every session to B" "! $AP switch claude B 2>/dev/null"
check "status lists it" "$AP status | grep -q '1 session'"
kill $FAKE; wait $FAKE 2>/dev/null
# Claude renewed B's login inside the slot meanwhile.
python3 -c "
import sys, json; sys.path.insert(0, '/plugin')
from tests.fakes import claude_blob
json.dump(claude_blob('bob', 2), open('$SLOTDIR/.credentials.json', 'w'))"
$AP cleanup >/dev/null
check "cleanup returned the idle slot" "[ ! -e $SLOTDIR ]"
$AP switch claude B >/dev/null
check "B now switches in, with the slot's newer login" "grep -q bob-refresh-2 $HOME/.claude/.credentials.json"

echo "== real Claude reads the slot's credential file on Linux"
if command -v claude >/dev/null; then
  MAIN_HASH=$(sha256sum $HOME/.claude/.credentials.json | cut -d' ' -f1)
  BROKEN=/tmp/slot-broken; mkdir -p $BROKEN; chmod 700 $BROKEN
  python3 -c "
import json, time
json.dump({'claudeAiOauth': {'accessToken': 'sk-ant-oat01-broken', 'refreshToken': 'sk-ant-ort01-broken',
 'expiresAt': int(time.time()*1000) - 1000, 'scopes': ['user:inference'], 'subscriptionType': 'max'}},
 open('$BROKEN/.credentials.json', 'w'))"
  OUT=$(cd /tmp && CLAUDE_SECURESTORAGE_CONFIG_DIR=$BROKEN timeout 60 claude -p hi 2>&1 | head -3)
  echo "  claude in a broken slot said: $OUT"
  EMPTY=/tmp/slot-empty; mkdir -p $EMPTY
  OUT2=$(cd /tmp && CLAUDE_SECURESTORAGE_CONFIG_DIR=$EMPTY timeout 60 claude -p hi 2>&1 | head -3)
  echo "  claude in an empty slot said: $OUT2"
  check "Claude tried the slot's (broken) login" "echo \"\$OUT\" | grep -qi 'oauth\|expired\|refresh\|authenticat'"
  check "an empty slot is a different failure (not logged in)" "[ \"\$OUT\" != \"\$OUT2\" ]"
  check "the main credential file was not touched" "[ \$(sha256sum $HOME/.claude/.credentials.json | cut -d' ' -f1) = $MAIN_HASH ]"
fi

echo "== summary: $pass passed, $fail failed"
[ $fail -eq 0 ]
