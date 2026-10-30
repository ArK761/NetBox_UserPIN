#!/usr/bin/env bash
# User PIN – checks of everything that can be checked from outside (and, with --server, on the NetBox server).
#
#   bash pin_check.sh http://172.30.1.25                      anonymous checks only
#   bash pin_check.sh http://172.30.1.25 --pin /pin/           + signs in a PIN-only person (the PIN is asked silently)
#   NB_TOKEN=xxxx bash pin_check.sh http://172.30.1.25         + checks with a NetBox API token (installed version, hidden accounts)
#   sudo bash pin_check.sh http://127.0.0.1 --server           + checks on the server (migrations, services, keys, keepers)
#
# Options (combine freely):  --pin <path>      address of the PIN-only page (default /pin/); asks for the PIN
#                            --wrong           also tries ONE wrong PIN (counts as a wrong attempt!)
#                            --write           also tries to ADD a tenant as the PIN-only person (shows whether the
#                                              working time / the group let it through); deletes it again when it can
#                            --server          the server checks (needs root: sudo)
# Nothing here stores or prints a PIN or a token.
BASE="${1:-http://127.0.0.1}"; shift || true
BASE="${BASE%/}"
PINPATH="/pin/"; DO_PIN=0; DO_WRONG=0; DO_WRITE=0; DO_SERVER=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pin) DO_PIN=1; if [[ "${2:-}" == /* ]]; then PINPATH="$2"; shift; fi ;;
    --wrong) DO_WRONG=1 ;;
    --write) DO_WRITE=1 ;;
    --server) DO_SERVER=1 ;;
  esac; shift
done
NB_VENV="${NB_VENV:-/opt/netbox/venv}"; NB_DIR="${NB_DIR:-/opt/netbox/netbox}"
LIST="${LIST:-/tenancy/tenants/}"
JAR="$(mktemp)"; TMP="$(mktemp -d)"; trap 'rm -rf "$JAR" "$TMP"' EXIT
PASS=0; FAIL=0; WARN=0
ok()   { PASS=$((PASS+1)); printf '  \e[32mOK\e[0m    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \e[31mFAIL\e[0m  %s  (%s)\n' "$1" "$2"; }
warn() { WARN=$((WARN+1)); printf '  \e[33mWARN\e[0m  %s\n' "$1"; }
info() { printf '  info  %s\n' "$1"; }
head_() { printf '\n\e[1m== %s ==\e[0m\n' "$1"; }
req()  { curl -s -k -o "$TMP/body" -D "$TMP/head" -w '%{http_code}' --max-time 30 -b "$JAR" -c "$JAR" "$@"; }
loc()  { grep -i '^location:' "$TMP/head" | head -1 | cut -d' ' -f2- | tr -d '\r'; }
body() { cat "$TMP/body"; }
csrf() { grep -i csrftoken "$JAR" | awk '{print $NF}' | tail -1; }
closed() {  # $1 path, $2 what; closed = 401/403/404, or a redirect to the sign-in / PIN page
  local code; code=$(req "$BASE$1")
  if [[ "$code" =~ ^(401|403|404)$ ]] || { [[ "$code" =~ ^30[1-8]$ ]] && [[ "$(loc)" =~ (login|/pin|guest|my-pin|access) ]]; }; then
    ok "$2 ($1 -> $code)"
  else bad "$2" "$1 -> $code $(loc)"; fi
}

head_ "0. Reachable"
code=$(req "$BASE/login/")
[[ "$code" == 200 ]] && ok "NetBox answers: /login/ -> 200" || { bad "NetBox answers" "/login/ -> $code (is $BASE right?)"; exit 1; }

head_ "1. Nobody signed in"
for p in / /dcim/devices/ /tenancy/tenants/ /users/users/ /user/profile/ /plugins/user-pin/ /plugins/user-pin/guests/ /plugins/user-pin/users/ /plugins/user-pin/settings/; do
  closed "$p" "anonymous gets nothing"
done
for p in /api/ /api/dcim/devices/ /api/users/users/ /api/plugins/installed-plugins/; do
  code=$(req "$BASE$p"); [[ "$code" =~ ^(401|403)$ ]] && ok "anonymous API refused ($p -> $code)" || bad "anonymous API refused" "$p -> $code"
done
for p in /api/schema/swagger-ui/ /api/docs/ /graphql/; do closed "$p" "anonymous gets no API documentation / GraphQL"; done
code=$(req "$BASE/static/docs/")
if [[ "$code" =~ ^(401|403|404)$ ]] || [[ "$code" =~ ^30[1-8]$ ]]; then ok "the NetBox offline documentation is closed (/static/docs/ -> $code)"
else warn "the NetBox offline documentation /static/docs/ -> $code: a static file served by the web server (nginx), not by NetBox, so the plugin cannot close it; to hide it: location /static/docs/ { return 404; }"; fi
code=$(req "$BASE$PINPATH")
if [[ "$code" == 200 ]] && body | grep -q 'name="pin"'; then ok "the PIN page is served on $PINPATH itself"; else warn "no PIN page on $PINPATH ($code $(loc)) – another address chosen? use --pin /your/address/"; fi
body | grep -qE 'User PIN v[0-9]' && bad "no plugin version for anonymous" "version shown" || ok "no plugin version for anonymous"
body | grep -qiE 'navbar-nav|id="sidebar"' && bad "no NetBox menu on the PIN page" "menu found" || ok "no NetBox menu on the PIN page"

if [[ -n "${NB_TOKEN:-}" ]]; then
  head_ "2. With a NetBox API token"
  api() { curl -s -k --max-time 30 -H "Authorization: Bearer $NB_TOKEN" -H 'Accept: application/json' "$BASE$1"; }
  v=$(api /api/plugins/installed-plugins/ | python3 -c "import sys,json
try:
    d=json.load(sys.stdin); r=[p for p in (d if isinstance(d,list) else d.get('results',[])) if 'user_pin' in str(p.get('package',p.get('name','')))]
    print(r[0].get('version','?') if r else 'none')
except Exception as e: print('error')" 2>/dev/null)
  case "$v" in none|error|'') bad "the plugin is installed" "api answered: ${v:-nothing} (token valid? staff?)" ;; *) ok "User PIN is installed, version $v" ;; esac
  n=$(api '/api/users/users/?username__ic=PinUser&limit=1' | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('count','?'))
except Exception: print('error')" 2>/dev/null)
  [[ "$n" == 0 ]] && ok "PIN-only accounts are not in the NetBox user list (API)" || bad "PIN-only accounts are hidden from the user list" "count=$n"
fi

if [[ $DO_PIN == 1 ]]; then
  head_ "3. A PIN-only person"
  read -r -s -p "PIN of the PIN-only person (not shown, not stored): " PIN; echo
  req "$BASE$PINPATH" >/dev/null
  if [[ $DO_WRONG == 1 ]]; then
    code=$(req -X POST -H "X-CSRFToken: $(csrf)" -H "Referer: $BASE$PINPATH" --data "csrfmiddlewaretoken=$(csrf)&pin=wrong-pin-0000" "$BASE$PINPATH")
    [[ "$code" == 200 ]] && ok "one wrong PIN is refused on the page" || bad "wrong PIN" "$code"
    req "$BASE$PINPATH" >/dev/null
  fi
  code=$(req -X POST -H "X-CSRFToken: $(csrf)" -H "Referer: $BASE$PINPATH" \
         --data-urlencode "csrfmiddlewaretoken=$(csrf)" --data-urlencode "pin=$PIN" "$BASE$PINPATH"); unset PIN
  if [[ "$code" == 302 ]]; then ok "signed in with the PIN (-> $(loc))"; else
    bad "signed in" "$code (wrong PIN, blocked, disabled, pause?)"; body | grep -o 'alert[^<]*<[^<]*' | head -2; DO_PIN=0; fi
fi

if [[ $DO_PIN == 1 ]]; then
  code=$(req "$BASE/plugins/user-pin/guest/")
  [[ "$code" == 200 ]] && ok "the welcome page opens" || bad "the welcome page" "$code $(loc)"
  H="$(body)"
  echo "$H" | grep -qE 'User PIN v[0-9]' && bad "no plugin version for the person" "version shown" || ok "no plugin version for the person"
  echo "$H" | grep -qiE 'switched off by the administrator|vypnut' && info "the function is SWITCHED OFF by a keeper (the person can only change the PIN)"
  echo "$H" | grep -qiE 'No access has been given|nebol pridelený' && info "the person has no group yet (only the PIN can be changed)"
  echo "$H" | grep -qiE 'Your working time|pracovný čas' && info "a working time is set: $(echo "$H" | grep -oiE '(Your working time|Tvoj pracovný čas)[^<]{0,80}' | head -1)"

  head_ "4. What the PIN-only person must never reach"
  for p in /api/ /api/dcim/devices/ /api/users/users/ /api/users/tokens/ /api/schema/ /api/schema/swagger-ui/ /api/docs/ /graphql/ \
           /admin/ /user/profile/ /user/password/ /user/api-tokens/ /user/preferences/ /core/ /users/users/ /users/groups/ \
           /plugins/user-pin/guests/ /plugins/user-pin/users/ /plugins/user-pin/settings/ /plugins/user-pin/areas/ /plugins/user-pin/mail/; do
    closed "$p" "closed for the PIN-only person"
  done
  code=$(req "$BASE/api/tenancy/tenant-groups/?brief=1"); info "a drop-down list (/api/…/?brief=1) -> $code (200 only where a field rule lets him pick)"

  head_ "5. A page the person may open ($LIST)"
  code=$(req "$BASE$LIST")
  if [[ "$code" == 200 ]]; then
    ok "opens $LIST"; H="$(body)"
    echo "$H" | grep -qE 'footer.footer\{display:none' && ok "footer links hidden" || warn "footer links not hidden"
    echo "$H" | grep -qE 'mdi-dialpad' && ok "PIN validity badge in the top bar" || warn "no PIN badge in the top bar"
    if echo "$H" | grep -qiE 'reading only|len čítanie|Mimo pracovného|Outside working time'; then
      info "OUTSIDE the working time: reading only (a red badge in the top bar)"
    elif echo "$H" | grep -qiE 'Working time until|Pracovný čas do'; then
      info "INSIDE the working time (a grey badge in the top bar)"
    elif echo "$H" | grep -qiE 'one more save|ešte jedno uloženie'; then
      info "the last minutes: ONE more save"
    else info "no working-time limit for this person"; fi
  else bad "opens $LIST (set LIST=/your/list/ if his group allows another one)" "$code $(loc)"; fi

  if [[ $DO_WRITE == 1 ]]; then
    head_ "6. Adding as the PIN-only person (a tenant, name pincli-<time>)"
    NAME="pincli-$(date +%H%M%S)"
    req "$BASE/tenancy/tenants/add/" >/dev/null; code=$(req "$BASE/tenancy/tenants/add/")
    info "the add form: $code $(loc)  (302 = a closed form: reading only or no right)"
    code=$(req -X POST -H "X-CSRFToken: $(csrf)" -H "Referer: $BASE/tenancy/tenants/add/" \
           --data-urlencode "csrfmiddlewaretoken=$(csrf)" --data-urlencode "name=$NAME" --data-urlencode "slug=$NAME" "$BASE/tenancy/tenants/add/")
    if [[ "$code" == 302 && "$(loc)" == *"/tenancy/tenants/add"* ]] || [[ "$code" == 302 && "$(loc)" == "/tenancy/tenants/" ]]; then
      info "the save was REFUSED (reading only, or the group has no add right)"
    elif [[ "$code" == 302 ]]; then
      info "the save WENT THROUGH -> $(loc). Delete the tenant $NAME in NetBox (or by API)."
    else info "the save answered $code"; fi
  fi

  head_ "7. Sign out"
  code=$(req "$BASE/plugins/user-pin/guest/logout/")
  [[ "$code" == 302 ]] && ok "signed out (-> $(loc))" || bad "signed out" "$code"
  closed "$LIST" "after signing out nothing is open"
fi

if [[ $DO_SERVER == 1 ]]; then
  head_ "8. On the server"
  if [[ ! -x "$NB_VENV/bin/python" ]]; then bad "NetBox venv" "$NB_VENV/bin/python not found (set NB_VENV / NB_DIR)"; else
    run() { (cd "$NB_DIR" && "$NB_VENV/bin/python" manage.py "$@" 2>&1 | grep -v 'staticfiles\|System check\|^WARNINGS\|^$\|FutureWarning\|warnings.warn'); }
    for s in netbox netbox-rq; do
      systemctl is-active --quiet "$s" && ok "service $s is running" || bad "service $s" "not active (the hourly jobs and the e-mails need netbox-rq)"
    done
    ver=$(cd "$NB_DIR" && "$NB_VENV/bin/python" -c "import importlib.metadata as m; print(m.version('netbox-user-pin'))" 2>/dev/null)
    [[ -n "$ver" ]] && ok "the plugin on disk: version $ver" || bad "the plugin" "cannot import netbox_user_pin"
    "$NB_VENV/bin/python" -c "import holidays; print(holidays.__version__)" >/dev/null 2>&1 && ok "the library of public holidays is installed" || warn "the library 'holidays' is missing (pip install holidays): only days and hours are checked"
    pending=$(run showmigrations netbox_user_pin | grep -c '\[ \]')
    [[ "$pending" == 0 ]] && ok "all migrations of the plugin are applied" || bad "migrations" "$pending not applied: run manage.py migrate"
    out=$(run userpin_check); echo "$out" | sed 's/^/        /'
    echo "$out" | grep -q 'old keys can be removed\|decrypts with the active key' && ok "userpin_check: everything decrypts with the active key" || warn "userpin_check: see the lines above (a non-active key or a failure?)"
    out=$(run userpin_keeper); info "$out"
    echo "$out" | grep -q '(none)' && warn "no protection keeper yet"
    out=$(run userpin_default_deny); info "$out"
    grep -q "^LOGIN_REQUIRED *= *True" "$NB_DIR/netbox/configuration.py" 2>/dev/null && ok "LOGIN_REQUIRED = True" || warn "LOGIN_REQUIRED is not True in configuration.py (recommended: True)"
    tz=$(grep -E "^TIME_ZONE" "$NB_DIR/netbox/configuration.py" 2>/dev/null | head -1); info "working time follows: ${tz:-TIME_ZONE not set (UTC)}; server time now: $(date '+%Y-%m-%d %H:%M %Z')"
  fi
fi

printf '\n\e[1mResult: %s OK, %s FAIL, %s WARN\e[0m\n' "$PASS" "$FAIL" "$WARN"
[[ $FAIL == 0 ]]
