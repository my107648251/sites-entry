#!/bin/bash
# Start the Discuz install over: no lock, no settings, the form sent again, then the background calls.
PW="$1"
rm -f /data/poc/real/dz/data/install.lock /data/poc/real/dz/config/config_global.php /data/poc/real/dz/config/config_ucenter.php /data/poc/real/dz/uc_server/data/config.inc.php /data/poc/real/dz/uc_server/data/install.lock
c() { curl -sk --resolve dzr.test:18443:127.0.0.1 -b /tmp/dzj -c /tmp/dzj "$@"; }; rm -f /tmp/dzj
B=https://dzr.test:18443/install/index.php
for s in "" "?step=1" "?step=2"; do c -o /dev/null "$B$s"; done
c -o /tmp/d -w "form %{http_code} %{size_download}B\n" -X POST --data-urlencode step=3 --data-urlencode install_ucenter=yes --data-urlencode "submitname=下一步" \
  --data-urlencode "dbinfo[dbhost]=10.233.105.3" --data-urlencode "dbinfo[dbname]=dz" --data-urlencode "dbinfo[dbuser]=dz" --data-urlencode "dbinfo[dbpw]=$PW" --data-urlencode "dbinfo[tablepre]=pre_" --data-urlencode "dbinfo[adminemail]=t@example.com" \
  --data-urlencode "admininfo[username]=admin" --data-urlencode "admininfo[password]=$PW" --data-urlencode "admininfo[password2]=$PW" --data-urlencode "admininfo[email]=t@example.com" "$B"
/root/poc2/dz-install.sh
c -o /tmp/r -w "ext_info %{http_code}\n" "$B?method=ext_info"
ls /data/poc/real/dz/data/install.lock
