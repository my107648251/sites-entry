#!/bin/bash
# The calls the Discuz installer's page makes in the browser, in order, through the entry.
c() { curl -sk --resolve dzr.test:18443:127.0.0.1 -b /tmp/dzj -c /tmp/dzj "$@"; }
B=https://dzr.test:18443/install/
ai=$(grep -o "method=do_db_init&allinfo=[A-Za-z0-9%+/=]*" /tmp/d | head -1 | sed 's/.*allinfo=//')
echo "settings found: ${#ai} characters"
for m in do_db_init do_db_data_init; do
  c -o /tmp/r -w "$m %{http_code} %{size_download}B %{time_total}s\n" "${B}index.php?method=$m&allinfo=$ai"
  grep -ao "Fatal error[^<]*\|Database Error[^<]*\|System Error[^<]*\|errno[^<]*" /tmp/r | head -3
  sed 's/<[^>]*>/ /g' /tmp/r | tr -s ' \n' | grep -o "完成[^ ]*\|失败[^ ]*" | head -3
done
c -o /tmp/r -w "initsys %{http_code} %{size_download}B %{time_total}s\n" "${B}../misc.php?mod=initsys"; sed 's/<[^>]*>/ /g' /tmp/r | tr -s ' \n' | head -c 300; echo
