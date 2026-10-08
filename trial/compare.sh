#!/bin/bash
# The same requests to our entry and to the real server; a line for each, and whether the two agree.
cd /root/poc2
ours() { # ours <host> <path> [curl args]
  curl -sk -o /tmp/o -w "%{http_code} %{redirect_url}" --resolve $1:18443:127.0.0.1 "${@:3}" "https://$1:18443$2"; }
real() { # real <ip> <host> <path> [curl args]
  curl -s -o /tmp/r -w "%{http_code} %{redirect_url}" -H "Host: $2" "${@:4}" "http://$1$3"; }
# What is compared: the code; where it leads on a redirect (the path of it); the page of a 200 (a file by its sum).
norm() { echo "$1" | sed -E 's#https?://[^/ ]+##'; }
same=0; diff=0
one() { # one <our host> <real ip> <real host> <path> [curl args]
  a=$(norm "$(ours $1 "$4" "${@:5}")"); b=$(norm "$(real $2 $3 "$4" "${@:5}")")
  pa=""; pb=""
  if [ "${a%% *}" = 200 ]; then pa=$(head -c 400 /tmp/o | md5sum | cut -c1-8); pb=$(head -c 400 /tmp/r | md5sum | cut -c1-8); fi
  if [ "$a" = "$b" ] && [ "$pa" = "$pb" ]; then same=$((same+1)); printf "  ok   %-34s %s %s\n" "$4" "$a" "$(head -c 110 /tmp/o | tr -d '\n' | grep -a '^[[:print:]]*$' || echo '(a file)')"
  else diff=$((diff+1)); printf "  DIFF %-34s ours: %s | %s\n       %-34s real: %s | %s\n" "$4" "$a" "$(head -c 150 /tmp/o | tr -d '\n' | grep -a '^[[:print:]]*$')" "" "$b" "$(head -c 150 /tmp/r | tr -d '\n' | grep -a '^[[:print:]]*$')"; fi
}
common=("/" "/hello/world" "/hello/world?x=1&y=2" "/style.css" "/nofile.css" "/index.php" "/index.php/a/b?z=1" "/sub" "/sub/" "/sub/deep/er?k=v" "/img/" "/img/logo.png" "/a%20b/c.php?q=1" "/%E4%B8%AD%E6%96%87/x")
run() { # run <title> <our host> <real ip> <real host> [more paths]
  echo "== $1"
  for p in "${common[@]}" "${@:5}"; do one $2 $3 $4 "$p"; done
  one $2 $3 $4 "/post/here?p=1" -X POST --data-binary @/tmp/body
}
head -c 2000000 /dev/urandom > /tmp/body
A=172.30.0.21; NX=172.30.0.22
run "WordPress, Apache rules (.htaccess)  vs real Apache" wp.test $A wp.test
run "ThinkPHP, Apache rules               vs real Apache" tp.test $A tp.test
run "Laravel, Apache rules                vs real Apache" lv.test $A lv.test "/users/5/" "/users/5" "/sub/x/"
run "Discuz, Apache rules                 vs real Apache" dz.test $A dz.test "/forum-2-1.html" "/thread-123-1-2.html?from=x" "/topic-abc.html" "/space-uid-7.html" "/forum.php?mod=x"
run "WordPress, nginx rules               vs real nginx" wpn.test $NX wpn.test
run "ThinkPHP, nginx rules                vs real nginx" tpn.test $NX tpn.test
run "Discuz, nginx rules                  vs real nginx" dzn.test $NX dzn.test "/forum-2-1.html" "/thread-123-1-2.html?from=x" "/topic-abc.html" "/forum.php?mod=x"
run "WordPress, IIS rules (web.config)    vs real Apache with the same site's .htaccess" wpi.test $A wp.test
run "ThinkPHP, IIS rules                  vs real Apache with the same site's .htaccess" tpi.test $A tp.test
echo "== agree: $same, differ: $diff"
echo "== files: a part of one, an unchanged one, a big one whole"
ours wp.test /img/logo.png -H "Range: bytes=100-199" >/dev/null; echo "  part: $(wc -c < /tmp/o) bytes, same as the file's: $([ "$(md5sum < /tmp/o)" = "$(tail -c +101 /data/poc/t/wp/img/logo.png | head -c 100 | md5sum)" ] && echo yes || echo NO)"
et=$(curl -skI --resolve wp.test:18443:127.0.0.1 https://wp.test:18443/style.css | grep -i etag | tr -d '\r' | cut -d' ' -f2); echo "  unchanged: $(curl -sk -o /dev/null -w '%{http_code}' -H "If-None-Match: $et" --resolve wp.test:18443:127.0.0.1 https://wp.test:18443/style.css)"
ours wp.test /img/logo.png >/dev/null; echo "  whole: $([ "$(md5sum < /tmp/o)" = "$(md5sum < /data/poc/t/wp/img/logo.png)" ] && echo same || echo DIFFERENT)"
echo "== what must not be given out"
for p in /.htaccess /.user.ini /other-site.txt /passwd.txt /updir/index.php /updir/style.css "/..%2ftp/style.css" "/img/../../tp/style.css"; do printf "  %-28s ours %s   real Apache %s\n" "$p" "$(ours wp.test "$p" --path-as-is | cut -d' ' -f1) $(head -c 40 /tmp/o | tr -d '\n')" "$(real $A wp.test "$p" --path-as-is | cut -d' ' -f1) $(head -c 40 /tmp/r | tr -d '\n')"; done
echo "== what PHP sends: a redirect, a code of its own, cookies, a page sent bit by bit"
cat > /data/poc/t/wp/t.php <<'X'
<?php
switch ($_GET["t"] ?? "") {
case "loc": header("Location: /elsewhere?a=1"); break;
case "code": http_response_code(418); echo "teapot\n"; break;
case "cookie": setcookie("a", "1"); setcookie("b", "2"); echo "cookies\n"; break;
case "slow": for ($i = 0; $i < 3; $i++) { echo "part $i\n"; flush(); usleep(400000); } break;
case "big": echo str_repeat("0123456789abcdef", 200000); break;
case "up": echo count($_FILES)." file ".($_FILES["f"]["size"] ?? 0)." ".md5_file($_FILES["f"]["tmp_name"])."\n"; break;
}
X
ours wp.test "/t.php?t=loc"; echo "  redirect: $(norm "$(ours wp.test '/t.php?t=loc')")"
echo "  code: $(ours wp.test '/t.php?t=code' | cut -d' ' -f1) $(cat /tmp/o)"
echo "  cookies: $(curl -skI -X GET --resolve wp.test:18443:127.0.0.1 'https://wp.test:18443/t.php?t=cookie' | grep -ci '^set-cookie')"
echo "  bit by bit, when each part came (s): $(curl -skN --resolve wp.test:18443:127.0.0.1 'https://wp.test:18443/t.php?t=slow' | while read l; do printf '%s@%s ' "$l" "$(date +%S.%N | cut -c1-5)"; done)"
ours wp.test "/t.php?t=big" >/dev/null; echo "  3.2 MB page: $(wc -c < /tmp/o) bytes, http/1.1 too: $(curl -sk --http1.1 --resolve wp.test:18443:127.0.0.1 'https://wp.test:18443/t.php?t=big' | wc -c)"
echo "  upload of 2 MB: $(curl -sk -F f=@/tmp/body --resolve wp.test:18443:127.0.0.1 'https://wp.test:18443/t.php?t=up') (sum of what was sent $(md5sum < /tmp/body | cut -c1-32))"
echo compare-done
