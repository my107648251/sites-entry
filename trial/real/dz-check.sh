#!/bin/bash
# Discuz through the entry: as a visitor, then logged in as its admin, posting a thread and reading it back.
PW="$1"; B=https://dzr.test:18443; J=/tmp/dzu; rm -f $J
c() { curl -sk --resolve dzr.test:18443:127.0.0.1 -b $J -c $J "$@"; }
code() { c -o /tmp/p -w "%{http_code} %{time_total}s %{size_download}B %{redirect_url}" "$@"; }
err() { grep -ao "Database Error\|System Error\|Fatal error[^<]*\|Warning[^<]*" /tmp/p | head -2 | tr '\n' ' '; }
docker stop -t 1 envr >/dev/null 2>&1
echo "home (cold):        $(code $B/)  $(grep -ao '<title>[^<]*' /tmp/p | head -1 | tr -d '\n') $(err)"
echo "forum.php:          $(code $B/forum.php)  $(err)"
echo "a board:            $(code "$B/forum.php?mod=forumdisplay&fid=2")  $(err)"
echo "static css/js:      $(code "$B/static/js/common.js") / $(code "$B/static/image/common/logo.svg")"
echo "captcha image:      $(code "$B/misc.php?mod=seccode&action=update&idhash=cS&modid=member::logging") type $(file -b /tmp/p 2>/dev/null | cut -c1-20)"
fh=$(c $B/member.php?mod=logging\&action=login | grep -ao 'name="formhash" value="[^"]*"' | head -1 | cut -d'"' -f4)
echo "log in:             $(code -X POST --data-urlencode "username=admin" --data-urlencode "password=$PW" -d "formhash=$fh&referer=$B/&questionid=0&answer=&loginsubmit=yes" "$B/member.php?mod=logging&action=login&loginsubmit=yes&inajax=1") $(grep -ao '欢迎您回来[^,<]*\|登录失败[^<]*\|密码错误[^<]*\|验证码[^<]*' /tmp/p | head -1)"
fh=$(c "$B/forum.php?mod=post&action=newthread&fid=2" | grep -ao 'name="formhash" value="[^"]*"' | head -1 | cut -d'"' -f4)
echo "new thread:         $(code -X POST --data-urlencode "subject=第一个测试帖" --data-urlencode "message=正文：经过 Pingora 入口发的帖" -d "formhash=$fh&posttime=$(date +%s)&wysiwyg=0&usesig=1&allownoticeauthor=1&topicsubmit=yes" "$B/forum.php?mod=post&action=newthread&fid=2&extra=&topicsubmit=yes")  $(err)"
tid=$(echo "$(cat /tmp/p) $(c -o /dev/null -w '%{redirect_url}' "$B/forum.php?mod=forumdisplay&fid=2")" | grep -ao 'tid=[0-9]*' | head -1 | cut -d= -f2)
[ -z "$tid" ] && tid=$(c "$B/forum.php?mod=forumdisplay&fid=2" | grep -ao 'tid=[0-9]*' | head -1 | cut -d= -f2)
echo "read the thread:    $(code "$B/forum.php?mod=viewthread&tid=$tid")  has the text: $(grep -ac '经过 Pingora 入口发的帖' /tmp/p)"
echo "admin centre:       $(code "$B/admin.php")  $(grep -ao '<title>[^<]*' /tmp/p | head -1)"
echo "turn on rewrite:    (Discuz writes no .htaccess; the rules are the site's, put in by the owner)"
cp /root/poc2/rules-dz.htaccess /data/poc/real/dz/.htaccess && chown 33:33 /data/poc/real/dz/.htaccess; sleep 3
echo "thread, pretty:     $(code "$B/thread-$tid-1-1.html")  has the text: $(grep -ac '经过 Pingora 入口发的帖' /tmp/p)"
echo "board, pretty:      $(code "$B/forum-2-1.html")  $(err)"
echo "config file:        $(code "$B/config/config_global.php") bytes $(wc -c < /tmp/p)"
echo "data folder:        $(code "$B/data/install.lock") / $(code "$B/data/")"
echo "uc_server:          $(code "$B/uc_server/")  $(err)"
echo "api (uc):           $(code "$B/api/uc.php")"
echo "log out:            $(code "$B/member.php?mod=logging&action=logout&formhash=$(c $B/forum.php | grep -ao 'formhash=[a-z0-9]*' | head -1 | cut -d= -f2)")"
echo dz-done
