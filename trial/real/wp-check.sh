#!/bin/bash
# WordPress through the entry, as a visitor and as its admin would use it.
PW="$1"; B=https://wpr.test:18443; J=/tmp/wpjar; rm -f $J
c() { curl -sk --resolve wpr.test:18443:127.0.0.1 -b $J -c $J "$@"; }
code() { c -o /tmp/p -w "%{http_code} %{time_total}s %{size_download}B %{redirect_url}" "$@"; }
docker stop -t 1 envr >/dev/null 2>&1
echo "home (cold):      $(code $B/)  title: $(grep -o '<title>[^<]*' /tmp/p | head -1)"
echo "home (warm):      $(code $B/)"
echo "css of a theme:   $(code "$B/wp-includes/css/dist/block-library/style.min.css")"
echo "login page:       $(code $B/wp-login.php)"
echo "log in:           $(code -X POST -d "log=admin&pwd=$PW&wp-submit=1&redirect_to=$B/wp-admin/&testcookie=1" -b "wordpress_test_cookie=WP%20Cookie%20check" $B/wp-login.php)"
echo "dashboard:        $(code $B/wp-admin/)  $(grep -o '<title>[^<]*' /tmp/p | head -1)"
nonce=$(c $B/wp-admin/options-permalink.php | grep -o 'name="_wpnonce" value="[^"]*"' | head -1 | cut -d'"' -f4)
echo "save permalinks:  $(code -X POST --data-urlencode "selection=/%postname%/" --data-urlencode "permalink_structure=/%postname%/" -d "_wpnonce=$nonce&_wp_http_referer=/wp-admin/options-permalink.php&submit=1" $B/wp-admin/options-permalink.php)"
sleep 3; echo ".htaccess WordPress wrote:"; sed 's/^/    /' /data/poc/real/wp/.htaccess 2>/dev/null || echo "    (none)"
echo "a post, pretty:   $(code $B/first-test/)  $(grep -o '<title>[^<]*' /tmp/p | head -1)"
echo "post, h1.1:       $(code --http1.1 $B/first-test/)"
echo "category:         $(code $B/category/uncategorized/)"
echo "page 2 of posts:  $(code "$B/page/2/")"
echo "no such page:     $(code $B/no-such-page/)"
echo "REST API:         $(code $B/wp-json/wp/v2/posts)  $(head -c 80 /tmp/p)"
echo "search:           $(code "$B/?s=hello")"
echo "feed:             $(code $B/feed/)"
echo "sitemap:          $(code $B/wp-sitemap.xml)"
# an upload through the admin's media page (async-upload)
docker exec envr php -r '$i=imagecreatetruecolor(64,64);imagefill($i,0,0,imagecolorallocate($i,200,0,0));imagepng($i,"/tmp/up.png");'; docker cp envr:/tmp/up.png /tmp/up.png
unonce=$(c $B/wp-admin/media-new.php | grep -o '"_wpnonce":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "upload media:     $(code -F "async-upload=@/tmp/up.png;type=image/png" -F "name=up.png" -F "_wpnonce=$unonce" -F "action=upload-attachment" $B/wp-admin/async-upload.php)  $(head -c 120 /tmp/p)"
f=$(grep -o '"url":"[^"]*uploads[^"]*"' /tmp/p | head -1 | cut -d'"' -f4 | sed 's#\\/#/#g;s#https://wpr.test:18443##')
[ -n "$f" ] && echo "the file uploaded: $(code "$B$f")  on the disk: $(ls -la /data/poc/real/wp$f 2>&1 | awk '{print $3":"$4, $5}')"
echo "wp-config.php:    $(code $B/wp-config.php)  bytes shown: $(wc -c < /tmp/p)"
echo "a folder listing: $(code $B/wp-content/uploads/)"
echo "log out:          $(code "$B/wp-login.php?action=logout&_wpnonce=$(c $B/wp-admin/ | grep -o "_wpnonce=[a-z0-9]*" | head -1 | cut -d= -f2)")"
echo wp-done
