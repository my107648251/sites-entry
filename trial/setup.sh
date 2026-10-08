#!/bin/bash
# The sites, rules and servers of the second trial: the same sites behind our entry, a real Apache and a real nginx.
set -e
cd /root/poc2
mkdir -p certs rules
T=/data/poc/t; N=/data/poc/tn
rm -rf $T $N
stub='<?php
$b = file_get_contents("php://input");
echo basename(__FILE__)."|uri=".$_SERVER["REQUEST_URI"]."|script=".$_SERVER["SCRIPT_NAME"]."|pi=".($_SERVER["PATH_INFO"]??"")."|qs=".$_SERVER["QUERY_STRING"]."|get=".json_encode($_GET)."|m=".$_SERVER["REQUEST_METHOD"]."|body=".(strlen($b)?md5($b):"")."\n";'
site() { # site <folder> [more php files]
  mkdir -p $1/sub $1/img $1/'a b'
  for f in index.php sub/index.php 'a b/c.php' "${@:2}"; do echo "$stub" > "$1/$f"; done
  echo "body{color:red}" > $1/style.css
  head -c 300000 /dev/urandom > $1/img/logo.png
  echo secret > $1/.user.ini
}
for s in wp tp lv; do site $T/$s; done
site $T/dz forum.php portal.php
# The same sites again, without rules of their own: for the rules written the other ways.
cp -a $T $N
# A link that leads out of the site: to another site's file, and to the system's.
ln -s $T/tp/index.php $T/wp/other-site.txt; ln -s /etc/passwd $T/wp/passwd.txt; ln -s ../tp $T/wp/updir
cat > $T/wp/.htaccess <<'X'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
X
cat > $T/tp/.htaccess <<'X'
<IfModule mod_rewrite.c>
  Options +FollowSymlinks -Multiviews
  RewriteEngine On

  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteRule ^(.*)$ index.php?s=/$1 [QSA,PT,L]
</IfModule>
X
cat > $T/lv/.htaccess <<'X'
<IfModule mod_rewrite.c>
    <IfModule mod_negotiation.c>
        Options -MultiViews -Indexes
    </IfModule>

    RewriteEngine On

    # Handle Authorization Header
    RewriteCond %{HTTP:Authorization} .
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

    # Redirect Trailing Slashes If Not A Folder...
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} (.+)/$
    RewriteRule ^ %1 [L,R=301]

    # Send Requests To Front Controller...
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</IfModule>
X
cat > $T/dz/.htaccess <<'X'
RewriteEngine On
RewriteBase /
RewriteCond %{QUERY_STRING} ^(.*)$
RewriteRule ^topic-(.+)\.html$ portal.php?mod=topic&topic=$1&%1
RewriteCond %{QUERY_STRING} ^(.*)$
RewriteRule ^forum-(\w+)-([0-9]+)\.html$ forum.php?mod=forumdisplay&fid=$1&page=$2&%1
RewriteCond %{QUERY_STRING} ^(.*)$
RewriteRule ^thread-([0-9]+)-([0-9]+)-([0-9]+)\.html$ forum.php?mod=viewthread&tid=$1&extra=page%3D$3&page=$2&%1
RewriteCond %{QUERY_STRING} ^(.*)$
RewriteRule ^space-(username|uid)-(.+)\.html$ home.php?mod=space&$1=$2&%1
X
cat > rules/wp.nginx <<'X'
location / {
    try_files $uri $uri/ /index.php?$args;
}
X
cat > rules/tp.nginx <<'X'
location / {
    if (!-e $request_filename) {
        rewrite ^(.*)$ /index.php?s=/$1 last;
    }
}
X
cat > rules/dz.nginx <<'X'
rewrite ^([^\.]*)/topic-(.+)\.html$ $1/portal.php?mod=topic&topic=$2 last;
rewrite ^([^\.]*)/forum-(\w+)-([0-9]+)\.html$ $1/forum.php?mod=forumdisplay&fid=$2&page=$3 last;
rewrite ^([^\.]*)/thread-([0-9]+)-([0-9]+)-([0-9]+)\.html$ $1/forum.php?mod=viewthread&tid=$2&extra=page%3D$4&page=$3 last;
rewrite ^([^\.]*)/space-(username|uid)-(.+)\.html$ $1/home.php?mod=space&$2=$3 last;
if (!-e $request_filename) {
    return 404;
}
X
cat > rules/wp.config <<'X'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="WordPress Rule" stopProcessing="true">
          <match url=".*" />
          <conditions>
            <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
            <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
          </conditions>
          <action type="Rewrite" url="index.php" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
X
cat > rules/tp.config <<'X'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="OrgPage" stopProcessing="true">
          <match url="^(.*)$" />
          <conditions logicalGrouping="MatchAll">
            <add input="{HTTP_HOST}" pattern="^(.*)$" />
            <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
            <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
          </conditions>
          <action type="Rewrite" url="index.php?s=/{R:1}" appendQueryString="true" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
X
hosts="wp tp lv dz wpn tpn dzn wpi tpi"
for h in $hosts; do openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=$h.test" -keyout certs/$h.test.key -out certs/$h.test.crt 2>/dev/null; done
F=172.30.0.11:9000
{
for s in wp tp lv dz; do echo "$s.test / envt $F $T/$s /sites/t/$s auto"; done
for s in wp tp dz; do echo "${s}n.test / envt $F $N/$s /sites/tn/$s /poc/rules/$s.nginx"; done
for s in wp tp; do echo "${s}i.test / envt $F $N/$s /sites/tn/$s /poc/rules/$s.config"; done
} > routes.txt
# The servers.
docker network inspect sites >/dev/null 2>&1 || docker network create --subnet 172.30.0.0/24 sites >/dev/null
docker rm -f envt truth-a truth-n entry2 >/dev/null 2>&1 || true
docker pull -q php:8.3-fpm >/dev/null; docker pull -q nginx:alpine >/dev/null
docker create --name envt --network sites --ip 172.30.0.11 --memory 256m --cpus 1 -v $T:/sites/t -v $N:/sites/tn php:8.3-fpm >/dev/null
{
echo '<Directory /sites>'; echo '  AllowOverride All'; echo '  Options -Indexes +FollowSymLinks'; echo '  Require all granted'; echo '</Directory>'
for s in wp tp lv dz; do echo "<VirtualHost *:80>"; echo "  ServerName $s.test"; echo "  DocumentRoot /sites/t/$s"; echo "</VirtualHost>"; done
} > truth-a.conf
docker run -d --name truth-a --network sites --ip 172.30.0.21 -v $T:/sites/t -v /root/poc2/truth-a.conf:/etc/apache2/sites-enabled/000-default.conf:ro php:8.3-apache sh -c "a2enmod -q rewrite && exec apache2-foreground" >/dev/null
{
for s in wp tp dz; do
cat <<X
server {
  listen 80; server_name ${s}n.test; root /sites/tn/$s; index index.php index.html;
  $(cat rules/$s.nginx)
  location ~ \.php(/|\$) {
    fastcgi_split_path_info ^(.+\.php)(/.*)\$;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    fastcgi_param PATH_INFO \$fastcgi_path_info;
    fastcgi_pass $F;
  }
}
X
done
} > truth-n.conf
docker start envt >/dev/null
docker run -d --name truth-n --network sites --ip 172.30.0.22 -v $N:/sites/tn:ro -v /root/poc2/truth-n.conf:/etc/nginx/conf.d/default.conf:ro nginx:alpine >/dev/null
sleep 2; docker stop -t 1 envt >/dev/null
docker ps --format "{{.Names}} {{.Status}}" | tr "\n" ";"; echo; echo setup-done
