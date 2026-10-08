#!/bin/bash
# The PHP environment with what WordPress and Discuz need, and the two programs on the data disk.
set -e
mkdir -p /root/poc3 && cd /root/poc3
cat > Dockerfile <<'X'
FROM php:8.3-fpm
RUN apt-get update && apt-get install -y --no-install-recommends libpng-dev libjpeg62-turbo-dev libfreetype6-dev libzip-dev libicu-dev \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j3 mysqli pdo_mysql gd zip exif intl opcache \
 && rm -rf /var/lib/apt/lists/*
X
docker build -q -t php-site:8.3 . 
R=/data/poc/real; rm -rf $R; mkdir -p $R
curl -sL -m 120 https://cn.wordpress.org/latest-zh_CN.tar.gz | tar xz -C $R && mv $R/wordpress $R/wp
curl -sL -m 180 -o dz.zip https://codeload.github.com/discuz-x/DiscuzX/zip/refs/heads/master
apt-get install -y -qq unzip >/dev/null 2>&1 || true
unzip -q dz.zip -d dzsrc && ls dzsrc/*/ | head -20
up=$(ls -d dzsrc/*/upload 2>/dev/null | head -1); [ -n "$up" ] && mv "$up" $R/dz
curl -sL -m 60 -o $R/wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chown -R 33:33 $R
rm -rf dzsrc dz.zip
du -sh $R/*; docker images php-site --format '{{.Size}}'; df -h / | tail -1
echo prep-done
