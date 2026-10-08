#!/bin/bash
# Two real sites behind the entry: WordPress at wpr.test, Discuz at dzr.test, one PHP-FPM environment for both.
cd /root/poc2
for h in wpr dzr; do [ -f certs/$h.test.crt ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=$h.test" -keyout certs/$h.test.key -out certs/$h.test.crt 2>/dev/null; done
sed -i '/^wpr.test\|^dzr.test/d' routes.txt
echo "wpr.test / envr 172.30.0.12:9000 /data/poc/real/wp /sites/wp auto" >> routes.txt
echo "dzr.test / envr 172.30.0.12:9000 /data/poc/real/dz /sites/dz auto" >> routes.txt
docker rm -f envr >/dev/null 2>&1
docker create --name envr --network sites --ip 172.30.0.12 --memory 512m --cpus 2 -v /data/poc/real:/sites php-site:8.3 >/dev/null
pkill -x hook; nohup ./hook envt=172.30.0.11:9000 envr=172.30.0.12:9000 > hook.log 2>&1 &
docker start entry2 >/dev/null 2>&1 || docker run -d --name entry2 --network host -v /root/poc2:/poc:ro -v /data/poc:/data/poc:ro -v /root/poc2/entry/target/debug/sites-entry:/sites-entry:ro rust:1-bookworm /sites-entry >/dev/null
sleep 3; echo up-done
