# sites-entry

“我的站点”的入口：用 [Pingora](https://github.com/cloudflare/pingora) 写的 Web 服务器，站在所有用户站点前面。现在是**样板**，不是正式实现。需求和验证记录在 incus 仓库的 `docs/requirements/53-my-sites.md`。

## 它做什么

- 收 80 / 443，按访客要的域名选证书（OpenSSL 后端的握手回调），运行中加证书不用重启；80 口跳 https，证书验证请求（`/.well-known/acme-challenge/`）转给后端。
- 按“域名 + 最长路径前缀”找到站点：几个站点可以共用一个环境，一个站点的不同路径可以交给不同环境。
- 自己执行伪静态：Apache 的 `.htaccess`、nginx 的 `rewrite` / `try_files` / `if` / `return`、IIS 的 `web.config`，读成同一种规则（`src/rewrite.rs`）。
- 自己发静态文件（断点续传、304），打开文件一律用 `openat2` + `RESOLVE_BENEATH`，指到站点目录外的符号链接当不存在；名字以点开头的不发（`src/files.rs`）。
- PHP 交给站点环境里的 PHP-FPM，自己说 FastCGI（`src/fcgi.rs`），边算边发。
- 转发前问后端环境起了没有，没起由后端起，闲了由后端停（`hook/` 是模拟的后端）。

## 编译

```
apt-get install cmake libssl-dev pkg-config
cargo build --release
```

## 样板怎么跑的

- `trial/setup.sh`：搭测试站点（WordPress、ThinkPHP、Laravel、Discuz 自带的规则），以及对照用的真 Apache、真 nginx。
- `trial/compare.sh`：同一批请求发给入口和真服务器，逐条比。2026-10-08：147 条里 145 条一致，另 2 条是 nginx 默认的 1 MB 上传限制。
- `trial/real/`：真的 WordPress、Discuz! X3.5 整站跑（安装、登录、发帖、上传、伪静态）。数据库密码从参数传，不在文件里。
- 正式运行时（2026-10-08 起）证书和路由由站点代理 sitesd（在 tominadev/incus 的 `cmd/sitesd`）写在 `SITES_DIR`（默认 `/var/lib/sites`）下：`entry.json` 和 `certs/`，入口一秒内读到；站点目录里的 `.htaccess` 改了下一个请求就生效。环境在哪由站点代理回答（`SITES_AGENT`，默认 `127.0.0.1:7071`），入口监听 `SITES_HTTP` / `SITES_HTTPS`（默认 `:80` / `:443`）。`trial/` 里的脚本是样板时期的，用的还是旧的文件格式。

## 还没做的

上传大小限制、超时、每站点并发限制、压缩、自定义错误页、子目录里的 `.htaccess`、nginx 别的 `location`、到 PHP-FPM 的连接复用、规则文件一变立即生效、压测。见文档 53 的“还没验证、正式做时要补的”。
