// The entry of "my sites" (docs/requirements/53 of tominadev/incus): the
// web server in front of every user's site on a host. It chooses the
// certificate by the name asked for, finds the site by host and the longest
// path prefix, applies the site's rewrite rules (Apache's, nginx's or IIS's,
// read into one form), serves files itself and hands PHP to the site's
// environment, PHP-FPM alone, over FastCGI.
//
// What it serves is written by the site agent (sitesd) beside it: routes in
// entry.json and certificates in certs/, under SITES_DIR. They are read
// again as they change; a site's .htaccess is read again as it changes,
// at the next request. Before a request goes to an environment the agent is
// asked for it (SITES_AGENT): it starts one that is stopped and says where
// it listens.

mod fcgi;
mod files;
mod rewrite;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use log::{info, warn};
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

fn setting(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// A route as the agent writes it (sitesd's EntryRoute).
#[derive(Deserialize, Clone, Default)]
#[serde(default)]
struct RouteIn {
    host: String,
    prefix: String,
    env: String,
    root: String,
    env_root: String,
    rules: String,
    text: String,
    off: String,
}

#[derive(Clone)]
struct Route {
    host: String,
    prefix: String,
    // The environment that runs its PHP; empty for a site of files alone.
    env: String,
    // The site's folder as the entry sees it, and as its environment does.
    root: PathBuf,
    fpm_root: String,
    // "auto": the .htaccess in its folder, read as it changes; else rules given whole.
    auto: bool,
    rules: Arc<rewrite::Rules>,
    // What is answered instead of the site: "" for the site, "off", "expired".
    off: String,
}

#[derive(Default)]
struct Table {
    certs: HashMap<String, (X509, PKey<Private>)>,
    routes: Vec<Route>,
}

type Shared = Arc<RwLock<Table>>;

/// The .htaccess of the sites' folders as last read, by folder, with the
/// moment the file was changed then (none: there was no file).
type Rules = Arc<Mutex<HashMap<PathBuf, (Option<SystemTime>, Arc<rewrite::Rules>)>>>;

// htaccess gives the rules of the .htaccess in a folder, read again where
// the file changed since it was last read.
fn htaccess(cache: &Rules, root: &Path) -> Arc<rewrite::Rules> {
    let file = root.join(".htaccess");
    let changed = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
    if let Some((at, r)) = cache.lock().unwrap().get(root) {
        if *at == changed {
            return r.clone();
        }
    }
    let r = Arc::new(match std::fs::read_to_string(&file) {
        Ok(text) => {
            let r = rewrite::htaccess(&text, "/");
            for s in &r.skipped {
                warn!("{}: rule passed over: {s}", file.display());
            }
            r
        }
        Err(_) => rewrite::Rules::default(),
    });
    cache.lock().unwrap().insert(root.to_path_buf(), (changed, r.clone()));
    r
}

// load reads the certificates and the routes the agent wrote.
fn load(dir: &str) -> Table {
    let mut t = Table::default();
    if let Ok(list) = std::fs::read_dir(format!("{dir}/certs")) {
        for e in list.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("crt") {
                continue;
            }
            // A certificate for every name under a domain is kept as _.domain.
            let name = p.file_stem().unwrap().to_string_lossy().replacen('_', "*", 1);
            let (Ok(c), Ok(k)) = (std::fs::read(&p), std::fs::read(p.with_extension("key"))) else { continue };
            match (X509::from_pem(&c), PKey::private_key_from_pem(&k)) {
                (Ok(c), Ok(k)) => {
                    t.certs.insert(name, (c, k));
                }
                _ => warn!("{}: not a certificate and its key", p.display()),
            }
        }
    }
    let routes: Vec<RouteIn> = match std::fs::read(format!("{dir}/entry.json")) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
            warn!("entry.json: {e}");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    };
    for r in routes {
        let rules = match r.rules.as_str() {
            "nginx" => rewrite::nginx(&r.text),
            "iis" => rewrite::iis(&r.text),
            _ => rewrite::Rules::default(),
        };
        for s in &rules.skipped {
            warn!("{}{}: rule passed over: {s}", r.host, r.prefix);
        }
        t.routes.push(Route {
            host: r.host.to_lowercase(),
            prefix: r.prefix.trim_end_matches('/').into(),
            env: r.env,
            root: PathBuf::from(r.root),
            fpm_root: r.env_root,
            auto: r.rules != "nginx" && r.rules != "iis",
            rules: Arc::new(rules),
            off: r.off,
        });
    }
    // The longest prefix first.
    t.routes.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));
    t
}

// certificate is the certificate for a name: its own, or one for every name under its domain.
fn certificate(t: &Table, name: &str) -> Option<(X509, PKey<Private>)> {
    if let Some(c) = t.certs.get(name) {
        return Some(c.clone());
    }
    let (_, parent) = name.split_once('.')?;
    t.certs.get(&format!("*.{parent}")).cloned()
}

struct Certs(Shared);

#[async_trait]
impl pingora::listeners::TlsAccept for Certs {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let name = ssl.servername(NameType::HOST_NAME).unwrap_or("").to_lowercase();
        let found = certificate(&self.0.read().unwrap(), &name);
        match found {
            Some((cert, key)) => {
                pingora::tls::ext::ssl_use_certificate(ssl, &cert).unwrap();
                pingora::tls::ext::ssl_use_private_key(ssl, &key).unwrap();
            }
            None => warn!("no certificate for {name:?}"),
        }
    }
}

struct Entry {
    table: Shared,
    tls: bool,
    agent: String,
    rules: Rules,
}

// ask asks the agent for an environment: it starts one that is not running
// and answers once it takes requests, with where it listens. Else the
// agent's answer: 423 for one that is off, 404 for none, 503.
async fn ask(agent: &str, env: &str) -> std::result::Result<String, u16> {
    let run = async {
        let mut s = tokio::net::TcpStream::connect(agent).await.ok()?;
        s.write_all(format!("GET /ask?env={env} HTTP/1.0\r\nHost: agent\r\n\r\n").as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        let text = String::from_utf8_lossy(&buf).to_string();
        let code: u16 = text.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(502);
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.trim().to_string()).unwrap_or_default();
        Some((code, body))
    };
    match tokio::time::timeout(Duration::from_secs(30), run).await {
        Ok(Some((200, addr))) if !addr.is_empty() => Ok(addr),
        Ok(Some((code, _))) => Err(code),
        _ => Err(504),
    }
}

// decode undoes the %XX of a path; none where it then holds a NUL or goes up out of where it is.
fn decode(path: &str) -> Option<String> {
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..(i + 3).min(b.len())]).ok()?, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    let s = String::from_utf8(out).ok()?;
    if s.contains('\0') || s.split('/').any(|seg| seg == "..") {
        return None;
    }
    Some(s)
}

// drain reads what is left of a request's body, so that an answer given
// before it was read does not cut the visitor off in the middle of sending.
async fn drain(session: &mut Session) {
    let mut left: usize = 64 << 20;
    while let Ok(Some(chunk)) = session.read_request_body().await {
        left = left.saturating_sub(chunk.len());
        if left == 0 {
            break;
        }
    }
}

async fn plain(session: &mut Session, code: u16, text: &str) -> Result<bool> {
    drain(session).await;
    let mut h = ResponseHeader::build(code, None)?;
    h.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    h.insert_header("Content-Length", text.len().to_string())?;
    session.write_response_header(Box::new(h), false).await?;
    session.write_response_body(Some(Bytes::from(text.to_string())), true).await?;
    Ok(true)
}

async fn redirect(session: &mut Session, code: u16, to: &str) -> Result<bool> {
    drain(session).await;
    let mut h = ResponseHeader::build(code, None)?;
    h.insert_header("Location", to.to_string())?;
    h.insert_header("Content-Length", "0")?;
    session.write_response_header(Box::new(h), true).await?;
    Ok(true)
}

fn io_err(what: &'static str, e: std::io::Error) -> Box<pingora::Error> {
    pingora::Error::because(pingora::ErrorType::InternalError, what, e)
}

impl Entry {
    // file sends a file of the site, a part of it where a part is asked for.
    async fn file(&self, session: &mut Session, route: &Route, rel: &str) -> Result<bool> {
        let Ok(f) = files::open(&route.root, rel, libc::O_RDONLY) else {
            return plain(session, 404, "not found\n").await;
        };
        let meta = f.metadata().map_err(|e| io_err("stat", e))?;
        let size = meta.len();
        let mtime = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        let etag = format!("\"{mtime:x}-{size:x}\"");
        let get = |name: &str| session.req_header().headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
        if get("if-none-match").as_deref() == Some(etag.as_str()) {
            let mut h = ResponseHeader::build(304, None)?;
            h.insert_header("ETag", etag)?;
            session.write_response_header(Box::new(h), true).await?;
            return Ok(true);
        }
        // "bytes=a-b", "bytes=a-" or "bytes=-n": one part.
        let mut part: Option<(u64, u64)> = None;
        if let Some(r) = get("range").and_then(|r| r.strip_prefix("bytes=").map(str::to_string)) {
            if let Some((a, b)) = r.split_once('-') {
                part = match (a.parse::<u64>(), b.parse::<u64>()) {
                    (Ok(a), Ok(b)) if a <= b && a < size => Some((a, b.min(size - 1))),
                    (Ok(a), Err(_)) if b.is_empty() && a < size => Some((a, size - 1)),
                    (Err(_), Ok(n)) if a.is_empty() && n > 0 => Some((size.saturating_sub(n), size - 1)),
                    _ => None,
                };
                if part.is_none() {
                    let mut h = ResponseHeader::build(416, None)?;
                    h.insert_header("Content-Range", format!("bytes */{size}"))?;
                    h.insert_header("Content-Length", "0")?;
                    session.write_response_header(Box::new(h), true).await?;
                    return Ok(true);
                }
            }
        }
        let (from, to) = part.unwrap_or((0, size.saturating_sub(1)));
        let len = if size == 0 { 0 } else { to - from + 1 };
        let mut h = ResponseHeader::build(if part.is_some() { 206 } else { 200 }, None)?;
        h.insert_header("Content-Type", files::mime(rel))?;
        h.insert_header("Content-Length", len.to_string())?;
        h.insert_header("ETag", etag)?;
        h.insert_header("Accept-Ranges", "bytes")?;
        if part.is_some() {
            h.insert_header("Content-Range", format!("bytes {from}-{to}/{size}"))?;
        }
        let head = session.req_header().method.as_str() == "HEAD";
        session.write_response_header(Box::new(h), head || len == 0).await?;
        if head || len == 0 {
            return Ok(true);
        }
        let mut f = tokio::fs::File::from_std(f);
        f.seek(std::io::SeekFrom::Start(from)).await.map_err(|e| io_err("seek", e))?;
        let mut left = len;
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let want = (buf.len() as u64).min(left) as usize;
            let n = f.read(&mut buf[..want]).await.map_err(|e| io_err("read", e))?;
            if n == 0 {
                break;
            }
            left -= n as u64;
            session.write_response_body(Some(Bytes::copy_from_slice(&buf[..n])), left == 0).await?;
        }
        Ok(true)
    }

    // php hands the request to the site's PHP-FPM and sends on what it answers.
    #[allow(clippy::too_many_arguments)]
    async fn php(&self, session: &mut Session, route: &Route, fcgi_addr: &str, host: &str, script: &str, path_info: &str, query: &str, uri: &str) -> Result<bool> {
        let req = session.req_header();
        // What the visitor asked for, with its port: over HTTP/2 there is no
        // Host header, the name comes as the request's authority.
        let authority = req.uri.authority().map(|a| a.as_str().to_string()).or_else(|| req.headers.get("host").and_then(|h| h.to_str().ok()).map(str::to_string)).unwrap_or_else(|| host.to_string());
        let port = authority.rsplit_once(':').map(|(_, p)| p.to_string()).filter(|p| p.parse::<u16>().is_ok()).unwrap_or_else(|| "443".into());
        let mut p: Vec<(String, String)> = vec![
            ("GATEWAY_INTERFACE".into(), "CGI/1.1".into()),
            // Programs look here to know what the server can do: WordPress
            // writes its rules into .htaccess only for one it takes for Apache.
            ("SERVER_SOFTWARE".into(), "Apache (compatible; sites-entry)".into()),
            ("SERVER_PROTOCOL".into(), "HTTP/1.1".into()),
            ("REQUEST_METHOD".into(), req.method.as_str().into()),
            ("REQUEST_SCHEME".into(), "https".into()),
            ("HTTPS".into(), "on".into()),
            ("REQUEST_URI".into(), uri.into()),
            ("QUERY_STRING".into(), query.into()),
            ("DOCUMENT_ROOT".into(), route.fpm_root.clone()),
            ("SCRIPT_FILENAME".into(), format!("{}{}", route.fpm_root, script)),
            ("SCRIPT_NAME".into(), format!("{}{}", route.prefix, script)),
            ("DOCUMENT_URI".into(), format!("{}{}{}", route.prefix, script, path_info)),
            ("SERVER_NAME".into(), host.into()),
            // The port the visitor came to: WordPress builds the address it
            // was asked for from it, and redirects to itself for ever where
            // it is not the one in the Host header.
            ("SERVER_PORT".into(), port),
            ("REDIRECT_STATUS".into(), "200".into()),
        ];
        if !path_info.is_empty() {
            p.push(("PATH_INFO".into(), path_info.into()));
        }
        if let Some(a) = session.client_addr() {
            let a = a.to_string();
            let (ip, port) = a.rsplit_once(':').unwrap_or((a.as_str(), "0"));
            p.push(("REMOTE_ADDR".into(), ip.trim_matches(|c| c == '[' || c == ']').into()));
            p.push(("REMOTE_PORT".into(), port.into()));
        }
        for (k, v) in req.headers.iter() {
            let Ok(v) = v.to_str() else { continue };
            match k.as_str() {
                "content-type" => p.push(("CONTENT_TYPE".into(), v.into())),
                "content-length" => p.push(("CONTENT_LENGTH".into(), v.into())),
                // What a visitor must not set for the page.
                "proxy" => {}
                name => p.push((format!("HTTP_{}", name.to_uppercase().replace('-', "_")), v.into())),
            }
        }
        if req.headers.get("host").is_none() {
            p.push(("HTTP_HOST".into(), authority));
        }
        let h2 = format!("{:?}", req.version).contains("2");
        let Ok(mut conn) = fcgi::begin(fcgi_addr, &p).await else {
            return plain(session, 502, "the site's PHP does not answer\n").await;
        };
        while let Some(chunk) = session.read_request_body().await? {
            conn.stdin(&chunk).await.map_err(|e| io_err("to php", e))?;
        }
        conn.end_stdin().await.map_err(|e| io_err("to php", e))?;
        let reply = match conn.headers().await {
            Ok(r) => r,
            Err(_) => return plain(session, 502, "the site's PHP gave no answer\n").await,
        };
        let mut h = ResponseHeader::build(reply.status, None)?;
        let mut sized = false;
        for (k, v) in reply.headers {
            sized |= k.eq_ignore_ascii_case("content-length");
            h.append_header(k, v)?;
        }
        // Its length is not known before it ends: sent in chunks, the connection kept.
        if !sized && !h2 {
            h.insert_header("Transfer-Encoding", "chunked")?;
        }
        session.write_response_header(Box::new(h), false).await?;
        while let Some(chunk) = conn.body().await.map_err(|e| io_err("from php", e))? {
            session.write_response_body(Some(Bytes::from(chunk)), false).await?;
        }
        session.write_response_body(None, true).await?;
        Ok(true)
    }
}

#[async_trait]
impl ProxyHttp for Entry {
    type CTX = Option<String>;
    fn new_ctx(&self) -> Self::CTX {
        None
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        let host = req
            .uri
            .host()
            .map(str::to_string)
            .or_else(|| req.headers.get("host").and_then(|h| h.to_str().ok()).map(str::to_string))
            .unwrap_or_default();
        let host = host.split(':').next().unwrap_or("").to_lowercase();
        let raw_path = req.uri.path().to_string();
        let query = req.uri.query().unwrap_or("").to_string();
        let uri = if query.is_empty() { raw_path.clone() } else { format!("{raw_path}?{query}") };
        // A certificate being issued is proved over plain HTTP: to the agent, which keeps the answers.
        if raw_path.starts_with("/.well-known/acme-challenge/") {
            *ctx = Some(self.agent.clone());
            return Ok(false);
        }
        if !self.tls {
            return redirect(session, 301, &format!("https://{host}{uri}")).await;
        }
        let Some(path) = decode(&raw_path) else {
            return plain(session, 400, "bad path\n").await;
        };
        let route = self.table.read().unwrap().routes.iter().find(|r| r.host == host && (r.prefix.is_empty() || path == r.prefix || path.starts_with(&format!("{}/", r.prefix)))).cloned();
        let Some(route) = route else {
            return plain(session, 404, "no such site\n").await;
        };
        // The folder of a site under a prefix, asked for without its slash.
        if path == route.prefix && !route.prefix.is_empty() {
            return redirect(session, 301, &format!("{path}/{}", if query.is_empty() { String::new() } else { format!("?{query}") })).await;
        }
        match route.off.as_str() {
            "" => {}
            "expired" => return plain(session, 403, "this site has expired\n").await,
            _ => return plain(session, 403, "this site is off\n").await,
        }
        // The rules see the path inside the site.
        let inside = path[route.prefix.len()..].to_string();
        let headers = req.headers.clone();
        let header = move |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let rules = if route.auto { htaccess(&self.rules, &route.root) } else { route.rules.clone() };
        let outcome = rewrite::apply(&rules, &rewrite::Req { path: inside, query, host: &host, https: true, root: &route.root, header: &header });
        let (mut rel, query) = match outcome {
            rewrite::Outcome::Redirect(code, to) => {
                let to = if to.starts_with('/') { format!("{}{to}", route.prefix) } else { to };
                return redirect(session, code, &to).await;
            }
            rewrite::Outcome::Status(code) => return plain(session, code, "refused by the site's rules\n").await,
            rewrite::Outcome::Pass(p, q) => (p, q),
        };
        // Nothing whose name begins with a dot is given out: .htaccess, .user.ini, .git.
        if rel.split('/').any(|seg| seg.starts_with('.') && seg != ".well-known") || rel.split('/').any(|seg| seg == "..") {
            return plain(session, 403, "not for reading\n").await;
        }
        let mut path_info = String::new();
        match files::kind(&route.root, &rel) {
            Some(files::Kind::File) => {}
            Some(files::Kind::Dir) => {
                if !rel.ends_with('/') {
                    return redirect(session, 301, &format!("{}{rel}/{}", route.prefix, if query.is_empty() { String::new() } else { format!("?{query}") })).await;
                }
                let index = ["index.php", "index.html", "index.htm"].iter().find(|i| files::kind(&route.root, &format!("{rel}{i}")) == Some(files::Kind::File));
                match index {
                    Some(i) => rel = format!("{rel}{i}"),
                    None => return plain(session, 403, "no index here\n").await,
                }
            }
            None => {
                // A script with more of a path after it: /index.php/a/b.
                let cut = rel.find(".php/").map(|i| i + 4);
                match cut {
                    Some(i) if files::kind(&route.root, &rel[..i]) == Some(files::Kind::File) => {
                        path_info = rel[i..].to_string();
                        rel.truncate(i);
                    }
                    _ => return plain(session, 404, "not found\n").await,
                }
            }
        }
        if rel.ends_with(".php") {
            if route.env.is_empty() {
                return plain(session, 403, "this site runs no PHP\n").await;
            }
            let addr = match ask(&self.agent, &route.env).await {
                Ok(a) => a,
                Err(423) => return plain(session, 403, "this site's environment is off\n").await,
                Err(_) => return plain(session, 503, "the site is starting or cannot be started, try again\n").await,
            };
            *ctx = Some(format!("php {}{}", route.env, rel));
            return self.php(session, &route, &addr, &host, &rel, &path_info, &query, &uri).await;
        }
        *ctx = Some(format!("file {rel}"));
        self.file(session, &route, &rel).await
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(ctx.clone().unwrap_or_default(), false, String::new())))
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora::Error>, ctx: &mut Self::CTX) {
        let code = session.response_written().map_or(0, |r| r.status.as_u16());
        info!("{} -> {} {}", self.request_summary(session, ctx), ctx.clone().unwrap_or_default(), code);
    }
}

// changed is when what the agent wrote last changed: the routes or the certificates.
fn changed(dir: &str) -> Option<SystemTime> {
    let a = std::fs::metadata(format!("{dir}/entry.json")).and_then(|m| m.modified()).ok();
    let b = std::fs::metadata(format!("{dir}/certs")).and_then(|m| m.modified()).ok();
    a.max(b)
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let dir = setting("SITES_DIR", "/var/lib/sites");
    let agent = setting("SITES_AGENT", "127.0.0.1:7071");
    let table: Shared = Arc::new(RwLock::new(load(&dir)));
    // Read again as the agent writes: a certificate or a route is there within a second, without a restart.
    let again = table.clone();
    let watched = dir.clone();
    std::thread::spawn(move || {
        let mut last = changed(&watched);
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let now = changed(&watched);
            if now != last {
                last = now;
                let t = load(&watched);
                info!("read again: {} routes, {} certificates", t.routes.len(), t.certs.len());
                *again.write().unwrap() = t;
            }
        }
    });
    let rules: Rules = Arc::new(Mutex::new(HashMap::new()));

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut https = http_proxy_service(&server.configuration, Entry { table: table.clone(), tls: true, agent: agent.clone(), rules: rules.clone() });
    let mut settings = TlsSettings::with_callbacks(Box::new(Certs(table.clone()))).unwrap();
    settings.enable_h2();
    https.add_tls_with_settings(&setting("SITES_HTTPS", "0.0.0.0:443"), None, settings);
    server.add_service(https);

    let mut http = http_proxy_service(&server.configuration, Entry { table, tls: false, agent, rules });
    http.add_tcp(&setting("SITES_HTTP", "0.0.0.0:80"));
    server.add_service(http);

    if files::kind(std::path::Path::new("/"), "/").is_none() || files::FALLBACK.load(std::sync::atomic::Ordering::Relaxed) {
        warn!("openat2 is not to be had here: files are checked the slower way");
    }
    server.run_forever();
}
