// The second trial of the entry of "my sites" (docs/requirements/53): the
// entry is the web server. It chooses the certificate by the name asked
// for, finds the site by host and the longest path prefix, applies the
// site's rewrite rules (Apache's, nginx's or IIS's, read into one form),
// serves files itself and hands PHP to the site's environment, which is
// PHP-FPM alone, over FastCGI. Before that it asks the backend, which
// starts the environment where it is not running.

mod fcgi;
mod files;
mod rewrite;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use log::{info, warn};
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const DIR: &str = "/poc";
const BACKEND: &str = "127.0.0.1:18090";

#[derive(Clone)]
struct Route {
    host: String,
    prefix: String,
    env: String,
    // Where its PHP-FPM listens; "-" for a site of files alone.
    fcgi: String,
    // The site's folder as the entry sees it, and as its environment does.
    root: PathBuf,
    fpm_root: String,
    rules: Arc<rewrite::Rules>,
}

#[derive(Default)]
struct Table {
    certs: HashMap<String, (X509, PKey<Private>)>,
    routes: Vec<Route>,
}

type Shared = Arc<RwLock<Table>>;

// rules_of reads a site's rules: "auto" is the .htaccess in its folder;
// else a file, read by its ending (.nginx, .config for IIS, else Apache's).
fn rules_of(root: &PathBuf, source: &str) -> rewrite::Rules {
    let path = if source == "auto" { root.join(".htaccess") } else { PathBuf::from(source) };
    let Ok(text) = std::fs::read_to_string(&path) else { return rewrite::Rules::default() };
    let name = path.to_string_lossy();
    if name.ends_with(".nginx") {
        rewrite::nginx(&text)
    } else if name.ends_with(".config") {
        rewrite::iis(&text)
    } else {
        rewrite::htaccess(&text, "/")
    }
}

// load reads the certificates and the routes: a line each of
// "host prefix environment fcgi-address folder folder-in-environment rules".
fn load(told: &mut HashMap<String, usize>) -> Table {
    let mut t = Table::default();
    if let Ok(dir) = std::fs::read_dir(format!("{DIR}/certs")) {
        for e in dir.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("crt") {
                continue;
            }
            let name = p.file_stem().unwrap().to_string_lossy().to_string();
            let (Ok(c), Ok(k)) = (std::fs::read(&p), std::fs::read(p.with_extension("key"))) else { continue };
            if let (Ok(c), Ok(k)) = (X509::from_pem(&c), PKey::private_key_from_pem(&k)) {
                t.certs.insert(name, (c, k));
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string(format!("{DIR}/routes.txt")) {
        for line in s.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() != 7 || line.starts_with('#') {
                continue;
            }
            let root = PathBuf::from(f[4]);
            let rules = rules_of(&root, f[6]);
            // What of a site's rules was passed over is said once.
            let key = format!("{}{}", f[0], f[1]);
            if told.get(&key) != Some(&rules.skipped.len()) {
                told.insert(key, rules.skipped.len());
                for s in &rules.skipped {
                    warn!("{}{}: rule passed over: {s}", f[0], f[1]);
                }
            }
            t.routes.push(Route { host: f[0].into(), prefix: f[1].trim_end_matches('/').into(), env: f[2].into(), fcgi: f[3].into(), root, fpm_root: f[5].into(), rules: Arc::new(rules) });
        }
    }
    // The longest prefix first.
    t.routes.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));
    t
}

struct Certs(Shared);

#[async_trait]
impl pingora::listeners::TlsAccept for Certs {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let name = ssl.servername(NameType::HOST_NAME).unwrap_or("").to_lowercase();
        let found = self.0.read().unwrap().certs.get(&name).cloned();
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
}

// ask asks the backend whether an environment can take requests: it starts
// the environment where it is not running and answers once it is.
async fn ask(env: &str) -> bool {
    let run = async {
        let mut s = tokio::net::TcpStream::connect(BACKEND).await.ok()?;
        s.write_all(format!("GET /ask?env={env} HTTP/1.0\r\nHost: backend\r\n\r\n").as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        Some(buf.starts_with(b"HTTP/1.0 200") || buf.starts_with(b"HTTP/1.1 200"))
    };
    matches!(tokio::time::timeout(Duration::from_secs(30), run).await, Ok(Some(true)))
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
    async fn php(&self, session: &mut Session, route: &Route, host: &str, script: &str, path_info: &str, query: &str, uri: &str) -> Result<bool> {
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
        let Ok(mut conn) = fcgi::begin(&route.fcgi, &p).await else {
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
        // A certificate being issued is proved over plain HTTP: to the backend, as it is.
        if raw_path.starts_with("/.well-known/acme-challenge/") {
            *ctx = Some(BACKEND.to_string());
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
        if route.fcgi != "-" && !ask(&route.env).await {
            return plain(session, 503, "the site is starting or cannot be started, try again\n").await;
        }
        // The rules see the path inside the site.
        let inside = path[route.prefix.len()..].to_string();
        let headers = req.headers.clone();
        let header = move |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let outcome = rewrite::apply(&route.rules, &rewrite::Req { path: inside, query, host: &host, https: true, root: &route.root, header: &header });
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
            if route.fcgi == "-" {
                return plain(session, 403, "this site runs no PHP\n").await;
            }
            *ctx = Some(format!("php {}{}", route.env, rel));
            return self.php(session, &route, &host, &rel, &path_info, &query, &uri).await;
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

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let mut told = HashMap::new();
    let table: Shared = Arc::new(RwLock::new(load(&mut told)));
    // Read again every two seconds: a certificate, a route or a site's rules changed are there without a restart.
    let again = table.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        let t = load(&mut told);
        *again.write().unwrap() = t;
    });

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut https = http_proxy_service(&server.configuration, Entry { table: table.clone(), tls: true });
    let mut settings = TlsSettings::with_callbacks(Box::new(Certs(table.clone()))).unwrap();
    settings.enable_h2();
    https.add_tls_with_settings("0.0.0.0:18443", None, settings);
    server.add_service(https);

    let mut http = http_proxy_service(&server.configuration, Entry { table, tls: false });
    http.add_tcp("0.0.0.0:18080");
    server.add_service(http);

    if files::kind(std::path::Path::new("/"), "/").is_none() || files::FALLBACK.load(std::sync::atomic::Ordering::Relaxed) {
        warn!("openat2 is not to be had here: files are checked the slower way");
    }
    server.run_forever();
}
