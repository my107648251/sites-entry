// The entry of "my sites" (docs/requirements/53 of tominadev/incus): the
// web server in front of every user's site on a host. It chooses the
// certificate by the name asked for, finds the site by host and the longest
// path prefix (plain HTTP is answered too, or sent to https where the
// name has a certificate; another name of a site is sent to the one it is
// reached at), applies the site's rewrite rules (Apache's, nginx's or IIS's,
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
mod logs;
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
    // https: a request over plain HTTP is sent to https (the name has a certificate).
    https: bool,
    // to: every request to this name is sent to that one (www and the name without it).
    to: String,
    // site: what the site is called in the access logs and the traffic
    // counted ("w12"); empty: neither is kept.
    site: String,
    // What a request to its PHP may be (docs/requirements/53, G-1), from its
    // environment: the most a body may be (bytes), how long PHP may take to
    // answer (seconds), how many requests may be at its PHP at once. 0: the
    // entry's own (DEFAULT_*).
    max_body: u64,
    timeout: u64,
    conns: u32,
    // proxy: the route is sent on to an instance of the site's user, at this
    // "address:port" (plain HTTP inside); no folder, no PHP of its own.
    proxy: String,
    // mimes: the kinds of files its site gives out besides the platform's,
    // the ending of a name to its type (M-3).
    mimes: HashMap<String, String>,
}

const DEFAULT_MAX_BODY: u64 = 8 << 20;
const DEFAULT_TIMEOUT: u64 = 60;
const DEFAULT_CONNS: u32 = 4;

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
    https: bool,
    to: String,
    site: String,
    max_body: u64,
    timeout: Duration,
    conns: u32,
    proxy: String,
    mimes: Arc<HashMap<String, String>>,
}

#[derive(Default)]
struct Table {
    certs: HashMap<String, (X509, PKey<Private>)>,
    routes: Vec<Route>,
    // The platform's table of the kinds of files given out, the ending of a
    // name to its type (mime.json, M-1); none: the agent told none, and
    // every file goes out as before there was a table.
    mimes: Option<Arc<HashMap<String, String>>>,
    // The page for a name no site has (nosite.html, M-6); none: a line of text.
    nosite: Option<Bytes>,
}

type Shared = Arc<RwLock<Table>>;

/// The .htaccess of the sites' folders as last read, by folder, with the
/// moment the file was changed then (none: there was no file).
type Rules = Arc<Mutex<HashMap<PathBuf, (Option<SystemTime>, Arc<rewrite::Rules>)>>>;

// htaccess gives the rules of the .htaccess in a folder (at base in the
// site), read again where the file changed since it was last read.
fn htaccess(cache: &Rules, root: &Path, base: &str) -> Arc<rewrite::Rules> {
    let file = root.join(".htaccess");
    let changed = std::fs::metadata(&file).and_then(|m| m.modified()).ok();
    if let Some((at, r)) = cache.lock().unwrap().get(root) {
        if *at == changed {
            return r.clone();
        }
    }
    let r = Arc::new(match std::fs::read_to_string(&file) {
        Ok(text) => {
            let r = rewrite::htaccess(&text, base);
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

// htaccess_at gives the rules for a path of a site, as Apache does in its
// folders: of the folders the path goes through (that are folders of the
// site), the deepest whose .htaccess turns rewriting on, its rules for
// what is under it. With the folder they are of, from the site's top.
fn htaccess_at(cache: &Rules, root: &Path, path: &str) -> (Arc<rewrite::Rules>, String) {
    let mut found = (htaccess(cache, root, "/"), "/".to_string());
    if !found.0.on {
        found.0 = Arc::new(rewrite::Rules::default());
    }
    let mut rel = String::from("/");
    for seg in path.trim_start_matches('/').split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            break;
        }
        rel = format!("{rel}{seg}/");
        // A folder of the site, not one a link leads out of it to.
        if files::kind(root, &rel) != Some(files::Kind::Dir) {
            break;
        }
        let r = htaccess(cache, &root.join(rel.trim_start_matches('/')), &rel);
        if r.on {
            found = (r, rel.clone());
        }
    }
    found
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
            https: r.https,
            to: r.to.to_lowercase(),
            // A name for a file: letters and digits only.
            site: if !r.site.is_empty() && r.site.len() <= 32 && r.site.bytes().all(|b| b.is_ascii_alphanumeric()) { r.site } else { String::new() },
            max_body: if r.max_body == 0 { DEFAULT_MAX_BODY } else { r.max_body },
            timeout: Duration::from_secs(if r.timeout == 0 { DEFAULT_TIMEOUT } else { r.timeout.min(3600) }),
            conns: if r.conns == 0 { DEFAULT_CONNS } else { r.conns.min(1024) },
            // An address and a port, or nothing.
            proxy: r.proxy.parse::<std::net::SocketAddrV4>().map(|a| a.to_string()).unwrap_or_default(),
            mimes: Arc::new(r.mimes.into_iter().map(|(k, v)| (k.to_ascii_lowercase(), v)).collect()),
        });
    }
    // The platform's table, and the page for a name no site has: what the agent wrote, where it did.
    if let Ok(b) = std::fs::read(format!("{dir}/mime.json")) {
        match serde_json::from_slice::<HashMap<String, String>>(&b) {
            Ok(m) => t.mimes = Some(Arc::new(m.into_iter().map(|(k, v)| (k.to_ascii_lowercase(), v)).collect())),
            Err(e) => warn!("mime.json: {e}"),
        }
    }
    if let Ok(b) = std::fs::read(format!("{dir}/nosite.html")) {
        if !b.is_empty() && b.len() <= 256 << 10 {
            t.nosite = Some(Bytes::from(b));
        }
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
    // The kept connections to the environments' PHP-FPM.
    pool: Arc<fcgi::Pool>,
    // How many requests may be at each environment's PHP at once: its
    // number of workers, by environment.
    slots: Arc<Mutex<HashMap<String, (u32, Arc<tokio::sync::Semaphore>)>>>,
    log: Arc<logs::Logs>,
}

// What the entry knows of a request as it ends: where it went, for the
// log and the site's access log and traffic.
#[derive(Default)]
struct Ctx {
    // The agent, for a certificate's proof; nothing else goes upstream.
    peer: Option<String>,
    what: String,
    site: String,
    started: Option<std::time::Instant>,
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

// page is the site's own page for an answer the entry gives, at the top of
// its folder as nginx's are usually written: 404.html for 404, 50x.html for
// 500 and over. None where the site has none.
fn page(route: &Route, code: u16) -> Option<Vec<u8>> {
    use std::io::Read;
    let name = match code {
        404 => "/404.html",
        500..=599 => "/50x.html",
        _ => return None,
    };
    let mut f = files::open(&route.root, name, libc::O_RDONLY).ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() || m.len() > 1 << 20 {
        return None;
    }
    let mut b = Vec::new();
    f.read_to_end(&mut b).ok()?;
    Some(b)
}

// fail answers with an error of the entry's: the site's own page for it
// where it has one (G-2), else a line of text.
async fn fail(session: &mut Session, route: &Route, code: u16, text: &str) -> Result<bool> {
    let Some(body) = page(route, code) else {
        return plain(session, code, text).await;
    };
    drain(session).await;
    let mut h = ResponseHeader::build(code, None)?;
    h.insert_header("Content-Type", "text/html; charset=utf-8")?;
    h.insert_header("Content-Length", body.len().to_string())?;
    h.insert_header("Cache-Control", "no-store")?;
    session.write_response_header(Box::new(h), false).await?;
    session.write_response_body(Some(Bytes::from(body)), true).await?;
    Ok(true)
}

// too_large refuses a body over the site's limit without reading it: the
// connection is closed after the answer.
async fn too_large(session: &mut Session, route: &Route) -> Result<bool> {
    let text = format!("the request is larger than this site takes ({} MB)\n", route.max_body >> 20);
    session.set_keepalive(None);
    let mut h = ResponseHeader::build(413, None)?;
    h.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    h.insert_header("Content-Length", text.len().to_string())?;
    h.insert_header("Connection", "close")?;
    session.write_response_header(Box::new(h), false).await?;
    session.write_response_body(Some(Bytes::from(text)), true).await?;
    Ok(true)
}

// compressible says whether a file of this type is sent compressed to a
// visitor that takes it (Pingora's module decides by the same types).
fn compressible(mime: &str) -> bool {
    mime.starts_with("text/") || mime.contains("json") || mime.contains("xml") || mime.contains("javascript")
}

// cache_control is what a visitor's browser is told of keeping a file:
// pages are asked about again each time (their ETag answers 304 when
// unchanged), what pages are made of is kept a week.
fn cache_control(mime: &str) -> &'static str {
    if mime.starts_with("text/html") {
        "no-cache"
    } else if mime.starts_with("image/") || mime.starts_with("font/") || mime.starts_with("text/css") || mime.starts_with("text/javascript") || mime.starts_with("video/") {
        "public, max-age=604800"
    } else {
        "public, max-age=3600"
    }
}

// http_date writes a moment as HTTP does: Sun, 06 Nov 1994 08:49:37 GMT.
fn http_date(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{}, {d:02} {} {y} {h:02}:{mi:02}:{s:02} GMT", DAYS[((secs / 86400) % 7) as usize], MONTHS[mo as usize - 1])
}

// civil is a moment (seconds since 1970, UTC) as year, month, day, hour,
// minute, second (Howard Hinnant's days_from_civil, backwards).
fn civil(secs: u64) -> (i64, u32, u32, u64, u64, u64) {
    let z = (secs / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    let t = secs % 86400;
    (y, m, d, t / 3600, t % 3600 / 60, t % 60)
}

fn io_err(what: &'static str, e: std::io::Error) -> Box<pingora::Error> {
    pingora::Error::because(pingora::ErrorType::InternalError, what, e)
}

impl Entry {
    // file sends a file of the site, a part of it where a part is asked for.
    async fn file(&self, session: &mut Session, route: &Route, rel: &str, mime: &str) -> Result<bool> {
        let Ok(f) = files::open(&route.root, rel, libc::O_RDONLY) else {
            return fail(session, route, 404, "not found\n").await;
        };
        let meta = f.metadata().map_err(|e| io_err("stat", e))?;
        let size = meta.len();
        let mtime = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        let etag = format!("\"{mtime:x}-{size:x}\"");
        let modified = http_date(mtime);
        let get = |name: &str| session.req_header().headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
        // Unchanged since the visitor's copy: by its ETag, or where it sent none by the date.
        let same = match get("if-none-match") {
            Some(tags) => tags.split(',').any(|t| t.trim().trim_start_matches("W/") == etag),
            None => get("if-modified-since").as_deref() == Some(modified.as_str()),
        };
        if same {
            let mut h = ResponseHeader::build(304, None)?;
            h.insert_header("ETag", etag)?;
            h.insert_header("Last-Modified", modified)?;
            h.insert_header("Cache-Control", cache_control(mime))?;
            session.write_response_header(Box::new(h), true).await?;
            return Ok(true);
        }
        // A part of a file that goes out compressed cannot be given: all of it then (as a server may).
        let packed = compressible(mime) && get("accept-encoding").is_some_and(|a| a.contains("gzip") || a.contains("br") || a.contains("zstd"));
        // "bytes=a-b", "bytes=a-" or "bytes=-n": one part.
        let mut part: Option<(u64, u64)> = None;
        if let Some(r) = get("range").filter(|_| !packed).and_then(|r| r.strip_prefix("bytes=").map(str::to_string)) {
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
        h.insert_header("Content-Type", mime)?;
        h.insert_header("Content-Length", len.to_string())?;
        h.insert_header("ETag", etag)?;
        h.insert_header("Last-Modified", modified)?;
        h.insert_header("Cache-Control", cache_control(mime))?;
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
        let port = authority.rsplit_once(':').map(|(_, p)| p.to_string()).filter(|p| p.parse::<u16>().is_ok()).unwrap_or_else(|| if self.tls { "443" } else { "80" }.into());
        let mut p: Vec<(String, String)> = vec![
            ("GATEWAY_INTERFACE".into(), "CGI/1.1".into()),
            // Programs look here to know what the server can do: WordPress
            // writes its rules into .htaccess only for one it takes for Apache.
            ("SERVER_SOFTWARE".into(), "Apache (compatible; sites-entry)".into()),
            ("SERVER_PROTOCOL".into(), "HTTP/1.1".into()),
            ("REQUEST_METHOD".into(), req.method.as_str().into()),
            ("REQUEST_SCHEME".into(), if self.tls { "https" } else { "http" }.into()),
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
        if self.tls {
            p.push(("HTTPS".into(), "on".into()));
        }
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
        // A body larger than the site takes is refused before it is read.
        let said: u64 = req.headers.get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).unwrap_or(0);
        if said > route.max_body {
            return too_large(session, route).await;
        }
        // As many at its PHP at once as it has workers; the others wait their turn, a while.
        let slots = {
            let mut all = self.slots.lock().unwrap();
            let e = all.entry(route.env.clone()).or_insert_with(|| (route.conns, Arc::new(tokio::sync::Semaphore::new(route.conns as usize))));
            if e.0 != route.conns {
                *e = (route.conns, Arc::new(tokio::sync::Semaphore::new(route.conns as usize)));
            }
            e.1.clone()
        };
        let Ok(Ok(_slot)) = tokio::time::timeout(Duration::from_secs(30), slots.acquire_owned()).await else {
            return fail(session, route, 503, "the site is busy, try again\n").await;
        };
        let Ok(mut conn) = fcgi::begin(&self.pool, fcgi_addr, &p).await else {
            return fail(session, route, 502, "the site's PHP does not answer\n").await;
        };
        let mut sent: u64 = 0;
        while let Some(chunk) = session.read_request_body().await? {
            sent += chunk.len() as u64;
            if sent > route.max_body {
                return too_large(session, route).await;
            }
            conn.stdin(&chunk).await.map_err(|e| io_err("to php", e))?;
        }
        conn.end_stdin().await.map_err(|e| io_err("to php", e))?;
        let reply = match tokio::time::timeout(route.timeout, conn.headers()).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => return fail(session, route, 502, "the site's PHP gave no answer\n").await,
            Err(_) => return fail(session, route, 504, "the site's PHP took too long to answer\n").await,
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
        // Its answer ended: the connection takes the next request.
        self.pool.put(conn);
        Ok(true)
    }
}

#[async_trait]
impl ProxyHttp for Entry {
    type CTX = Ctx;
    // Text goes out compressed to a visitor that takes it: brotli, zstd or gzip (G-2).
    fn init_downstream_modules(&self, modules: &mut pingora::modules::http::HttpModules) {
        modules.add_module(pingora::modules::http::compression::ResponseCompressionBuilder::enable(5));
    }
    fn new_ctx(&self) -> Self::CTX {
        Ctx { started: Some(std::time::Instant::now()), ..Default::default() }
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
            ctx.peer = Some(self.agent.clone());
            ctx.what = "acme".into();
            return Ok(false);
        }
        let Some(path) = decode(&raw_path) else {
            return plain(session, 400, "bad path\n").await;
        };
        let route = self.table.read().unwrap().routes.iter().find(|r| r.host == host && (r.prefix.is_empty() || path == r.prefix || path.starts_with(&format!("{}/", r.prefix)))).cloned();
        let Some(route) = route else {
            // A name no site has: the platform's page for it where it gave one (M-6).
            let page = self.table.read().unwrap().nosite.clone();
            let Some(page) = page else {
                return plain(session, 404, "no such site\n").await;
            };
            ctx.what = "nosite".into();
            drain(session).await;
            let mut h = ResponseHeader::build(404, None)?;
            h.insert_header("Content-Type", "text/html; charset=utf-8")?;
            h.insert_header("Content-Length", page.len().to_string())?;
            h.insert_header("Cache-Control", "no-store")?;
            session.write_response_header(Box::new(h), false).await?;
            session.write_response_body(Some(page), true).await?;
            return Ok(true);
        };
        ctx.site = route.site.clone();
        // Another name of the site: the visitor goes to the one it is to be reached at.
        if !route.to.is_empty() {
            let scheme = if self.tls || route.https { "https" } else { "http" };
            return redirect(session, 301, &format!("{scheme}://{}{uri}", route.to)).await;
        }
        // Plain HTTP is answered as it is where the name has no certificate (yet).
        if !self.tls && route.https {
            return redirect(session, 301, &format!("https://{host}{uri}")).await;
        }
        // Sent on to an instance of its user: as it is asked for, to it.
        if !route.proxy.is_empty() {
            match route.off.as_str() {
                "" => {}
                "expired" => return plain(session, 403, "this site has expired\n").await,
                "held" => return plain(session, 403, "this site has been stopped\n").await,
                _ => return plain(session, 403, "this site is off\n").await,
            }
            ctx.peer = Some(route.proxy.clone());
            ctx.what = format!("proxy {}", route.proxy);
            return Ok(false);
        }
        // The folder of a site under a prefix, asked for without its slash.
        if path == route.prefix && !route.prefix.is_empty() {
            return redirect(session, 301, &format!("{path}/{}", if query.is_empty() { String::new() } else { format!("?{query}") })).await;
        }
        match route.off.as_str() {
            "" => {}
            "expired" => return plain(session, 403, "this site has expired\n").await,
            "held" => return plain(session, 403, "this site has been stopped\n").await,
            _ => return plain(session, 403, "this site is off\n").await,
        }
        // The rules see the path inside the site.
        let inside = path[route.prefix.len()..].to_string();
        let headers = req.headers.clone();
        let header = move |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let rules = if route.auto { htaccess_at(&self.rules, &route.root, &inside).0 } else { route.rules.clone() };
        let outcome = rewrite::apply(&rules, &rewrite::Req { path: inside, query, host: &host, https: self.tls, root: &route.root, header: &header });
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
                    None => return fail(session, &route, 404, "no index here\n").await,
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
                    _ => return fail(session, &route, 404, "not found\n").await,
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
                Err(_) => return fail(session, &route, 503, "the site is starting or cannot be started, try again\n").await,
            };
            ctx.what = format!("php {}{}", route.env, rel);
            return self.php(session, &route, &addr, &host, &rel, &path_info, &query, &uri).await;
        }
        // Given out by the ending of its name: in the site's table or the
        // platform's, or not at all (M-1 to M-5).
        let platform = self.table.read().unwrap().mimes.clone();
        let mime = match files::kind_of(&rel, platform.as_deref(), &route.mimes) {
            files::Type::Is(m) => m,
            files::Type::Script => return plain(session, 403, "not for reading\n").await,
            files::Type::Unknown => {
                ctx.what = format!("untyped {rel}");
                return fail(session, &route, 404, "this kind of file is not given out here\n").await;
            }
        };
        ctx.what = format!("file {rel}");
        self.file(session, &route, &rel, &mime).await
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(ctx.peer.clone().unwrap_or_default(), false, String::new())))
    }

    // What the instance a site is sent on to is told of the visitor: where
    // it came from, and whether over https; the name it asked for is kept.
    async fn upstream_request_filter(&self, session: &mut Session, upstream: &mut RequestHeader, _ctx: &mut Self::CTX) -> Result<()> {
        let ip = session.client_addr().map(|a| a.to_string()).unwrap_or_default();
        let ip = ip.rsplit_once(':').map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']').to_string()).unwrap_or(ip);
        let fwd = match upstream.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(before) => format!("{before}, {ip}"),
            None => ip.clone(),
        };
        upstream.insert_header("X-Forwarded-For", fwd)?;
        upstream.insert_header("X-Real-IP", ip)?;
        upstream.insert_header("X-Forwarded-Proto", if self.tls { "https" } else { "http" })?;
        // Over HTTP/2 the name comes as the authority: the instance is given it as Host.
        if upstream.headers.get("host").is_none() {
            if let Some(a) = upstream.uri.authority().map(|a| a.as_str().to_string()) {
                upstream.insert_header("Host", a)?;
            }
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora::Error>, ctx: &mut Self::CTX) {
        let code = session.response_written().map_or(0, |r| r.status.as_u16());
        info!("{} -> {} {}", self.request_summary(session, ctx), ctx.what, code);
        // The site's access log and traffic (G-5).
        if !ctx.site.is_empty() {
            let req = session.req_header();
            let get = |name: &str| req.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
            let ip = session.client_addr().map(|a| a.to_string()).unwrap_or_default();
            let ip = ip.rsplit_once(':').map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']').to_string()).unwrap_or(ip);
            let line = logs::Line {
                ip,
                method: req.method.as_str().to_string(),
                uri: req.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default(),
                version: format!("{:?}", req.version),
                status: code,
                sent: session.body_bytes_sent() as u64,
                read: session.body_bytes_read() as u64,
                referer: get("referer"),
                agent: get("user-agent"),
                ms: ctx.started.map_or(0, |s| s.elapsed().as_millis() as u64),
            };
            self.log.add(&ctx.site, &line);
        }
    }
}

// changed is when what the agent wrote last changed: the routes or the certificates.
fn changed(dir: &str) -> Option<SystemTime> {
    ["entry.json", "certs", "mime.json", "nosite.html"].iter().filter_map(|f| std::fs::metadata(format!("{dir}/{f}")).and_then(|m| m.modified()).ok()).max()
}

// cli is what the entry does from the command line, for the site agent to
// ask it (docs/requirements/53, step 5), its answer JSON on stdout:
//
//   sites-entry check nginx|iis|htaccess   < rules
//     the rules read, and the lines passed over
//   sites-entry try ROOT auto|nginx|iis PATH?QUERY HOST [http] < rules
//     what a request of the site whose folder is ROOT becomes: the rules
//     met, and whether the file it comes to is there
fn cli(args: &[String]) -> Option<i32> {
    use std::io::Read;
    let what = args.get(1)?.as_str();
    if what != "check" && what != "try" {
        return None;
    }
    let mut text = String::new();
    let _ = std::io::stdin().read_to_string(&mut text);
    let parse = |kind: &str| match kind {
        "nginx" => rewrite::nginx(&text),
        "iis" => rewrite::iis(&text),
        _ => rewrite::htaccess(&text, "/"),
    };
    if what == "check" {
        let r = parse(args.get(2).map(String::as_str).unwrap_or(""));
        println!("{}", serde_json::json!({ "rules": r.rules.len(), "on": r.on, "skipped": r.skipped }));
        return Some(0);
    }
    let (Some(root), Some(kind), Some(url)) = (args.get(2), args.get(3), args.get(4)) else {
        eprintln!("usage: sites-entry try ROOT auto|nginx|iis PATH?QUERY HOST [http]");
        return Some(2);
    };
    let host = args.get(5).cloned().unwrap_or_default();
    let https = args.get(6).map(String::as_str) != Some("http");
    let root = Path::new(root);
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let (rules, at) = if kind == "auto" {
        let cache: Rules = Arc::new(Mutex::new(HashMap::new()));
        htaccess_at(&cache, root, path)
    } else {
        (Arc::new(parse(kind)), String::new())
    };
    let header = |_: &str| String::new();
    let (out, met) = rewrite::trace(&rules, &rewrite::Req { path: path.to_string(), query: query.to_string(), host: &host, https, root, header: &header });
    let kind_of = |p: &str| match files::kind(root, p) {
        Some(files::Kind::File) => "file",
        Some(files::Kind::Dir) => "dir",
        None => "none",
    };
    let answer = match out {
        rewrite::Outcome::Pass(p, q) => serde_json::json!({ "outcome": "pass", "path": p, "query": q, "file": kind_of(&p), "met": met, "htaccess": at, "skipped": rules.skipped }),
        rewrite::Outcome::Redirect(code, to) => serde_json::json!({ "outcome": "redirect", "code": code, "to": to, "met": met, "htaccess": at, "skipped": rules.skipped }),
        rewrite::Outcome::Status(code) => serde_json::json!({ "outcome": "status", "code": code, "met": met, "htaccess": at, "skipped": rules.skipped }),
    };
    println!("{answer}");
    Some(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = cli(&args) {
        std::process::exit(code);
    }
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
    let pool = Arc::new(fcgi::Pool::default());
    let slots = Arc::new(Mutex::new(HashMap::new()));
    let log = Arc::new(logs::Logs::new(PathBuf::from(format!("{dir}/logs"))));
    log.clone().every(PathBuf::from(format!("{dir}/traffic.json")));

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut https = http_proxy_service(&server.configuration, Entry { table: table.clone(), tls: true, agent: agent.clone(), rules: rules.clone(), pool: pool.clone(), slots: slots.clone(), log: log.clone() });
    let mut settings = TlsSettings::with_callbacks(Box::new(Certs(table.clone()))).unwrap();
    settings.enable_h2();
    https.add_tls_with_settings(&setting("SITES_HTTPS", "0.0.0.0:443"), None, settings);
    server.add_service(https);

    let mut http = http_proxy_service(&server.configuration, Entry { table, tls: false, agent, rules, pool, slots, log });
    http.add_tcp(&setting("SITES_HTTP", "0.0.0.0:80"));
    server.add_service(http);

    if files::kind(std::path::Path::new("/"), "/").is_none() || files::FALLBACK.load(std::sync::atomic::Ordering::Relaxed) {
        warn!("openat2 is not to be had here: files are checked the slower way");
    }
    server.run_forever();
}
