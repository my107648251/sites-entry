// Files of a site, opened so that nothing outside the site's folder is
// ever reached: a link in it that leads out (to another site's files, to
// the system's) is refused by the kernel itself (openat2, RESOLVE_BENEATH).

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(PartialEq, Clone, Copy)]
pub enum Kind {
    File,
    Dir,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;

// Whether the kernel's way is not to be had here, and the slower check is used.
pub static FALLBACK: AtomicBool = AtomicBool::new(false);

// open opens rel, a path with a leading slash, inside root.
pub fn open(root: &Path, rel: &str, flags: i32) -> io::Result<File> {
    let rel = rel.trim_start_matches('/');
    let rel = if rel.is_empty() { "." } else { rel };
    let c_root = CString::new(root.as_os_str().as_bytes())?;
    let c_rel = CString::new(rel)?;
    unsafe {
        let dir = libc::open(c_root.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC);
        if dir < 0 {
            return Err(io::Error::last_os_error());
        }
        let how = OpenHow { flags: (flags | libc::O_CLOEXEC) as u64, mode: 0, resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS };
        let fd = libc::syscall(libc::SYS_openat2, dir, c_rel.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>());
        let err = io::Error::last_os_error();
        libc::close(dir);
        if fd >= 0 {
            return Ok(File::from_raw_fd(fd as i32));
        }
        match err.raw_os_error() {
            // No such call here (an old kernel, or a sandbox that forbids it): the paths are compared instead.
            Some(libc::ENOSYS) | Some(libc::EPERM) => {}
            _ => return Err(err),
        }
    }
    FALLBACK.store(true, Ordering::Relaxed);
    let real_root = root.canonicalize()?;
    let real = real_root.join(rel).canonicalize()?;
    if !real.starts_with(&real_root) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "outside the site"));
    }
    std::fs::OpenOptions::new().read(true).custom_flags_path(flags).open(real)
}

trait PathFlags {
    fn custom_flags_path(&mut self, flags: i32) -> &mut Self;
}

impl PathFlags for std::fs::OpenOptions {
    fn custom_flags_path(&mut self, flags: i32) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(flags & !libc::O_ACCMODE)
    }
}

// kind says what rel is inside root: a file, a folder, or neither (also
// when it leads out of root).
pub fn kind(root: &Path, rel: &str) -> Option<Kind> {
    let f = open(root, rel, libc::O_PATH).ok()?;
    let m = f.metadata().ok()?;
    if m.is_file() {
        Some(Kind::File)
    } else if m.is_dir() {
        Some(Kind::Dir)
    } else {
        None
    }
}

pub fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "mp4" => "video/mp4",
        _ => "application/octet-stream",
    }
}

/// What a file is given out as (docs/requirements/53, M-1 to M-5).
#[derive(Debug, PartialEq)]
pub enum Type {
    /// Given out, as this type.
    Is(String),
    /// A script's ending other than .php (.phtml, .phar, .php5): never given out as a file.
    Script,
    /// An ending neither the platform's table nor the site's has: not given out.
    Unknown,
}

fn script(ending: &str) -> bool {
    matches!(ending, "phtml" | "pht" | "phps" | "phar") || (ending.len() == 4 && ending.starts_with("php") && ending.as_bytes()[3].is_ascii_digit())
}

/// The kind of a file by the ending of its name, as IIS does it: the site's
/// own table first, then the platform's; an ending in neither is not given
/// out, nor a name with no ending (but for what is under /.well-known/,
/// which has none by custom). Where the entry was told no table (an agent
/// from before there was one) every file goes out as before.
pub fn kind_of(rel: &str, platform: Option<&std::collections::HashMap<String, String>>, site: &std::collections::HashMap<String, String>) -> Type {
    let name = rel.rsplit('/').next().unwrap_or("");
    let ending = match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => name[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    };
    if script(&ending) {
        return Type::Script;
    }
    let Some(platform) = platform else {
        return Type::Is(mime(rel).to_string());
    };
    if ending.is_empty() {
        return if rel.starts_with("/.well-known/") { Type::Is("text/plain; charset=utf-8".into()) } else { Type::Unknown };
    }
    match site.get(&ending).or_else(|| platform.get(&ending)) {
        Some(t) => Type::Is(t.clone()),
        None => Type::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn kinds() {
        let platform: HashMap<String, String> = [("html", "text/html; charset=utf-8"), ("png", "image/png")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let site: HashMap<String, String> = [("dat", "application/octet-stream"), ("png", "image/x-mine")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let none = HashMap::new();
        let k = |rel: &str| kind_of(rel, Some(&platform), &site);
        assert_eq!(k("/index.html"), Type::Is("text/html; charset=utf-8".into()));
        assert_eq!(k("/a/B.HTML"), Type::Is("text/html; charset=utf-8".into()));
        // The site's own: one more ending, and its say over the platform's.
        assert_eq!(k("/x.dat"), Type::Is("application/octet-stream".into()));
        assert_eq!(k("/x.png"), Type::Is("image/x-mine".into()));
        assert_eq!(kind_of("/x.dat", Some(&platform), &none), Type::Unknown);
        // Not in either table: not given out.
        for rel in ["/db.sql", "/site.bak", "/conf.inc", "/a.tar.xz", "/LICENSE", "/dir.d/readme", "/trailing."] {
            assert_eq!(k(rel), Type::Unknown, "{rel}");
        }
        // A script's ending: never, though a site's table had it.
        let sly: HashMap<String, String> = [("phtml", "text/plain"), ("php5", "text/plain")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        for rel in ["/a.phtml", "/a.PHAR", "/a.php5", "/a.pht", "/a.phps"] {
            assert_eq!(kind_of(rel, Some(&platform), &sly), Type::Script, "{rel}");
            assert_eq!(kind_of(rel, None, &none), Type::Script, "{rel}");
        }
        // No ending under /.well-known/: given out as text.
        assert_eq!(k("/.well-known/apple-app-site-association"), Type::Is("text/plain; charset=utf-8".into()));
        // No table told: as before, whatever the ending.
        assert_eq!(kind_of("/db.sql", None, &none), Type::Is("application/octet-stream".into()));
        assert_eq!(kind_of("/a.css", None, &none), Type::Is("text/css".into()));
    }
}
