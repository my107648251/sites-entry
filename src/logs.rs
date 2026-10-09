// What each site was asked for (docs/requirements/53, G-5): an access log of
// its own, in logs/<site>.log under the sites' folder (the combined format
// of Apache and nginx, with how long the answer took), turned over to
// <site>.log.1 at LOG_MAX; and its requests and bytes, counted since the
// entry started and written to traffic.json every half minute, for the
// panel to add up by the day (it tells a new start by "boot").

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LOG_MAX: u64 = 20 << 20;

pub struct Line {
    pub ip: String,
    pub method: String,
    pub uri: String,
    pub version: String,
    pub status: u16,
    pub sent: u64,
    pub read: u64,
    pub referer: String,
    pub agent: String,
    pub ms: u64,
}

#[derive(Default, Clone, Copy, serde::Serialize)]
pub struct Count {
    pub requests: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

pub struct Logs {
    dir: PathBuf,
    boot: u64,
    // Written through a buffer, put in the file every second (every).
    open: Mutex<HashMap<String, (BufWriter<File>, u64)>>,
    counts: Mutex<HashMap<String, Count>>,
}

// clean keeps a field of a log line on its line and within its quotes.
fn clean(s: &str) -> String {
    let s: String = s.chars().take(2000).map(|c| if c.is_control() { ' ' } else { c }).collect();
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// stamp writes a moment as access logs do: 09/Oct/2026:15:20:01 +0000.
fn stamp(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = crate::civil(secs);
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{d:02}/{}/{y}:{h:02}:{mi:02}:{s:02} +0000", MONTHS[mo as usize - 1])
}

pub fn format(l: &Line, now: u64) -> String {
    format!(
        "{} - - [{}] \"{} {} {}\" {} {} \"{}\" \"{}\" {}ms\n",
        clean(&l.ip),
        stamp(now),
        clean(&l.method),
        clean(&l.uri),
        clean(&l.version),
        l.status,
        l.sent,
        clean(&l.referer),
        clean(&l.agent),
        l.ms
    )
}

impl Logs {
    pub fn new(dir: PathBuf) -> Logs {
        let _ = std::fs::create_dir_all(&dir);
        let boot = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
        Logs { dir, boot, open: Mutex::new(HashMap::new()), counts: Mutex::new(HashMap::new()) }
    }

    // add counts a request of a site and writes it to the site's log.
    pub fn add(&self, site: &str, l: &Line) {
        {
            let mut c = self.counts.lock().unwrap();
            let c = c.entry(site.to_string()).or_default();
            c.requests += 1;
            c.bytes_out += l.sent;
            c.bytes_in += l.read;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let text = format(l, now);
        let mut open = self.open.lock().unwrap();
        let file = self.dir.join(format!("{site}.log"));
        if !open.contains_key(site) {
            let Ok(f) = OpenOptions::new().create(true).append(true).open(&file) else { return };
            let size = f.metadata().map(|m| m.len()).unwrap_or(0);
            open.insert(site.to_string(), (BufWriter::with_capacity(64 << 10, f), size));
        }
        let (f, size) = open.get_mut(site).unwrap();
        if f.write_all(text.as_bytes()).is_err() {
            open.remove(site);
            return;
        }
        *size += text.len() as u64;
        // Turned over: the older half kept, the file begun again.
        if *size > LOG_MAX {
            let _ = std::fs::rename(&file, self.dir.join(format!("{site}.log.1")));
            open.remove(site);
        }
    }

    // traffic is what was counted, by site, as written to traffic.json.
    pub fn traffic(&self) -> serde_json::Value {
        let c = self.counts.lock().unwrap().clone();
        serde_json::json!({ "boot": self.boot, "sites": c })
    }

    // write puts the counts in traffic.json beside the logs' folder, whole or not at all.
    pub fn write(&self, file: &std::path::Path) {
        let tmp = file.with_extension("json.tmp");
        if std::fs::write(&tmp, self.traffic().to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, file);
        }
    }

    // flush puts what the logs hold in their files.
    pub fn flush(&self) {
        for (f, _) in self.open.lock().unwrap().values_mut() {
            let _ = f.flush();
        }
    }

    // every puts the logs in their files every second and writes the counts
    // every half minute; a log that was moved away (by hand) is opened again.
    pub fn every(self: Arc<Self>, file: PathBuf) {
        std::thread::spawn(move || {
            let mut n = 0u32;
            loop {
                std::thread::sleep(Duration::from_secs(1));
                self.flush();
                n += 1;
                if n % 30 == 0 {
                    self.write(&file);
                    self.open.lock().unwrap().retain(|site, _| self.dir.join(format!("{site}.log")).exists());
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line() {
        let l = Line {
            ip: "1.2.3.4".into(),
            method: "GET".into(),
            uri: "/a?b=\"c\"".into(),
            version: "HTTP/1.1".into(),
            status: 200,
            sent: 12,
            read: 0,
            referer: "-".into(),
            agent: "x\ny".into(),
            ms: 3,
        };
        // 2026-10-09 15:20:01 UTC
        assert_eq!(format(&l, 1791559201), "1.2.3.4 - - [09/Oct/2026:15:20:01 +0000] \"GET /a?b=\\\"c\\\" HTTP/1.1\" 200 12 \"-\" \"x y\" 3ms\n");
    }

    #[test]
    fn counted_and_turned_over() {
        let dir = std::env::temp_dir().join(format!("logs-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let logs = Logs::new(dir.clone());
        let l = Line { ip: "1.2.3.4".into(), method: "GET".into(), uri: "/".into(), version: "HTTP/1.1".into(), status: 200, sent: 100, read: 7, referer: "-".into(), agent: "-".into(), ms: 1 };
        logs.add("w1", &l);
        logs.add("w1", &l);
        logs.flush();
        let t = logs.traffic();
        assert_eq!(t["sites"]["w1"]["requests"], 2);
        assert_eq!(t["sites"]["w1"]["bytes_out"], 200);
        assert_eq!(t["sites"]["w1"]["bytes_in"], 14);
        assert_eq!(std::fs::read_to_string(dir.join("w1.log")).unwrap().lines().count(), 2);
        // Over the size: moved to .1, begun again.
        logs.open.lock().unwrap().get_mut("w1").unwrap().1 = LOG_MAX;
        logs.add("w1", &l);
        assert!(dir.join("w1.log.1").exists());
        logs.add("w1", &l);
        logs.flush();
        assert_eq!(std::fs::read_to_string(dir.join("w1.log")).unwrap().lines().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
