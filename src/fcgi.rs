// A FastCGI client, as much of it as PHP-FPM needs: a request, its
// parameters, its body, and the answer as it comes. Connections are kept
// open after an answer and used again for the next request to the same
// environment (FCGI_KEEP_CONN). A worker of PHP-FPM serves one connection
// at a time, so the entry never holds more connections to an environment,
// busy and idle, than it lets requests run there at once: the caller's
// limit, which is the environment's number of workers.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BEGIN: u8 = 1;
const END: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;
const STDERR: u8 = 7;

pub struct Conn {
    s: TcpStream,
    out: Vec<u8>,
    done: bool,
    // ended: the answer ended as it should (an END record), so the
    // connection can take another request.
    ended: bool,
    addr: String,
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

// A worker of an environment with no request for 30 s is stopped
// (pm.process_idle_timeout), and its connection with it: one idle longer
// than this is not used again.
const IDLE: Duration = Duration::from_secs(20);
const KEEP: usize = 64;

// Pool keeps the connections whose answer ended, by address.
#[derive(Default)]
pub struct Pool {
    idle: Mutex<HashMap<String, Vec<(TcpStream, Instant)>>>,
}

impl Pool {
    // take gives a kept connection to addr that is still open, if there is one.
    fn take(&self, addr: &str) -> Option<TcpStream> {
        let mut idle = self.idle.lock().unwrap();
        let list = idle.get_mut(addr)?;
        while let Some((s, at)) = list.pop() {
            if at.elapsed() > IDLE {
                continue;
            }
            // Open with nothing to read: still there. Closed: a read gives 0.
            let mut b = [0u8; 1];
            match s.try_read(&mut b) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Some(s),
                _ => continue,
            }
        }
        None
    }

    // put keeps a connection whose answer ended, for the next request.
    pub fn put(&self, c: Conn) {
        if !c.ended || !c.out.is_empty() {
            return;
        }
        let mut idle = self.idle.lock().unwrap();
        let list = idle.entry(c.addr).or_default();
        if list.len() < KEEP {
            list.push((c.s, Instant::now()));
        }
    }

    #[cfg(test)]
    pub fn idle(&self, addr: &str) -> usize {
        self.idle.lock().unwrap().get(addr).map_or(0, Vec::len)
    }
}

fn record(kind: u8, data: &[u8], to: &mut Vec<u8>) {
    to.extend_from_slice(&[1, kind, 0, 1, (data.len() >> 8) as u8, data.len() as u8, 0, 0]);
    to.extend_from_slice(data);
}

fn len(n: usize, to: &mut Vec<u8>) {
    if n < 128 {
        to.push(n as u8);
    } else {
        to.extend_from_slice(&[(n >> 24) as u8 | 0x80, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
}

pub async fn begin(pool: &Pool, addr: &str, params: &[(String, String)]) -> io::Result<Conn> {
    let mut buf = Vec::new();
    // The role of a responder, the connection kept after the answer.
    record(BEGIN, &[0, 1, 1, 0, 0, 0, 0, 0], &mut buf);
    let mut pairs = Vec::new();
    for (k, v) in params {
        len(k.len(), &mut pairs);
        len(v.len(), &mut pairs);
        pairs.extend_from_slice(k.as_bytes());
        pairs.extend_from_slice(v.as_bytes());
    }
    for chunk in pairs.chunks(65535) {
        record(PARAMS, chunk, &mut buf);
    }
    record(PARAMS, &[], &mut buf);
    // A kept connection found closed as it is written to: a new one.
    if let Some(mut s) = pool.take(addr) {
        if s.write_all(&buf).await.is_ok() {
            return Ok(Conn { s, out: Vec::new(), done: false, ended: false, addr: addr.to_string() });
        }
    }
    let mut s = TcpStream::connect(addr).await?;
    s.set_nodelay(true)?;
    s.write_all(&buf).await?;
    Ok(Conn { s, out: Vec::new(), done: false, ended: false, addr: addr.to_string() })
}

impl Conn {
    pub async fn stdin(&mut self, data: &[u8]) -> io::Result<()> {
        let mut buf = Vec::with_capacity(data.len() + 64);
        for chunk in data.chunks(65535) {
            record(STDIN, chunk, &mut buf);
        }
        self.s.write_all(&buf).await
    }

    pub async fn end_stdin(&mut self) -> io::Result<()> {
        let mut buf = Vec::new();
        record(STDIN, &[], &mut buf);
        self.s.write_all(&buf).await
    }

    // more reads one record: what PHP wrote goes to out, what it complained of to the log.
    async fn more(&mut self) -> io::Result<()> {
        let mut head = [0u8; 8];
        if self.s.read_exact(&mut head).await.is_err() {
            self.done = true;
            return Ok(());
        }
        let n = ((head[4] as usize) << 8) | head[5] as usize;
        let mut data = vec![0u8; n + head[6] as usize];
        self.s.read_exact(&mut data).await?;
        data.truncate(n);
        match head[1] {
            STDOUT => self.out.extend_from_slice(&data),
            STDERR => log::warn!("php: {}", String::from_utf8_lossy(&data).trim_end()),
            END => {
                self.done = true;
                self.ended = true;
            }
            _ => {}
        }
        Ok(())
    }

    // headers reads up to the end of the headers PHP sends before its page.
    pub async fn headers(&mut self) -> io::Result<Reply> {
        let end = loop {
            if let Some(i) = self.out.windows(4).position(|w| w == b"\r\n\r\n") {
                break Some((i, 4));
            }
            if let Some(i) = self.out.windows(2).position(|w| w == b"\n\n") {
                break Some((i, 2));
            }
            if self.done {
                break None;
            }
            self.more().await?;
        };
        let Some((i, skip)) = end else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "php sent no headers"));
        };
        let head = String::from_utf8_lossy(&self.out[..i]).to_string();
        self.out.drain(..i + skip);
        let mut reply = Reply { status: 200, headers: Vec::new() };
        let mut located = false;
        for line in head.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("status") {
                reply.status = v.split(' ').next().and_then(|c| c.parse().ok()).unwrap_or(200);
                located = true;
            } else {
                if k.eq_ignore_ascii_case("location") && !located {
                    reply.status = 302;
                }
                reply.headers.push((k.to_string(), v.to_string()));
            }
        }
        Ok(reply)
    }

    // body gives the next of the page, none at its end.
    pub async fn body(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if !self.out.is_empty() {
                return Ok(Some(std::mem::take(&mut self.out)));
            }
            if self.done {
                return Ok(None);
            }
            self.more().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    // A PHP-FPM giving one answer per request on a connection it keeps:
    // the second request comes on the same connection.
    #[tokio::test]
    async fn kept_and_used_again() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            for _ in 0..2 {
                // Read up to the empty STDIN record that ends a request.
                loop {
                    let mut head = [0u8; 8];
                    s.read_exact(&mut head).await.unwrap();
                    let n = ((head[4] as usize) << 8) | head[5] as usize;
                    let mut d = vec![0u8; n + head[6] as usize];
                    s.read_exact(&mut d).await.unwrap();
                    if head[1] == STDIN && n == 0 {
                        break;
                    }
                }
                let mut out = Vec::new();
                record(STDOUT, b"Content-Type: text/plain\r\n\r\nhi", &mut out);
                record(STDOUT, &[], &mut out);
                record(END, &[0; 8], &mut out);
                s.write_all(&out).await.unwrap();
            }
            1
        });
        let pool = Pool::default();
        for _ in 0..2 {
            let mut c = begin(&pool, &addr, &[("A".into(), "b".into())]).await.unwrap();
            c.end_stdin().await.unwrap();
            let r = c.headers().await.unwrap();
            assert_eq!(r.status, 200);
            assert_eq!(c.body().await.unwrap().unwrap(), b"hi");
            assert!(c.body().await.unwrap().is_none());
            pool.put(c);
            assert_eq!(pool.idle(&addr), 1);
        }
        assert_eq!(server.await.unwrap(), 1);
    }

    // A kept connection the other side closed is not used again.
    #[tokio::test]
    async fn closed_not_used() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let c = TcpStream::connect(&addr).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        drop(s);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let pool = Pool::default();
        pool.idle.lock().unwrap().insert(addr.clone(), vec![(c, Instant::now())]);
        assert!(pool.take(&addr).is_none());
    }
}
