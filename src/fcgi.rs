// A FastCGI client, as much of it as PHP-FPM needs: one request on one
// connection, its parameters, its body, and the answer as it comes.

use std::io;
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
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
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

pub async fn begin(addr: &str, params: &[(String, String)]) -> io::Result<Conn> {
    let mut s = TcpStream::connect(addr).await?;
    let mut buf = Vec::new();
    // The role of a responder, the connection closed after the answer.
    record(BEGIN, &[0, 1, 0, 0, 0, 0, 0, 0], &mut buf);
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
    s.write_all(&buf).await?;
    Ok(Conn { s, out: Vec::new(), done: false })
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
            END => self.done = true,
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
