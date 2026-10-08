// The rewrite rules of a site, read from any of three writings — Apache's
// .htaccess (mod_rewrite), an nginx configuration, IIS's web.config — into
// one form, and applied to a request. A trial: the common directives, and
// a list of what was passed over.

use fancy_regex::Regex;
use std::path::Path;

use crate::files;

pub enum Test {
    File(bool),
    Dir(bool),
    Exists(bool),
    Re(Regex, bool),
    Eq(String, bool),
}

pub struct Cond {
    pub input: String,
    pub test: Test,
    pub or_next: bool,
}

pub struct Rule {
    pub conds: Vec<Cond>,
    pub re: Regex,
    pub negate: bool,
    // What the path becomes: "-" for no change. $1 is of the rule's
    // pattern, %1 of the last condition's, %{NAME} a variable.
    pub target: String,
    pub last: bool,
    pub qsa: bool,
    pub qsd: bool,
    pub redirect: Option<u16>,
    pub status: Option<u16>,
    // The pattern is for the whole path, with its leading slash (nginx);
    // else for the path inside the base, without one (Apache, IIS).
    pub abs: bool,
    // nginx, inside "location /": not for a PHP script's path, which nginx
    // gives to the block for PHP instead.
    pub in_location: bool,
    // nginx: what the pattern caught is escaped where it goes into the arguments.
    pub escape_args: bool,
}

#[derive(Default)]
pub struct Rules {
    pub rules: Vec<Rule>,
    pub base: String,
    // Apache in a directory: once a rule has rewritten the path, the rules
    // are gone through again from the top.
    pub restart: bool,
    // Apache, IIS: of /index.php/a/b the file asked about is index.php.
    pub script_is_file: bool,
    pub on: bool,
    pub skipped: Vec<String>,
}

pub struct Req<'a> {
    pub path: String,
    pub query: String,
    pub host: &'a str,
    pub https: bool,
    pub root: &'a Path,
    pub header: &'a dyn Fn(&str) -> String,
}

pub enum Outcome {
    Pass(String, String),
    Redirect(u16, String),
    Status(u16),
}

fn re(pattern: &str, nocase: bool) -> Option<Regex> {
    Regex::new(&if nocase { format!("(?i){pattern}") } else { pattern.to_string() }).ok()
}

fn var(name: &str, r: &Req, path: &str, query: &str) -> String {
    let up = name.to_uppercase();
    match up.as_str() {
        "REQUEST_FILENAME" | "SCRIPT_FILENAME" => format!("{}{}", r.root.display(), path),
        "REQUEST_URI" | "URL" | "DOCUMENT_URI" => path.to_string(),
        "QUERY_STRING" => query.to_string(),
        "HTTP_HOST" | "SERVER_NAME" => r.host.to_string(),
        "HTTPS" => if r.https { "on" } else { "off" }.to_string(),
        "REQUEST_SCHEME" => if r.https { "https" } else { "http" }.to_string(),
        "DOCUMENT_ROOT" => r.root.display().to_string(),
        _ => {
            if let Some(h) = up.strip_prefix("HTTP:") {
                (r.header)(h)
            } else if let Some(h) = up.strip_prefix("HTTP_") {
                (r.header)(&h.replace('_', "-"))
            } else {
                String::new()
            }
        }
    }
}

// escape writes what goes into the arguments as nginx does.
fn escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b <= 0x20 || b >= 0x7f || b"\"#%&+<>?\\^`{|}".contains(&b) {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

// script cuts what follows a script's name off a path, where the script is there: /index.php/a/b is /index.php.
fn script(root: &Path, rel: &str) -> String {
    match rel.find(".php/") {
        Some(i) if files::kind(root, &rel[..i + 4]) == Some(files::Kind::File) => rel[..i + 4].to_string(),
        _ => rel.to_string(),
    }
}

// expand fills a target or a condition's input in: $N, %N and %{NAME};
// with esc, what the rule's pattern caught is escaped.
fn expand(t: &str, rule: &[String], cond: &[String], r: &Req, path: &str, query: &str, esc: bool) -> String {
    let b = t.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        if c == '\\' && i + 1 < b.len() {
            out.push(b[i + 1] as char);
            i += 2;
        } else if (c == '$' || c == '%') && i + 1 < b.len() && (b[i + 1] as char).is_ascii_digit() {
            let n = (b[i + 1] - b'0') as usize;
            let from = if c == '$' { rule } else { cond };
            let got = from.get(n).map(String::as_str).unwrap_or("");
            if esc && c == '$' {
                out.push_str(&escape(got));
            } else {
                out.push_str(got);
            }
            i += 2;
        } else if c == '%' && i + 1 < b.len() && b[i + 1] == b'{' {
            match t[i + 2..].find('}') {
                Some(end) => {
                    out.push_str(&var(&t[i + 2..i + 2 + end], r, path, query));
                    i += end + 3;
                }
                None => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            // A character of any length, as it is.
            let ch = t[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn caps(re: &Regex, s: &str) -> Option<Vec<String>> {
    let c = re.captures(s).ok()??;
    Some((0..c.len()).map(|i| c.get(i).map(|m| m.as_str().to_string()).unwrap_or_default()).collect())
}

pub fn apply(rules: &Rules, r: &Req) -> Outcome {
    let (mut path, mut query) = (r.path.clone(), r.query.clone());
    if !rules.on {
        return Outcome::Pass(path, query);
    }
    // A path that is a PHP script's, with or without more after its name.
    let is_php = r.path.ends_with(".php") || r.path.contains(".php/");
    for _ in 0..10 {
        let mut changed = false;
        for rule in &rules.rules {
            if rule.in_location && is_php {
                continue;
            }
            let subject = if rule.abs {
                path.clone()
            } else {
                match path.strip_prefix(&rules.base) {
                    Some(s) => s.to_string(),
                    None => continue,
                }
            };
            let got = caps(&rule.re, &subject);
            if got.is_some() == rule.negate {
                continue;
            }
            let of_rule = got.unwrap_or_default();
            // The conditions: all of them, but that those joined by OR are any of them.
            let mut of_cond: Vec<String> = Vec::new();
            let mut ok = true;
            let mut i = 0;
            while i < rule.conds.len() {
                let mut any = false;
                loop {
                    let c = &rule.conds[i];
                    let input = expand(&c.input, &of_rule, &of_cond, r, &path, &query, false);
                    let mut rel = input.strip_prefix(&r.root.display().to_string()).unwrap_or(&input).to_string();
                    if rules.script_is_file {
                        rel = script(r.root, &rel);
                    }
                    let hit = match &c.test {
                        Test::File(want) => (files::kind(r.root, &rel) == Some(files::Kind::File)) == *want,
                        Test::Dir(want) => (files::kind(r.root, &rel) == Some(files::Kind::Dir)) == *want,
                        Test::Exists(want) => files::kind(r.root, &rel).is_some() == *want,
                        Test::Eq(s, want) => (&input == s) == *want,
                        Test::Re(re, negate) => match caps(re, &input) {
                            Some(c) => {
                                if !*negate {
                                    of_cond = c;
                                }
                                !*negate
                            }
                            None => *negate,
                        },
                    };
                    any |= hit;
                    i += 1;
                    if !c.or_next || i >= rule.conds.len() {
                        break;
                    }
                }
                if !any {
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }
            if let Some(code) = rule.status {
                return Outcome::Status(code);
            }
            if rule.target == "-" {
                if rule.last {
                    break;
                }
                continue;
            }
            // The path and the arguments are filled in apart: what is caught may hold a '?' of its own.
            let (tpath, tquery) = match rule.target.split_once('?') {
                Some((p, q)) => (expand(p, &of_rule, &of_cond, r, &path, &query, false), Some(expand(q, &of_rule, &of_cond, r, &path, &query, rule.escape_args))),
                None => (expand(&rule.target, &of_rule, &of_cond, r, &path, &query, false), None),
            };
            // Apache leaves no '&' at the end of the arguments it makes.
            let tquery = if rules.restart { tquery.map(|q| q.trim_end_matches('&').to_string()) } else { tquery };
            let new_query = match tquery {
                Some(q) if rule.qsa && !query.is_empty() => if q.is_empty() { query.clone() } else { format!("{q}&{query}") },
                Some(q) => q,
                None if rule.qsd => String::new(),
                None => query.clone(),
            };
            let with_query = |p: &str| if new_query.is_empty() { p.to_string() } else { format!("{p}?{new_query}") };
            if tpath.starts_with("http://") || tpath.starts_with("https://") {
                return Outcome::Redirect(rule.redirect.unwrap_or(302), with_query(&tpath));
            }
            let new_path = if tpath.starts_with('/') { tpath } else { format!("{}{}", rules.base, tpath) };
            if let Some(code) = rule.redirect {
                return Outcome::Redirect(code, with_query(&new_path));
            }
            changed |= new_path != path;
            path = new_path;
            query = new_query;
            if rule.last {
                break;
            }
        }
        if !changed || !rules.restart {
            break;
        }
    }
    Outcome::Pass(path, query)
}

// words cuts a line into words; one in quotes is one word.
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut esc = false;
    let mut any = false;
    for c in line.chars() {
        if esc {
            cur.push('\\');
            cur.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
            any = true;
        } else if let Some(q) = quote {
            if c == q { quote = None } else { cur.push(c) }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
            any = true;
        } else if c.is_whitespace() {
            if any || !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
                any = false;
            }
        } else {
            cur.push(c);
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn file_test(p: &str) -> Option<Test> {
    let (neg, t) = match p.strip_prefix('!') {
        Some(t) => (true, t),
        None => (false, p),
    };
    Some(match t {
        "-f" | "-s" => Test::File(!neg),
        "-d" => Test::Dir(!neg),
        "-e" | "-l" => Test::Exists(!neg),
        _ => return None,
    })
}

// htaccess reads Apache's mod_rewrite directives; base is the URL of the
// directory the file is in.
pub fn htaccess(text: &str, base: &str) -> Rules {
    let mut out = Rules { base: base.to_string(), restart: true, script_is_file: true, ..Default::default() };
    let mut conds: Vec<Cond> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('<') {
            continue;
        }
        let w = words(line);
        let flags: Vec<String> = w.last().filter(|f| f.starts_with('[') && f.ends_with(']')).map(|f| f[1..f.len() - 1].split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default();
        let has = |name: &str| flags.iter().any(|f| f.eq_ignore_ascii_case(name));
        match w[0].to_lowercase().as_str() {
            "rewriteengine" => out.on = w.get(1).map(|v| v.eq_ignore_ascii_case("on")).unwrap_or(false),
            "rewritebase" => {
                let b = w.get(1).cloned().unwrap_or_default();
                out.base = if b.ends_with('/') { b } else { format!("{b}/") };
            }
            "rewritecond" if w.len() >= 3 => {
                let nocase = has("NC") || has("nocase");
                let p = &w[2];
                let test = if let Some(t) = file_test(p) {
                    t
                } else if let Some(s) = p.strip_prefix('=') {
                    Test::Eq(s.to_string(), true)
                } else if let Some(s) = p.strip_prefix("!=") {
                    Test::Eq(s.to_string(), false)
                } else {
                    let (neg, pat) = match p.strip_prefix('!') {
                        Some(x) => (true, x),
                        None => (false, p.as_str()),
                    };
                    match re(pat, nocase) {
                        Some(r) => Test::Re(r, neg),
                        None => {
                            out.skipped.push(line.to_string());
                            continue;
                        }
                    }
                };
                conds.push(Cond { input: w[1].clone(), test, or_next: has("OR") || has("ornext") });
            }
            "rewriterule" if w.len() >= 3 => {
                let (neg, pat) = match w[1].strip_prefix('!') {
                    Some(x) => (true, x.to_string()),
                    None => (false, w[1].clone()),
                };
                let Some(r) = re(&pat, has("NC") || has("nocase")) else {
                    out.skipped.push(line.to_string());
                    conds.clear();
                    continue;
                };
                let mut redirect = None;
                for f in &flags {
                    let up = f.to_uppercase();
                    if up == "R" || up == "REDIRECT" {
                        redirect = Some(302);
                    } else if let Some(c) = up.strip_prefix("R=").or(up.strip_prefix("REDIRECT=")) {
                        redirect = Some(match c {
                            "PERMANENT" => 301,
                            "TEMP" => 302,
                            "SEEOTHER" => 303,
                            n => n.parse().unwrap_or(302),
                        });
                    }
                }
                out.rules.push(Rule {
                    conds: std::mem::take(&mut conds),
                    re: r,
                    negate: neg,
                    target: w[2].clone(),
                    last: has("L") || has("last") || has("END"),
                    qsa: has("QSA") || has("qsappend"),
                    qsd: has("QSD"),
                    redirect,
                    status: if has("F") || has("forbidden") { Some(403) } else if has("G") || has("gone") { Some(410) } else { None },
                    abs: false,
                    in_location: false,
                    escape_args: false,
                });
            }
            // What says nothing of rewriting and is harmless to pass over.
            "options" | "directoryindex" | "addtype" | "adddefaultcharset" | "errordocument" | "setenv" | "setenvif" | "header" | "expiresactive" | "expiresbytype" | "addoutputfilterbytype" | "php_value" | "php_flag" => {}
            _ => out.skipped.push(line.to_string()),
        }
    }
    out
}

// nginx_var turns nginx's variables in a target or an input into ours.
fn nginx_var(s: &str) -> String {
    // A '%' means nothing to nginx: it stays one.
    let mut t = s.replace('%', "\\%");
    for (a, b) in [
        ("$request_filename", "%{REQUEST_FILENAME}"),
        ("$document_root", "%{DOCUMENT_ROOT}"),
        ("$request_uri", "%{REQUEST_URI}"),
        ("$query_string", "%{QUERY_STRING}"),
        ("$http_host", "%{HTTP_HOST}"),
        ("$server_name", "%{HTTP_HOST}"),
        ("$scheme", "%{REQUEST_SCHEME}"),
        ("$host", "%{HTTP_HOST}"),
        ("$args", "%{QUERY_STRING}"),
        ("$uri", "%{REQUEST_URI}"),
    ] {
        t = t.replace(a, b);
    }
    t
}

// nginx reads the directives of an nginx server that say how paths are
// rewritten: rewrite, try_files, if, and what is in "location /".
pub fn nginx(text: &str) -> Rules {
    let mut out = Rules { base: "/".into(), on: true, ..Default::default() };
    // The statements, one by one: each ends in ';', '{' or '}'.
    let mut clean = String::new();
    for l in text.lines() {
        let l = l.trim();
        if !l.starts_with('#') {
            clean.push_str(l);
            clean.push(' ');
        }
    }
    let mut stack: Vec<(bool, usize, bool)> = Vec::new(); // (whether its statements count, how many conditions it added, whether it is "location /")
    let mut conds: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut parens = 0;
    let live = |stack: &Vec<(bool, usize, bool)>| stack.iter().all(|s| s.0);
    for c in clean.chars() {
        if let Some(q) = quote {
            cur.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => {
                quote = Some(c);
                cur.push(c);
            }
            '(' => {
                parens += 1;
                cur.push(c);
            }
            ')' => {
                parens -= 1;
                cur.push(c);
            }
            '{' if parens == 0 => {
                let head = cur.trim().to_string();
                cur.clear();
                let w = words(&head);
                match w.first().map(String::as_str) {
                    Some("location") => {
                        // Only what holds for every path is taken; a block for PHP files is ours to do anyway.
                        let all = w.len() == 2 && w[1] == "/";
                        if !all && !head.contains(".php") {
                            out.skipped.push(format!("{head} {{ … }}"));
                        }
                        stack.push((all, 0, all));
                    }
                    Some("if") => {
                        let inner = head[2..].trim().trim_start_matches('(').trim_end_matches(')').trim().to_string();
                        conds.push(inner);
                        stack.push((true, 1, false));
                    }
                    Some("server") | Some("http") => stack.push((true, 0, false)),
                    _ => {
                        out.skipped.push(format!("{head} {{ … }}"));
                        stack.push((false, 0, false));
                    }
                }
            }
            '}' if parens == 0 => {
                cur.clear();
                if let Some((_, n, _)) = stack.pop() {
                    for _ in 0..n {
                        conds.pop();
                    }
                }
            }
            ';' if parens == 0 => {
                let stmt = cur.trim().to_string();
                cur.clear();
                if stmt.is_empty() || !live(&stack) {
                    continue;
                }
                let w = words(&stmt);
                let in_location = stack.iter().any(|s| s.2);
                let mut here: Vec<Cond> = Vec::new();
                let mut bad = false;
                for c in &conds {
                    let cw = words(c);
                    let cond = if cw.len() == 2 && file_test(&cw[0]).is_some() {
                        Some(Cond { input: nginx_var(&cw[1]), test: file_test(&cw[0]).unwrap(), or_next: false })
                    } else if cw.len() == 3 {
                        let (neg, op) = match cw[1].strip_prefix('!') {
                            Some(o) => (true, o),
                            None => (false, cw[1].as_str()),
                        };
                        match op {
                            "~" | "~*" => re(&cw[2], op == "~*").map(|r| Cond { input: nginx_var(&cw[0]), test: Test::Re(r, neg), or_next: false }),
                            "=" => Some(Cond { input: nginx_var(&cw[0]), test: Test::Eq(cw[2].clone(), !neg), or_next: false }),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    match cond {
                        Some(c) => here.push(c),
                        None => bad = true,
                    }
                }
                if bad {
                    out.skipped.push(stmt);
                    continue;
                }
                match w[0].as_str() {
                    "rewrite" if w.len() >= 3 => {
                        let Some(r) = re(&w[1], false) else {
                            out.skipped.push(stmt);
                            continue;
                        };
                        let flag = w.get(3).map(String::as_str).unwrap_or("");
                        let mut target = nginx_var(&w[2]);
                        // Its own arguments are kept after those it names, unless it ends in '?'.
                        let qsa = !target.ends_with('?');
                        if !qsa {
                            target.pop();
                        }
                        let outside = target.starts_with("http") || target.starts_with("%{REQUEST_SCHEME}");
                        out.rules.push(Rule {
                            conds: here,
                            re: r,
                            negate: false,
                            target,
                            last: flag == "last" || flag == "break",
                            qsa,
                            qsd: false,
                            redirect: match flag {
                                "permanent" => Some(301),
                                "redirect" => Some(302),
                                _ if outside => Some(302),
                                _ => None,
                            },
                            status: None,
                            abs: true,
                            in_location,
                            escape_args: true,
                        });
                    }
                    "try_files" if w.len() >= 3 => {
                        // Tried in turn: the file, the folder; then the last, a path to go to or a code.
                        for item in &w[1..w.len() - 1] {
                            match item.as_str() {
                                "$uri" => here.push(Cond { input: "%{REQUEST_FILENAME}".into(), test: Test::File(false), or_next: false }),
                                "$uri/" => here.push(Cond { input: "%{REQUEST_FILENAME}".into(), test: Test::Dir(false), or_next: false }),
                                other => out.skipped.push(format!("try_files … {other} …")),
                            }
                        }
                        let fallback = &w[w.len() - 1];
                        let any = Regex::new("^").unwrap();
                        if let Some(code) = fallback.strip_prefix('=') {
                            out.rules.push(Rule { conds: here, re: any, negate: false, target: "-".into(), last: true, qsa: false, qsd: false, redirect: None, status: code.parse().ok(), abs: true, in_location, escape_args: false });
                        } else {
                            // "?$args" and the like: the request's own arguments, kept.
                            let mut t = fallback.replace("$is_args$args", "").replace("?$args", "").replace("&$args", "").replace("?$query_string", "").replace("&$query_string", "");
                            let qsa = t != *fallback || !t.contains('?');
                            t = nginx_var(&t);
                            out.rules.push(Rule { conds: here, re: any, negate: false, target: t, last: true, qsa, qsd: false, redirect: None, status: None, abs: true, in_location, escape_args: false });
                        }
                    }
                    "return" if w.len() >= 2 => {
                        let code: u16 = w[1].parse().unwrap_or(0);
                        let any = Regex::new("^").unwrap();
                        if (301..=308).contains(&code) && w.len() >= 3 {
                            out.rules.push(Rule { conds: here, re: any, negate: false, target: nginx_var(&w[2]), last: true, qsa: false, qsd: false, redirect: Some(code), status: None, abs: true, in_location, escape_args: false });
                        } else if code >= 400 {
                            out.rules.push(Rule { conds: here, re: any, negate: false, target: "-".into(), last: true, qsa: false, qsd: false, redirect: None, status: Some(code), abs: true, in_location, escape_args: false });
                        } else {
                            out.skipped.push(stmt);
                        }
                    }
                    // Ours to do, whatever is said of them.
                    "index" | "root" | "include" | "fastcgi_pass" | "fastcgi_index" | "fastcgi_param" | "fastcgi_split_path_info" | "listen" | "server_name" | "charset" | "access_log" | "error_log" | "expires" => {}
                    _ => out.skipped.push(stmt),
                }
            }
            _ => cur.push(c),
        }
    }
    out
}

// iis reads the rewrite rules of IIS's web.config.
pub fn iis(text: &str) -> Rules {
    let mut out = Rules { base: "/".into(), on: true, script_is_file: true, ..Default::default() };
    let Ok(doc) = roxmltree::Document::parse(text) else {
        out.skipped.push("web.config is not well-formed XML".into());
        return out;
    };
    // {R:1} of the rule, {C:1} of the conditions, {NAME} a variable.
    let conv = |s: &str| {
        let mut t = String::new();
        // A '%' means nothing to IIS: it stays one.
        let s = s.replace('%', "\\%");
        let mut rest = s.as_str();
        while let Some(i) = rest.find('{') {
            t.push_str(&rest[..i]);
            let Some(j) = rest[i..].find('}') else { break };
            let name = &rest[i + 1..i + j];
            if let Some(n) = name.strip_prefix("R:") {
                t.push_str(&format!("${n}"));
            } else if let Some(n) = name.strip_prefix("C:") {
                t.push_str(&format!("%{n}"));
            } else {
                t.push_str(&format!("%{{{name}}}"));
            }
            rest = &rest[i + j + 1..];
        }
        t.push_str(rest);
        t
    };
    let yes = |v: Option<&str>, default: bool| v.map(|x| x.eq_ignore_ascii_case("true")).unwrap_or(default);
    for rule in doc.descendants().filter(|n| n.has_tag_name("rule")) {
        let name = rule.attribute("name").unwrap_or("?");
        let Some(m) = rule.children().find(|n| n.has_tag_name("match")) else { continue };
        let Some(r) = re(m.attribute("url").unwrap_or(""), yes(m.attribute("ignoreCase"), true)) else {
            out.skipped.push(format!("rule {name}: its pattern"));
            continue;
        };
        let mut conds = Vec::new();
        if let Some(cs) = rule.children().find(|n| n.has_tag_name("conditions")) {
            let any = cs.attribute("logicalGrouping").map(|g| g.eq_ignore_ascii_case("MatchAny")).unwrap_or(false);
            for a in cs.children().filter(|n| n.has_tag_name("add")) {
                let neg = yes(a.attribute("negate"), false);
                let test = match a.attribute("matchType").unwrap_or("Pattern") {
                    "IsFile" => Test::File(!neg),
                    "IsDirectory" => Test::Dir(!neg),
                    _ => match re(a.attribute("pattern").unwrap_or(""), yes(a.attribute("ignoreCase"), true)) {
                        Some(r) => Test::Re(r, neg),
                        None => {
                            out.skipped.push(format!("rule {name}: a condition's pattern"));
                            continue;
                        }
                    },
                };
                conds.push(Cond { input: conv(a.attribute("input").unwrap_or("")), test, or_next: any });
            }
        }
        let Some(act) = rule.children().find(|n| n.has_tag_name("action")) else { continue };
        let kind = act.attribute("type").unwrap_or("Rewrite");
        let mut new = Rule {
            conds,
            re: r,
            negate: yes(m.attribute("negate"), false),
            target: conv(act.attribute("url").unwrap_or("-")),
            last: yes(rule.attribute("stopProcessing"), false),
            qsa: yes(act.attribute("appendQueryString"), true),
            qsd: false,
            redirect: None,
            status: None,
            abs: false,
            in_location: false,
            escape_args: false,
        };
        match kind {
            "Rewrite" => {}
            "Redirect" => {
                new.redirect = Some(match act.attribute("redirectType").unwrap_or("Permanent") {
                    "Found" => 302,
                    "SeeOther" => 303,
                    "Temporary" => 307,
                    _ => 301,
                })
            }
            "CustomResponse" => {
                new.status = act.attribute("statusCode").and_then(|c| c.parse().ok());
                new.target = "-".into();
            }
            "None" => new.target = "-".into(),
            other => {
                out.skipped.push(format!("rule {name}: action {other}"));
                continue;
            }
        }
        // Without arguments named, its own are kept as they are.
        if !new.target.contains('?') {
            new.qsd = !new.qsa;
        }
        out.rules.push(new);
    }
    out
}
