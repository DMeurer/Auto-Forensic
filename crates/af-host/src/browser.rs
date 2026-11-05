//! Opening a URL in the default browser, for the viewer.
//!
//! No shell is involved: the URL is passed as one argument to a fixed program, so characters
//! like `&` or `|` in a URL can't run anything. Only `http`, `https` and `file` URLs are accepted,
//! and none that could be read as an option or that contain whitespace or control characters.
//!
//! | Host | Program |
//! |---|---|
//! | Linux and other Unix | `xdg-open <url>` |
//! | Windows | `rundll32.exe url.dll,FileProtocolHandler <url>` |
//! | macOS | `open <url>` |
//!
//! The variable `AF_BROWSER` replaces the program; it is run as `<AF_BROWSER> <url>`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::process::{Command, Stdio};

/// The environment variable that names a browser program to use instead of the default.
pub const BROWSER_VAR: &str = "AF_BROWSER";

/// The kind of host, as far as opening a browser is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    Windows,
    MacOs,
    /// Linux and other Unix systems with `xdg-open`.
    Unix,
}

impl HostOs {
    /// The host this binary was built for.
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Unix
        }
    }
}

/// A program and its arguments, ready to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub program: OsString,
    pub args: Vec<OsString>,
}

/// Why a URL was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    /// Not `http://`, `https://` or `file://`.
    Scheme,
    /// Contains whitespace or a control character.
    Characters,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheme => write!(f, "only http, https and file URLs can be opened"),
            Self::Characters => write!(f, "the URL contains whitespace or control characters"),
        }
    }
}

impl std::error::Error for UrlError {}

/// Checks a URL before it is handed to another program.
pub fn check_url(url: &str) -> Result<(), UrlError> {
    let lower = url.to_ascii_lowercase();
    if !["http://", "https://", "file://"]
        .iter()
        .any(|s| lower.starts_with(s))
    {
        return Err(UrlError::Scheme);
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(UrlError::Characters);
    }
    Ok(())
}

/// The command that opens `url` on `os`, or with `browser` if one is set.
pub fn browser_command(url: &str, os: HostOs, browser: Option<&OsStr>) -> Result<Launch, UrlError> {
    check_url(url)?;
    let url = OsString::from(url);
    let launch = match (browser.filter(|b| !b.is_empty()), os) {
        (Some(b), _) => Launch {
            program: b.to_os_string(),
            args: vec![url],
        },
        (None, HostOs::Windows) => Launch {
            program: "rundll32.exe".into(),
            args: vec!["url.dll,FileProtocolHandler".into(), url],
        },
        (None, HostOs::MacOs) => Launch {
            program: "open".into(),
            args: vec![url],
        },
        (None, HostOs::Unix) => Launch {
            program: "xdg-open".into(),
            args: vec![url],
        },
    };
    Ok(launch)
}

/// Opens `url` in the default browser (or `AF_BROWSER`) and returns without waiting for it.
pub fn open_in_browser(url: &str) -> io::Result<()> {
    let browser = std::env::var_os(BROWSER_VAR);
    let launch = browser_command(url, HostOs::current(), browser.as_deref())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    start(&launch)
}

/// Starts a program detached from our terminal, and reaps it in the background.
fn start(launch: &Launch) -> io::Result<()> {
    let mut child = Command::new(&launch.program)
        .args(&launch.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::spawn(move || child.wait());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "http://127.0.0.1:8080/view?event=12&q=a|b";

    fn args(l: &Launch) -> Vec<&str> {
        l.args.iter().map(|a| a.to_str().unwrap()).collect()
    }

    #[test]
    fn default_commands_per_host() {
        let w = browser_command(URL, HostOs::Windows, None).unwrap();
        assert_eq!(w.program, "rundll32.exe");
        assert_eq!(args(&w), ["url.dll,FileProtocolHandler", URL]);
        let u = browser_command(URL, HostOs::Unix, None).unwrap();
        assert_eq!(u.program, "xdg-open");
        assert_eq!(args(&u), [URL]);
        let m = browser_command(URL, HostOs::MacOs, None).unwrap();
        assert_eq!(m.program, "open");
    }

    #[test]
    fn override_replaces_the_program_and_empty_is_ignored() {
        let l = browser_command(URL, HostOs::Windows, Some(OsStr::new("firefox"))).unwrap();
        assert_eq!(l.program, "firefox");
        assert_eq!(args(&l), [URL]);
        let l = browser_command(URL, HostOs::Unix, Some(OsStr::new(""))).unwrap();
        assert_eq!(l.program, "xdg-open");
    }

    #[test]
    fn urls_that_are_refused() {
        for bad in [
            "javascript:alert(1)",
            "--help",
            "-x http://a",
            "ftp://host/file",
            "www.example.com",
        ] {
            assert_eq!(check_url(bad), Err(UrlError::Scheme), "{bad}");
        }
        for bad in [
            "http://a b",
            "http://a\nb",
            "http://a\tb",
            "file:///x\u{0}y",
        ] {
            assert_eq!(check_url(bad), Err(UrlError::Characters), "{bad:?}");
        }
        assert_eq!(check_url("HTTPS://Example.org/a?b=c&d=e"), Ok(()));
        assert_eq!(check_url("file:///home/user/report.html"), Ok(()));
    }

    #[test]
    fn missing_program_is_an_error() {
        let launch = browser_command(
            URL,
            HostOs::current(),
            Some(OsStr::new("af-no-such-browser-program")),
        )
        .unwrap();
        let err = start(&launch).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn current_host_matches_the_build() {
        let os = HostOs::current();
        if cfg!(windows) {
            assert_eq!(os, HostOs::Windows);
        } else if cfg!(target_os = "linux") {
            assert_eq!(os, HostOs::Unix);
        }
    }
}
