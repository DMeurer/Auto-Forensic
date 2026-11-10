//! The `af` command.

use af_core::artifact::Artifact;
use af_core::bytes::Locator;
use af_core::ids::SourceId;
use af_core::names::Kind;
use af_core::profile::{NoneProfile, OsProfile};
use af_core::runner::Plugin;
use af_core::system::Family;
use af_core::time::Time;
use af_store::project::Project;
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// Every compiled-in plugin, in the order the runner calls them within a phase. Adding a plugin
/// is one line here (the Linux canary, C2, checks that nothing else in core has to change).
const PLUGINS: &[&dyn Plugin] = &[
    &af_windows::plugins::HiveRootKeys,
    &af_windows::plugins::UserProfiles,
    &af_windows::evtx::EventLogs,
    &af_windows::prefetch::Prefetch,
    &af_windows::lnk::Shortcuts,
    &af_windows::registry_timeline::KeyTimes,
    &af_windows::host::Host,
    &af_windows::network::Network,
    &af_windows::autoruns::RunKeys,
    &af_windows::autoruns::Services,
    &af_windows::bam::Bam,
    &af_windows::sam::Sam,
    &af_windows::usb::Usb,
    &af_windows::mft::Mft,
    &af_core::fs_timeline::Timeline,
    &af_windows::usn::Journal,
    &af_linux::Wtmp,
    &af_linux::Passwd,
];

/// Every compiled-in OS profile; adding one is one line here (the canary counts it with the
/// plugin line). `none` goes last: it claims what nothing else does.
const PROFILES: &[&dyn OsProfile] = &[
    &af_windows::WindowsProfile,
    &af_linux::LinuxProfile,
    &NoneProfile,
];

#[derive(Parser)]
#[command(
    name = "af",
    version,
    about = "AutoForensic: a forensic timeline with labelled links"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create and inspect projects.
    #[command(subcommand)]
    Project(ProjectCommand),
    /// Add, list, remove and relink a project's sources.
    #[command(subcommand)]
    Source(SourceCommand),
    /// List a project's systems and merge suggestions.
    #[command(subcommand)]
    System(SystemCommand),
    /// What was read, what's missing, and why.
    Status { project: PathBuf },
    /// Run the compiled-in plugins on a project. Unchanged inputs aren't extracted again.
    Run { project: PathBuf },
    /// Each system's users with their hives, as the last run found them.
    Users { project: PathBuf },
    /// Events in timeline order as tab-separated lines. Event log records get EvtxECmd's fields
    /// from maps: the project's `maps/*.map` first, then af's, then EvtxECmd's (compiled in).
    Events {
        project: PathBuf,
        /// Only events of this kind, such as `windows.evtx.4624`.
        #[arg(long)]
        kind: Option<String>,
        /// At most this many events.
        #[arg(long)]
        limit: Option<u64>,
    },
}

#[derive(Subcommand)]
enum SystemCommand {
    /// Every system, one per import, and pairs that may be the same machine.
    List { project: PathBuf },
}

#[derive(Subcommand)]
enum SourceCommand {
    /// Add an image (referenced, never written) or a loose file (copied into the project).
    /// A loose file's kind is detected from its content (a hive by its root keys).
    Add {
        project: PathBuf,
        path: PathBuf,
        /// Name a loose file's kind by hand, such as windows.hive.system.
        #[arg(long = "as", value_name = "KIND")]
        as_kind: Option<String>,
        /// When the evidence was captured, in UTC: "YYYY-MM-DD", "YYYY-MM-DD HH:MM" or
        /// "YYYY-MM-DD HH:MM:SS". Facts from this source are true as of then.
        #[arg(long, value_name = "UTC")]
        as_of: Option<String>,
    },
    /// List the sources with their hashes.
    List { project: PathBuf },
    /// Remove a source and everything read from it. An image itself is never touched.
    Remove { project: PathBuf, id: String },
    /// Point an image source at its new place, after checking it is the same image.
    Relink {
        project: PathBuf,
        id: String,
        path: PathBuf,
        /// Also compare the full SHA-256 (reads the whole image).
        #[arg(long)]
        verify: bool,
    },
}

/// "YYYY-MM-DD", "YYYY-MM-DD HH:MM" or "YYYY-MM-DD HH:MM:SS" in UTC, as seconds since 1970.
fn parse_utc(text: &str) -> Result<i64, String> {
    let bad = || format!("{text:?} is not a UTC time like 2026-04-26 10:00:00");
    let (date, time) = text
        .trim()
        .split_once(' ')
        .unwrap_or((text.trim(), "00:00:00"));
    let d: Vec<&str> = date.split('-').collect();
    let mut t: Vec<&str> = time.split(':').collect();
    if t.len() == 2 {
        t.push("0");
    }
    let (Ok([y, mo, da]), Ok([h, mi, se])) = (
        <[&str; 3]>::try_from(d.as_slice()),
        <[&str; 3]>::try_from(t.as_slice()),
    ) else {
        return Err(bad());
    };
    let num = |s: &str| s.parse::<u32>().map_err(|_| bad());
    let key = af_core::time::TimeKey::from_utc(
        y.parse::<i64>().map_err(|_| bad())?,
        num(mo)?,
        num(da)?,
        num(h)?,
        num(mi)?,
        num(se)?,
    )
    .ok_or_else(bad)?;
    Ok((key.0 - af_core::time::UNIX_EPOCH_KEY).div_euclid(af_core::time::TICKS_PER_SECOND))
}

/// How long read-only commands wait while a run writes the project: AF_LOCK_WAIT_SECS, or 30 s.
fn wait() -> std::time::Duration {
    let secs = std::env::var("AF_LOCK_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    std::time::Duration::from_secs(secs)
}

fn source_id(text: &str) -> Result<SourceId, String> {
    u128::from_str_radix(text, 16)
        .map(SourceId)
        .map_err(|_| format!("{text:?} is not a source ID (32 hex digits, see `af source list`)"))
}

#[derive(Subcommand)]
enum ProjectCommand {
    /// Create a project in DIR, which must not exist or be empty.
    New {
        dir: PathBuf,
        /// A name for people; defaults to the folder name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Show a project's name, creation time and version.
    Info { dir: PathBuf },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("af: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout().lock();
    match cli.command {
        Command::Project(ProjectCommand::New { dir, name }) => {
            let name = name.unwrap_or_else(|| {
                dir.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "project".into())
            });
            Project::create(&dir, &name)?;
            writeln!(out, "created project {name:?} in {}", dir.display())?;
        }
        Command::Project(ProjectCommand::Info { dir }) => {
            let info = Project::open_read_only(&dir, wait())?.info()?;
            writeln!(out, "name:     {}", info.name)?;
            writeln!(
                out,
                "created:  {}",
                Time::from_unix_seconds(info.created_unix).display()
            )?;
            writeln!(out, "by af:    {}", info.created_by_version)?;
            writeln!(out, "plugins:  {} compiled in", PLUGINS.len())?;
        }
        Command::Run { project } => {
            let r = af_store::run::run_project(&project, PLUGINS, PROFILES)?;
            writeln!(
                out,
                "ran {} plugins on {} systems: {} extracted, {} events loaded",
                PLUGINS.len(),
                r.systems,
                r.extracted,
                r.events_loaded
            )?;
        }
        Command::Events {
            project,
            kind,
            limit,
        } => events(&project, kind.as_deref(), limit, &mut out)?,
        Command::Users { project } => {
            let p = Project::open_read_only(&project, wait())?;
            let mut facts = p.store.facts()?;
            facts.sort_by(|a, b| a.subject.cmp(&b.subject));
            for s in p.systems()? {
                let label = s
                    .label
                    .as_deref()
                    .map(|l| format!(" {l}"))
                    .unwrap_or_default();
                writeln!(out, "system {} ({}){label}", s.id, s.family)?;
                for f in facts.iter().filter(|f| {
                    f.system == s.id.0
                        && matches!(f.kind.as_str(), "windows.user_profile" | "unix.user")
                }) {
                    let a: serde_json::Value = f
                        .attrs
                        .as_deref()
                        .and_then(|t| serde_json::from_str(t).ok())
                        .unwrap_or_default();
                    let text =
                        |k: &str| a.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let mark = if a.get("in_profile_list") != Some(&serde_json::Value::Bool(false))
                    {
                        ""
                    } else if text("home").is_empty() {
                        "  (loose hive, no SID known)"
                    } else {
                        "  (folder only, not in ProfileList)"
                    };
                    writeln!(
                        out,
                        "  {}  {}  {}{mark}",
                        f.subject,
                        text("name"),
                        text("home")
                    )?;
                    for h in a
                        .get("hives")
                        .and_then(|v| v.as_array())
                        .into_iter()
                        .flatten()
                    {
                        let field = |k: &str| h.get(k).and_then(|v| v.as_str()).unwrap_or("");
                        writeln!(out, "    {}  {}", field("kind"), field("path"))?;
                    }
                }
            }
        }
        Command::Status { project } => {
            write!(
                out,
                "{}",
                Project::open_read_only(&project, wait())?.status(PLUGINS)?
            )?;
        }
        Command::System(SystemCommand::List { project }) => {
            let p = Project::open_read_only(&project, wait())?;
            for s in p.systems()? {
                let label = s.label.as_deref().unwrap_or("-");
                writeln!(out, "{} {:8} {label} (source {})", s.id, s.family, s.source)?;
                for (k, v) in &s.facts {
                    writeln!(out, "    {k}: {v}")?;
                }
            }
            for m in p.merge_suggestions()? {
                writeln!(
                    out,
                    "maybe the same machine: {} and {} ({})",
                    m.a, m.b, m.reason
                )?;
            }
        }
        Command::Source(cmd) => match cmd {
            SourceCommand::Add {
                project,
                path,
                as_kind,
                as_of,
            } => {
                let as_kind = as_kind.map(|k| Kind::new(&k)).transpose()?;
                let as_of = as_of.map(|t| parse_utc(&t)).transpose()?;
                let mut p = Project::open(&project)?;
                let s = p.add_source(&path)?;
                if let Some(t) = as_of {
                    p.set_as_of(s.id, Some(t), "entered")?;
                }
                writeln!(out, "{}", p.as_of(s.id)?.display())?;
                writeln!(out, "added {} {} {:?}", s.kind, s.id, s.label)?;
                writeln!(out, "sha256 {}", s.sha256)?;
                if let Some(c) = p.image_check(s.id)? {
                    writeln!(out, "{}", c.display())?;
                    if let Some(d) = &c.acquired {
                        writeln!(out, "acquired {d} (the imager's local time, zone unknown)")?;
                    }
                }
                let (volumes, notes) = p.volumes(s.id)?;
                for v in &volumes {
                    writeln!(out, "{}", v.display())?;
                    writeln!(out, "  {}", v.coverage())?;
                }
                for n in &notes {
                    writeln!(out, "note: {n}")?;
                }
                if s.kind == "device" {
                    for (dev, at) in af_host::device::mounted(&s.files[0]) {
                        writeln!(
                            out,
                            "warning: {dev} is mounted at {at}; the mount can write while af reads. Unmount it first"
                        )?;
                    }
                    writeln!(
                        out,
                        "note: a live device isn't hashed. To block writes, run `sudo blockdev --setro {}`, or image it and add the image",
                        s.files[0].display()
                    )?;
                }
                if s.kind == "loose" {
                    // shortcut: reads the whole copy; fine for hives, revisit for large loose files.
                    let kind = match as_kind {
                        Some(k) => Some(k),
                        None => af_windows::loose::detect(&std::fs::read(&s.files[0])?),
                    };
                    // Each import is its own system (F23); merging is the analyst's call.
                    let family = match &kind {
                        Some(k) if k.namespace() == "windows" => Family::Windows,
                        _ => Family::None,
                    };
                    let sys = p.add_system(s.id, &family, None, &[])?;
                    match &kind {
                        Some(kind) => {
                            let mut index = p.store.artifacts()?;
                            index.add(Artifact {
                                kind: kind.clone(),
                                locator: Locator::root("source.loose", &s.id.to_string()),
                                source: s.id,
                                system: Some(sys),
                                sha256: s.sha256.clone(),
                            });
                            p.store.save_artifacts(&index)?;
                            writeln!(out, "kind   {kind}")?;
                        }
                        None => writeln!(out, "kind   unknown; name it with --as KIND")?,
                    }
                    writeln!(out, "system {sys} ({})", family.as_str())?;
                } else {
                    for sys in p.add_systems(&s, PROFILES)? {
                        writeln!(out, "system {sys}")?;
                    }
                }
            }
            SourceCommand::List { project } => {
                let p = Project::open_read_only(&project, wait())?;
                let index = p.store.artifacts()?;
                for s in p.sources()? {
                    writeln!(
                        out,
                        "{} {:5} {:>14} {} {}",
                        s.id, s.kind, s.size, s.sha256, s.label
                    )?;
                    for f in &s.files {
                        let mark = if f.exists() {
                            ""
                        } else {
                            "  (missing: relink it)"
                        };
                        writeln!(out, "    {}{mark}", f.display())?;
                    }
                    for a in index.all().filter(|a| a.source == s.id) {
                        writeln!(out, "    kind: {}", a.kind)?;
                    }
                    writeln!(out, "    {}", p.as_of(s.id)?.display())?;
                }
            }
            SourceCommand::Remove { project, id } => {
                Project::open(&project)?.remove_source(source_id(&id)?)?;
                writeln!(out, "removed {id}")?;
            }
            SourceCommand::Relink {
                project,
                id,
                path,
                verify,
            } => {
                let s = Project::open(&project)?.relink_source(source_id(&id)?, &path, verify)?;
                let how = if verify { "full hash" } else { "fingerprint" };
                writeln!(
                    out,
                    "relinked {} to {} ({how} matches)",
                    s.id,
                    s.files[0].display()
                )?;
            }
        },
    }
    Ok(())
}

/// `af events`: the project's maps, then the compiled-in ones (af's, then EvtxECmd's), applied
/// to each event log record.
fn events(
    project: &std::path::Path,
    kind: Option<&str>,
    limit: Option<u64>,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    use af_windows::evtx_map::{EventMap, builtin_maps, map_event};
    let p = Project::open_read_only(project, wait())?;
    let mut maps = vec![];
    if let Ok(dir) = std::fs::read_dir(project.join("maps")) {
        let mut files: Vec<_> = dir
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|f| f.extension().is_some_and(|x| x == "map"))
            .collect();
        files.sort();
        for f in files {
            match std::fs::read_to_string(&f)
                .map_err(|e| e.to_string())
                .and_then(|t| EventMap::parse(&t))
            {
                Ok(m) => maps.push(m),
                Err(e) => eprintln!("map {} skipped: {e}", f.display()),
            }
        }
    }
    maps.extend(builtin_maps());
    let clean = |s: &str| s.replace(['\t', '\r', '\n'], " ");
    let mut lines = vec![];
    let mut used: Vec<usize> = vec![];
    for (e, record, attrs) in p.store.event_list(kind, limit)? {
        let time = Time::from_columns(&e.time)
            .map(|t| t.display())
            .unwrap_or_default();
        let event: Option<serde_json::Value> =
            attrs.as_deref().and_then(|a| serde_json::from_str(a).ok());
        let mapped = event.as_ref().and_then(|ev| map_event(&maps, ev));
        let mut cols = vec![time, e.kind.clone(), e.meaning.clone()];
        match mapped {
            Some((m, f)) => {
                let i = maps.iter().position(|x| std::ptr::eq(x, m)).unwrap_or(0);
                if !used.contains(&i) {
                    used.push(i);
                }
                cols.extend([f.description, f.user_name, f.remote_host, f.executable_info]);
                cols.extend(f.payload);
            }
            None => cols.extend(std::iter::repeat_n(String::new(), 10)),
        }
        cols.push(record.unwrap_or_default());
        lines.push(cols.iter().map(|c| clean(c)).collect::<Vec<_>>().join("\t"));
    }
    // A note shows when its map was used or its event was asked for, even with no events: it
    // says why one may be missing (such as an audit policy that was off).
    let asked = kind.and_then(|k| k.strip_prefix("windows.evtx.")?.parse::<u32>().ok());
    for (i, m) in maps.iter().enumerate() {
        if let Some(n) = &m.note
            && (used.contains(&i) || asked == Some(m.event_id))
        {
            writeln!(
                out,
                "# note on event {} ({}): {}",
                m.event_id,
                m.description,
                clean(n)
            )?;
        }
    }
    writeln!(
        out,
        "time\tkind\tmeaning\tdescription\tuser_name\tremote_host\texecutable_info\t\
         payload_data1\tpayload_data2\tpayload_data3\tpayload_data4\tpayload_data5\tpayload_data6\t\
         record"
    )?;
    for l in lines {
        writeln!(out, "{l}")?;
    }
    Ok(())
}
