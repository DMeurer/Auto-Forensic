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
    &af_windows::recyclebin::RecycleBin,
    &af_windows::tasks::Tasks,
    &af_windows::browser::BrowserHistory,
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
    &af_windows::same_file::SameFile,
    &af_windows::sessions::Sessions,
    &af_windows::logons::Logons,
    &af_windows::download::DownloadToUse,
    &af_windows::moved::MovedTo,
    &af_windows::usb_connections::UsbConnections,
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
    /// One event, group or fact and its links, each with its label first, strong before possible
    /// (L1), then the groups it is in with their links (L7). The event ID is the last column of
    /// `af events`; group and fact IDs show in explain.
    Explain { project: PathBuf, id: String },
    /// Tag events, groups and facts, and list them by tag (O1). Tags stay through re-runs.
    #[command(subcommand)]
    Tag(TagCommand),
    /// Dated comments on events, groups and facts (O1). Comments stay through re-runs.
    #[command(subcommand)]
    Comment(CommentCommand),
    /// Named lists of events and groups, such as "Report" (O8). Lists stay through re-runs.
    #[command(subcommand)]
    List(ListCommand),
    /// Groups: show why each member is there, list them, and make your own (O8).
    #[command(subcommand)]
    Group(GroupCommand),
}

#[derive(Subcommand)]
enum ListCommand {
    /// Make a list (a list with this name already is kept).
    New { project: PathBuf, name: String },
    /// Add events or groups by ID, or copy in a group's members or another list's entries.
    Add {
        project: PathBuf,
        name: String,
        ids: Vec<String>,
        /// Copy this group's event and group members.
        #[arg(long, value_name = "GROUP")]
        from_group: Option<String>,
        /// Copy this list's entries.
        #[arg(long, value_name = "LIST")]
        from_list: Option<String>,
    },
    /// Take events or groups off a list; they stay in the project.
    Remove {
        project: PathBuf,
        name: String,
        ids: Vec<String>,
    },
    /// A list's entries in the order they were added.
    Show { project: PathBuf, name: String },
    /// Every list with its number of entries.
    All { project: PathBuf },
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Make your own group with a reason; prints its ID.
    New { project: PathBuf, reason: String },
    /// Add events, facts or groups to your own group.
    Add {
        project: PathBuf,
        group: String,
        ids: Vec<String>,
        /// Why these members are there.
        #[arg(long)]
        why: Option<String>,
    },
    /// Take members out of your own group; they stay in the project.
    Remove {
        project: PathBuf,
        group: String,
        ids: Vec<String>,
    },
    /// A group's reason and every member with why it is there.
    Show { project: PathBuf, group: String },
    /// Every group, by kind and start; only one kind if given.
    List {
        project: PathBuf,
        #[arg(long)]
        kind: Option<String>,
    },
}

#[derive(Subcommand)]
enum TagCommand {
    /// Tag an event, group or fact by its ID (from `af events` or `af explain`).
    Add {
        project: PathBuf,
        id: String,
        tag: String,
    },
    /// Take a tag off an event, group or fact.
    Remove {
        project: PathBuf,
        id: String,
        tag: String,
    },
    /// Every tagged item, by tag; only one tag if given.
    List {
        project: PathBuf,
        tag: Option<String>,
    },
}

#[derive(Subcommand)]
enum CommentCommand {
    /// Comment on an event, group or fact by its ID; prints the comment's number.
    Add {
        project: PathBuf,
        id: String,
        text: String,
    },
    /// Every comment, oldest first; only those on one item if its ID is given.
    List {
        project: PathBuf,
        id: Option<String>,
    },
    /// Remove a comment by its number.
    Remove { project: PathBuf, no: i64 },
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
        Command::Explain { project, id } => explain(&project, &id, &mut out)?,
        Command::Tag(cmd) => match cmd {
            TagCommand::Add { project, id, tag } => {
                let mut p = Project::open(&project)?;
                let target = resolve(&p, &id)?;
                let new = p.store.add_tag(&target, tag.trim())?;
                let what = describe_endpoint(&p, &target)?;
                if new {
                    writeln!(out, "tagged {tag}: {what}")?;
                } else {
                    writeln!(out, "already tagged {tag}: {what}")?;
                }
            }
            TagCommand::Remove { project, id, tag } => {
                let mut p = Project::open(&project)?;
                let target = resolve(&p, &id)?;
                if !p.store.remove_tag(&target, tag.trim())? {
                    return Err(format!("{id} has no tag {tag:?}").into());
                }
                writeln!(out, "removed tag {tag}")?;
            }
            TagCommand::List { project, tag } => {
                let p = Project::open_read_only(&project, wait())?;
                for (tag, kind, id) in p.store.tags(tag.as_deref())? {
                    let what = match id {
                        Some(id) => describe(&p, &kind, id)?,
                        None => kind,
                    };
                    writeln!(out, "{tag}\t{what}")?;
                }
            }
        },
        Command::List(cmd) => list_command(cmd, &mut out)?,
        Command::Group(cmd) => group_command(cmd, &mut out)?,
        Command::Comment(cmd) => match cmd {
            CommentCommand::Add { project, id, text } => {
                let mut p = Project::open(&project)?;
                let target = resolve(&p, &id)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                let no = p.store.add_comment(&target, &text, now)?;
                writeln!(out, "comment #{no} on {}", describe_endpoint(&p, &target)?)?;
            }
            CommentCommand::List { project, id } => {
                let p = Project::open_read_only(&project, wait())?;
                let target = id.map(|id| resolve(&p, &id)).transpose()?;
                for c in p.store.comments(target.as_ref())? {
                    let what = match c.target_id {
                        Some(id) => describe(&p, &c.target_kind, id)?,
                        None => c.target_kind.clone(),
                    };
                    writeln!(out, "#{}  {}  {what}", c.no, unix(c.created_unix))?;
                    writeln!(out, "    {}", c.text)?;
                }
            }
            CommentCommand::Remove { project, no } => {
                if !Project::open(&project)?.store.remove_comment(no)? {
                    return Err(format!("no comment #{no}").into());
                }
                writeln!(out, "removed comment #{no}")?;
            }
        },
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
/// `af explain`: an event, a group (L7) or a fact (L8), its links, label first, then the groups
/// it is directly in, each with the links to and from that group.
fn explain(
    project: &std::path::Path,
    id: &str,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    use af_core::ids::{Endpoint, EventId, FactId, GroupId};
    let id = u128::from_str_radix(id.trim(), 16).map_err(|e| format!("ID {id}: {e}"))?;
    let p = Project::open_read_only(project, wait())?;
    let endpoint = if let Some((e, record)) = p.store.event_by_id(id)? {
        writeln!(out, "{}  {}", describe(&p, "event", id)?, e.meaning)?;
        if let Some(r) = record {
            writeln!(out, "  record {r}")?;
        }
        Endpoint::Event(EventId(id))
    } else if let Some(g) = p.store.group_by_id(id)? {
        write_group(&p, &g, Some(20), out)?;
        Endpoint::Group(GroupId(id))
    } else if let Some(f) = p.store.fact_by_id(id)? {
        writeln!(out, "fact {}  {id:032x}", f.kind)?;
        writeln!(out, "  {}", f.subject)?;
        if let Some(a) = f.attrs {
            writeln!(out, "  {a}")?;
        }
        writeln!(out, "  made by {}", f.created_by)?;
        Endpoint::Fact(FactId(id))
    } else {
        return Err(format!("no event, group or fact {id:x} in this project").into());
    };
    // O1: the analyst's tags and comments.
    let tags = p.store.tags_of(&endpoint)?;
    if !tags.is_empty() {
        writeln!(out, "  tags: {}", tags.join(", "))?;
    }
    for c in p.store.comments(Some(&endpoint))? {
        writeln!(
            out,
            "  comment #{} ({}): {}",
            c.no,
            unix(c.created_unix),
            c.text
        )?;
    }
    if write_links(&p, &endpoint, "", out)? == 0 {
        writeln!(out, "no links")?;
    }
    for g in p.store.groups_of(&endpoint)? {
        let Some(row) = p.store.group_by_id(g.0)? else {
            continue;
        };
        writeln!(
            out,
            "in group {}: {} ({} members)  {:032x}",
            row.kind, row.reason, row.members, g.0
        )?;
        write_links(&p, &Endpoint::Group(g), "  via group: ", out)?;
    }
    Ok(())
}

/// One line for an event (time and kind), a group (kind, reason, ID), a fact (kind, subject, ID)
/// or another endpoint.
fn describe(p: &Project, kind: &str, id: u128) -> Result<String, Box<dyn std::error::Error>> {
    Ok(match kind {
        "event" => match p.store.event_by_id(id)? {
            Some((e, _)) => {
                let time = Time::from_columns(&e.time)
                    .map(|t| t.display())
                    .unwrap_or_default();
                format!("{time}  {}", e.kind)
            }
            None => format!("event {id:032x}"),
        },
        "group" => match p.store.group_by_id(id)? {
            Some(g) => format!("group {}: {}  {id:032x}", g.kind, g.reason),
            None => format!("group {id:032x}"),
        },
        "fact" => match p.store.fact_by_id(id)? {
            Some(f) => format!("fact {}: {}  {id:032x}", f.kind, f.subject),
            None => format!("fact {id:032x}"),
        },
        kind => format!("{kind} {id:032x}"),
    })
}

/// A group's header, then its members (at most `limit`), each with why it is there first (O8).
fn write_group(
    p: &Project,
    g: &af_store::groups::GroupRow,
    limit: Option<usize>,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(out, "group {}  {:032x}", g.kind, g.id.0)?;
    writeln!(out, "  {}", g.reason)?;
    if let (Some(a), Some(b)) = (g.ts_min, g.ts_max) {
        writeln!(out, "  {} to {}", ticks(a), ticks(b))?;
    }
    writeln!(out, "  made by {}, {} members", g.created_by, g.members)?;
    let members = p.store.members_of(g.id)?;
    let shown = limit.unwrap_or(members.len());
    for (kind, m, why) in members.iter().take(shown) {
        let why = why.as_deref().unwrap_or("member");
        writeln!(out, "  {why}:  {}", describe(p, kind, *m)?)?;
    }
    if members.len() > shown {
        writeln!(out, "  and {} more", members.len() - shown)?;
    }
    Ok(())
}

/// `af list` (O8).
fn list_command(cmd: ListCommand, out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    use af_core::ids::{Endpoint, EventId, GroupId};
    use af_store::rebuild::USER;
    let named = |p: &Project, name: &str| -> Result<u128, Box<dyn std::error::Error>> {
        p.store
            .list_id(name)?
            .ok_or_else(|| format!("no list {name:?}").into())
    };
    match cmd {
        ListCommand::New { project, name } => {
            Project::open(&project)?.store.create_list(&name, USER)?;
            writeln!(out, "list {name}")?;
        }
        ListCommand::Add {
            project,
            name,
            ids,
            from_group,
            from_list,
        } => {
            let mut p = Project::open(&project)?;
            let list = named(&p, &name)?;
            let mut items = ids
                .iter()
                .map(|id| resolve(&p, id))
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(g) = from_group {
                let Endpoint::Group(g) = resolve(&p, &g)? else {
                    return Err(format!("{g} is not a group").into());
                };
                for (kind, id, _) in p.store.members_of(g)? {
                    match kind.as_str() {
                        "event" => items.push(Endpoint::Event(EventId(id))),
                        "group" => items.push(Endpoint::Group(GroupId(id))),
                        _ => {}
                    }
                }
            }
            if let Some(other) = from_list {
                let other = named(&p, &other)?;
                items.extend(p.store.list_entries(other)?.into_iter().map(|e| e.member));
            }
            let (mut added, mut skipped) = (0, 0);
            for item in &items {
                if p.store.add_to_list(list, item, USER)? {
                    added += 1;
                } else {
                    skipped += 1;
                }
            }
            writeln!(
                out,
                "{added} added to {name}, {skipped} already there or not an event or group"
            )?;
        }
        ListCommand::Remove { project, name, ids } => {
            let mut p = Project::open(&project)?;
            let list = named(&p, &name)?;
            let mut n = 0;
            for id in &ids {
                let item = resolve(&p, id)?;
                n += usize::from(p.store.remove_from_list(list, &item)?);
            }
            writeln!(out, "{n} removed from {name}")?;
        }
        ListCommand::Show { project, name } => {
            let p = Project::open_read_only(&project, wait())?;
            for e in p.store.list_entries(named(&p, &name)?)? {
                writeln!(
                    out,
                    "{}  added {} by {}",
                    describe_endpoint(&p, &e.member)?,
                    unix(e.added_unix),
                    e.created_by
                )?;
            }
        }
        ListCommand::All { project } => {
            let p = Project::open_read_only(&project, wait())?;
            for name in p.store.lists()? {
                let n = p.store.list_entries(named(&p, &name)?)?.len();
                writeln!(out, "{name}\t{n} entries")?;
            }
        }
    }
    Ok(())
}

/// `af group` (O8). Only the analyst's groups change: rules rebuild theirs every run.
fn group_command(cmd: GroupCommand, out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    use af_core::ids::{Endpoint, GroupId};
    use af_store::rebuild::USER;
    let own = |p: &Project, id: &str| -> Result<GroupId, Box<dyn std::error::Error>> {
        let Endpoint::Group(g) = resolve(p, id)? else {
            return Err(format!("{id} is not a group").into());
        };
        let row = p.store.group_by_id(g.0)?.expect("resolved");
        if row.created_by != USER {
            return Err(format!(
                "group {id} was made by {}, which remakes it every run; make your own with `af group new`",
                row.created_by
            )
            .into());
        }
        Ok(g)
    };
    match cmd {
        GroupCommand::New { project, reason } => {
            let mut p = Project::open(&project)?;
            let id = GroupId(SourceId::new_random().0);
            p.store.add_group(
                id,
                &Kind::new("user.group").expect("valid kind"),
                &reason,
                USER,
            )?;
            writeln!(out, "group {:032x}", id.0)?;
        }
        GroupCommand::Add {
            project,
            group,
            ids,
            why,
        } => {
            let mut p = Project::open(&project)?;
            let g = own(&p, &group)?;
            for id in &ids {
                let m = resolve(&p, id)?;
                p.store.add_member(g, &m, why.as_deref(), USER)?;
            }
            p.store.refresh_group_ranges()?;
            writeln!(out, "{} added to group {:032x}", ids.len(), g.0)?;
        }
        GroupCommand::Remove {
            project,
            group,
            ids,
        } => {
            let mut p = Project::open(&project)?;
            let g = own(&p, &group)?;
            let mut n = 0;
            for id in &ids {
                let m = resolve(&p, id)?;
                n += usize::from(p.store.remove_member(g, &m)?);
            }
            p.store.refresh_group_ranges()?;
            writeln!(out, "{n} removed from group {:032x}", g.0)?;
        }
        GroupCommand::Show { project, group } => {
            let p = Project::open_read_only(&project, wait())?;
            let Endpoint::Group(g) = resolve(&p, &group)? else {
                return Err(format!("{group} is not a group").into());
            };
            let row = p.store.group_by_id(g.0)?.expect("resolved");
            write_group(&p, &row, None, out)?;
        }
        GroupCommand::List { project, kind } => {
            let p = Project::open_read_only(&project, wait())?;
            for g in p.store.groups(kind.as_deref())? {
                let start = g.ts_min.map(ticks).unwrap_or_default();
                writeln!(
                    out,
                    "{:032x}\t{}\t{}\t{} members\t{}",
                    g.id.0, g.kind, start, g.members, g.reason
                )?;
            }
        }
    }
    Ok(())
}

/// An event, group or fact by its hex ID, whichever the project has.
fn resolve(p: &Project, id: &str) -> Result<af_core::ids::Endpoint, Box<dyn std::error::Error>> {
    use af_core::ids::{Endpoint, EventId, FactId, GroupId};
    let n = u128::from_str_radix(id.trim(), 16).map_err(|e| format!("ID {id}: {e}"))?;
    Ok(if p.store.event_by_id(n)?.is_some() {
        Endpoint::Event(EventId(n))
    } else if p.store.group_by_id(n)?.is_some() {
        Endpoint::Group(GroupId(n))
    } else if p.store.fact_by_id(n)?.is_some() {
        Endpoint::Fact(FactId(n))
    } else {
        return Err(format!("no event, group or fact {n:x} in this project").into());
    })
}

/// [`describe`] for an endpoint.
fn describe_endpoint(
    p: &Project,
    e: &af_core::ids::Endpoint,
) -> Result<String, Box<dyn std::error::Error>> {
    let c = e.to_columns();
    match c.id {
        Some(id) => describe(p, &c.kind, id),
        None => Ok(c.kind),
    }
}

/// Seconds since 1970 as a UTC time.
fn unix(secs: i64) -> String {
    ticks((secs + 11_644_473_600) * 10_000_000)
}

/// A time key as a date (100 ns ticks since 1601).
fn ticks(t: i64) -> String {
    u64::try_from(t).map_or(t.to_string(), |t| Time::from_ticks_1601(t).display())
}

/// The links from (`->`) and to (`<-`) one endpoint, each line after `prefix`; how many.
fn write_links(
    p: &Project,
    of: &af_core::ids::Endpoint,
    prefix: &str,
    out: &mut dyn Write,
) -> Result<usize, Box<dyn std::error::Error>> {
    let links = p.store.links_of(of)?;
    for l in &links {
        let other = match (l.other_kind.as_str(), l.other_id) {
            (kind, Some(o)) => describe(p, kind, o)?,
            (kind, None) => kind.to_string(),
        };
        let arrow = if l.outgoing { "->" } else { "<-" };
        writeln!(
            out,
            "{prefix}{}  {arrow} {other}  [{}]  {}: {}",
            l.label, l.tier, l.reason, l.key
        )?;
        if let Some(d) = &l.description {
            writeln!(out, "{prefix}    {d}")?;
        }
    }
    Ok(links.len())
}

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
        // L1: the ID `af explain` takes.
        cols.push(format!("{:032x}", e.id));
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
         record\tid"
    )?;
    for l in lines {
        writeln!(out, "{l}")?;
    }
    Ok(())
}
