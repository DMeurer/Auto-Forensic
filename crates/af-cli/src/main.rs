//! The `af` command.

use af_core::ids::SourceId;
use af_core::runner::Plugin;
use af_core::time::Time;
use af_store::project::Project;
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// Every compiled-in plugin, in the order the runner calls them within a phase. Adding a plugin
/// is one line here (the Linux canary, C2, checks that nothing else in core has to change).
const PLUGINS: &[&dyn Plugin] = &[];

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
}

#[derive(Subcommand)]
enum SourceCommand {
    /// Add an image (referenced, never written) or a loose file (copied into the project).
    Add { project: PathBuf, path: PathBuf },
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
            let info = Project::open(&dir)?.info()?;
            writeln!(out, "name:     {}", info.name)?;
            writeln!(
                out,
                "created:  {}",
                Time::from_unix_seconds(info.created_unix).display()
            )?;
            writeln!(out, "by af:    {}", info.created_by_version)?;
            writeln!(out, "plugins:  {} compiled in", PLUGINS.len())?;
        }
        Command::Source(cmd) => match cmd {
            SourceCommand::Add { project, path } => {
                let s = Project::open(&project)?.add_source(&path)?;
                writeln!(out, "added {} {} {:?}", s.kind, s.id, s.label)?;
                writeln!(out, "sha256 {}", s.sha256)?;
            }
            SourceCommand::List { project } => {
                for s in Project::open(&project)?.sources()? {
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
