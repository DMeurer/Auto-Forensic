//! The `af` command.

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
    }
    Ok(())
}
