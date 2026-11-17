# AutoForensic user guide

`af` builds one timeline from disk images and loose files, and links events with labelled, explained links: "moved to", "last connected", "named in log" and so on. Everything goes into a project folder. Your evidence is never written to.

## Build

You need Rust; `rustup` installs the pinned toolchain on first use. The bundled DuckDB is C++ and needs a C++ compiler and about 6 GB of memory to build.

```
cargo build --release
```

The binary is `target/release/af`. Every command and option has `--help`.

## A first case

```
af project new ~/cases/case1 --name "Case 1"
af source add ~/cases/case1 /evidence/disk.E01
af run ~/cases/case1
af status ~/cases/case1
```

1. **`af project new DIR`** makes the project. DIR must not exist or must be empty.
2. **`af source add PROJECT PATH`** adds evidence.
   - **Images** (`.E01`, `.dd`, `.raw`, `.img`, `.000`, `.001`, `.vmdk`, `.vhd`, `.vhdx`) are referenced in place and opened read-only. `af` hashes them on adding, so a large image takes a while.
   - **Loose files** are copied into the project. Registry hives are recognised by their content. For anything else, name the kind:

     | File | `--as` |
     |---|---|
     | Event log (`.evtx`) | `windows.evtx` |
     | Prefetch (`.pf`) | `windows.prefetch` |
     | Shortcut (`.lnk`) | `windows.lnk` |
     | `$MFT` | `windows.mft` |
     | `$UsnJrnl:$J` | `windows.usn` |
     | A hive it doesn't recognise | `windows.hive.system`, `.software`, `.sam`, `.security`, `.ntuser`, `.usrclass`, `.amcache` |

   - `--as-of "YYYY-MM-DD HH:MM"` (UTC) says when the evidence was captured. Facts read from it, such as "this stick is drive F:", are true as of then.
3. **`af run PROJECT`** runs every plugin. Run it again after adding sources or updating `af`: only new or changed inputs are read again.
4. **`af status PROJECT`** says what was read, how much, and what wasn't and why. For example, it lists volumes it can't read and plugins whose input isn't in the project. BitLocker volumes are reported as locked. Decrypt them first (for example with `dislocker`), then add the decrypted image.

Each image or loose file becomes its own *system*. `af system list PROJECT` shows them, with pairs that may be the same machine.

## Reading the timeline

```
af events PROJECT --limit 50
af events PROJECT --kind windows.evtx.4624
af explain PROJECT EVENT_ID
af facts PROJECT
af facts PROJECT --kind windows.usb --events
af users PROJECT
```

- **`af events`** prints tab-separated lines in time order, all times in UTC. Event log entries get EvtxECmd's fields (description, user, payloads). The last column is the event's ID. `--kind` takes an exact kind. After the rows come notes on the event log maps that were used, as lines starting with `#`, for example why an event may be missing.
- **`af explain ID`** shows an event, group or fact:
  - its links, each with its label, strength (strong before possible) and the reason it exists;
  - the groups it is in;
  - the plugin that made it and where its bytes are, down to the offset in the image, with a hex dump (`--bytes N`, default 512).

  Use explain to check a finding against the evidence.
- **`af facts`** lists things that hold over time rather than happen at one moment: USB devices, drive letters, services, network interfaces, users. Without `--kind` you get each kind with its count. `--kind PREFIX` lists the facts themselves, and `--events` adds the events linked to each.
- **`af users`** lists each system's users with their hives.

## Your own notes

Tags, comments, lists and your own groups are kept when you run again.

```
af tag add PROJECT ID stick
af tag list PROJECT
af comment add PROJECT ID "first time the stick was seen"
af comment list PROJECT
af list new PROJECT Report
af list add PROJECT Report ID ...
af list show PROJECT Report
af group new PROJECT "files copied to the stick"
af group add PROJECT GROUP_ID ID ... --why "same size and name"
af group show PROJECT GROUP_ID
```

- **Tags and comments** work on events, groups and facts.
- **Lists** hold events and groups in the order you added them. `af list add` can also copy in a group's members (`--from-group`) or another list (`--from-list`).
- **Groups** are made by the rules (sessions, root keys and so on) and by you. `af group show` gives the reason for every member. Only your own groups can be changed.

## Export

```
af export PROJECT --format csv --out case1.csv
af export PROJECT --format csv --out report.csv --list Report
af export PROJECT --format jsonl --out case1.jsonl --kind windows.evtx --tag stick
```

- **CSV** opens in Eric Zimmerman's Timeline Explorer. It has UTC times as `yyyy-MM-dd HH:mm:ss.fffffff`, EvtxECmd's columns, and then tags, the number of links, the record and the event ID.
- **JSONL** has one event per line, with its record, tags and links.
- Filters can be combined: `--kind PREFIX`, `--list NAME` (directly or through a group in it) and `--tag NAME`.
- An existing file is never overwritten.

## Good to know

- **Event log maps:** `af` uses EvtxECmd's maps, compiled in. Your own `.map` files in `PROJECT/maps/` come first.
- **One writer at a time:** while `af run` writes a project, other commands wait for up to 30 seconds (`AF_LOCK_WAIT_SECS` changes this).
- **Removing evidence:** `af source remove PROJECT SOURCE_ID` removes a source and everything read from it; the image itself is untouched.
- **Moved images:** `af source relink` points the project at an image's new place after checking it is the same image (`--verify` compares the full SHA-256).
