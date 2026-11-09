//! Hand-rolled CLI parsing.
//!
//! No `clap`: it is ~250 KiB of code and a dozen transitive crates for a
//! program whose whole point is being small. The grammar here is tiny and the
//! error messages are written by hand anyway.

use std::path::PathBuf;

/// Command requested on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the engine for real (requires Windows + WinDivert).
    Run(RunArgs),
    /// Simulate traffic without touching the network stack.
    Simulate(SimArgs),
    /// Measure the pipeline's throughput.
    Bench(BenchArgs),
    /// Print a configuration file that is ready to edit.
    InitConfig {
        /// Destination path.
        path: PathBuf,
        /// Overwrite an existing file.
        force: bool,
    },
    /// Validate a configuration file without running anything.
    Check {
        /// File to check.
        path: PathBuf,
    },
    /// Show the effective configuration and the rules as compiled.
    Lint {
        /// File to lint.
        path: PathBuf,
    },
    /// Check whether this machine can run `netrocket run`, without touching
    /// any packet.
    Doctor {
        /// Configuration file to validate as part of the check.
        config: PathBuf,
    },
    /// Print version and build information.
    Version,
    /// Print usage.
    Help,
}

/// Arguments for `nr run`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// Configuration file.
    pub config: PathBuf,
    /// Only count, never divert (WinDivert sniff mode).
    pub monitor: bool,
    /// Override the engine filter.
    pub filter: Option<String>,
    /// Serve the read-only control channel on this path (pipe name on Windows).
    pub ctl: Option<PathBuf>,
}

/// Arguments for `nr simulate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimArgs {
    /// Configuration file.
    pub config: PathBuf,
    /// Flows to simulate.
    pub flows: usize,
    /// Frames per flow.
    pub frames: usize,
    /// Print the per-flow table.
    pub verbose: bool,
    /// Pin the clock to this minute of the day (UTC), for `schedule` limits.
    pub at: Option<u16>,
}

impl Default for SimArgs {
    fn default() -> Self {
        Self {
            config: PathBuf::new(),
            flows: 8,
            frames: 1_000,
            verbose: false,
            at: None,
        }
    }
}

/// Arguments for `nr bench`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchArgs {
    /// Frames to process.
    pub frames: usize,
    /// Flows.
    pub flows: usize,
    /// Repeat count.
    pub repeat: usize,
    /// Reuse a small, cache-resident frame set (default). This isolates the
    /// pipeline's own cost. `--stream` instead walks every generated frame
    /// once, which is memory-bound and reflects a cold working set.
    pub hot: bool,
}

impl Default for BenchArgs {
    fn default() -> Self {
        Self {
            frames: 200_000,
            flows: 8,
            repeat: 3,
            hot: true,
        }
    }
}

/// Parse `std::env::args().skip(1)`.
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Command, String> {
    let mut it = args.into_iter().peekable();
    let Some(cmd) = it.next() else {
        return Ok(Command::Help);
    };
    let mut rest: Vec<String> = it.collect();
    match cmd.as_str() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "-V" | "--version" | "version" => Ok(Command::Version),
        "run" | "start" => {
            let mut a = RunArgs {
                config: PathBuf::from("netrocket.conf"),
                ..RunArgs::default()
            };
            while let Some(flag) = rest.pop() {
                match flag.as_str() {
                    "--monitor" => a.monitor = true,
                    _ if flag.starts_with("--config=") => {
                        a.config = PathBuf::from(&flag["--config=".len()..]);
                    }
                    _ if flag.starts_with("--ctl=") => {
                        a.ctl = Some(PathBuf::from(&flag["--ctl=".len()..]));
                    }
                    _ if flag.starts_with("--filter=") => {
                        a.filter = Some(flag["--filter=".len()..].to_owned());
                    }
                    other => return Err(format!("unknown option for `run`: {other}")),
                }
            }
            Ok(Command::Run(a))
        }
        "simulate" | "sim" => {
            let mut a = SimArgs::default();
            while let Some(flag) = rest.pop() {
                match flag.as_str() {
                    "--verbose" | "-v" => a.verbose = true,
                    _ if flag.starts_with("--flows=") => {
                        a.flows = parse_num(&flag["--flows=".len()..])?;
                    }
                    _ if flag.starts_with("--frames=") => {
                        a.frames = parse_num(&flag["--frames=".len()..])?;
                    }
                    _ if flag.starts_with("--config=") => {
                        a.config = PathBuf::from(&flag["--config=".len()..]);
                    }
                    _ if flag.starts_with("--at=") => {
                        let v = &flag["--at=".len()..];
                        a.at = nr_core::config::parse_minute_of_day(v)
                            .ok_or_else(|| format!("bad time for `simulate --at`: {v}"))?
                            .into();
                    }
                    other => return Err(format!("unknown option for `simulate`: {other}")),
                }
            }
            Ok(Command::Simulate(a))
        }
        "bench" => {
            let mut a = BenchArgs::default();
            while let Some(flag) = rest.pop() {
                match flag.as_str() {
                    _ if flag.starts_with("--frames=") => {
                        a.frames = parse_num(&flag["--frames=".len()..])?;
                    }
                    _ if flag.starts_with("--flows=") => {
                        a.flows = parse_num(&flag["--flows=".len()..])?;
                    }
                    _ if flag.starts_with("--repeat=") => {
                        a.repeat = parse_num::<usize>(&flag["--repeat=".len()..])?.max(1);
                    }
                    "--stream" | "--cold" => a.hot = false,
                    "--hot" => a.hot = true,
                    other => return Err(format!("unknown option for `bench`: {other}")),
                }
            }
            Ok(Command::Bench(a))
        }
        "init" => {
            let mut path = PathBuf::from("netrocket.conf");
            let mut force = false;
            while let Some(flag) = rest.pop() {
                match flag.as_str() {
                    "--force" | "-f" => force = true,
                    _ if flag.starts_with("--config=") => {
                        path = PathBuf::from(&flag["--config=".len()..]);
                    }
                    other => return Err(format!("unknown option for `init`: {other}")),
                }
            }
            Ok(Command::InitConfig { path, force })
        }
        "doctor" => {
            let mut config = PathBuf::from("netrocket.conf");
            while let Some(flag) = rest.pop() {
                match flag.as_str() {
                    _ if flag.starts_with("--config=") => {
                        config = PathBuf::from(&flag["--config=".len()..]);
                    }
                    other => return Err(format!("unknown option for `doctor`: {other}")),
                }
            }
            Ok(Command::Doctor { config })
        }
        "check" => {
            let mut path = PathBuf::from("netrocket.conf");
            while let Some(flag) = rest.pop() {
                match flag.as_str() {
                    _ if flag.starts_with("--config=") => {
                        path = PathBuf::from(&flag["--config=".len()..]);
                    }
                    other => return Err(format!("unknown option for `check`: {other}")),
                }
            }
            Ok(Command::Check { path })
        }
        "lint" => {
            let mut path = PathBuf::from("netrocket.conf");
            while let Some(flag) = rest.pop() {
                match flag.as_str() {
                    _ if flag.starts_with("--config=") => {
                        path = PathBuf::from(&flag["--config=".len()..]);
                    }
                    other => return Err(format!("unknown option for `lint`: {other}")),
                }
            }
            Ok(Command::Lint { path })
        }
        other => Err(format!("unknown command `{other}` (try `netrocket help`)")),
    }
}

fn parse_num<T: std::str::FromStr>(s: &str) -> Result<T, String> {
    s.parse::<T>().map_err(|_| format!("not a number: {s}"))
}

/// Usage text. Written for someone who has never seen the original project.
#[must_use]
pub const fn help_text() -> &'static str {
    "\
netrocket — per-application bandwidth shaping for Windows, in Rust

USAGE
  netrocket run      [--config=FILE] [--monitor] [--filter=EXPR] [--ctl=PATH]
  netrocket simulate [--config=FILE] [--flows=N] [--frames=N] [--at=HH:MM] [--verbose]
  netrocket bench    [--flows=N] [--frames=N] [--repeat=N] [--stream]
  netrocket init     [--config=FILE] [--force]
  netrocket check    [--config=FILE]
  netrocket doctor   [--config=FILE]
  netrocket lint     [--config=FILE]
  netrocket version

COMMANDS
  run        Shape traffic using the WinDivert driver. Needs Administrator.
             --monitor counts packets without diverting them (zero risk).
             --ctl serves a read-only control channel on PATH (a pipe name
             on Windows) so a local UI can read counters without the driver.
  simulate   Replay deterministic synthetic traffic through the real engine.
             Works on any OS. Nothing is intercepted, nothing is shaped.
  bench      Measure packets/second through the pipeline. Works on any OS.
  init       Write a commented configuration file you can edit.
  doctor     Check this machine: driver binaries, elevation, endpoint table,
             and whether the configuration is usable. Diverts no packets.
  check      Parse and validate a configuration file.
  lint       Show limits and compiled rules exactly as the engine sees them.

EXAMPLES
  netrocket doctor
  netrocket init --config=netrocket.conf
  netrocket check --config=netrocket.conf
  netrocket simulate --config=netrocket.conf --verbose
  netrocket bench --flows=16 --frames=20000
  netrocket run --config=netrocket.conf          (Windows, elevated)

EXIT CODES
  0 success   1 usage error   2 configuration error   3 runtime error
"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn parses_run() {
        let c = p(&["run", "--config=foo.conf", "--monitor"]).unwrap();
        match c {
            Command::Run(a) => {
                assert!(a.monitor);
                assert_eq!(a.config, PathBuf::from("foo.conf"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_simulate() {
        match p(&["simulate", "--flows=4", "--frames=99", "-v"]).unwrap() {
            Command::Simulate(a) => {
                assert_eq!(a.flows, 4);
                assert_eq!(a.frames, 99);
                assert!(a.verbose);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_doctor() {
        assert!(matches!(p(&["doctor"]).unwrap(), Command::Doctor { .. }));
        assert!(matches!(
            p(&["doctor", "--config=x.conf"]).unwrap(),
            Command::Doctor { .. }
        ));
    }

    #[test]
    fn parses_init_and_check() {
        assert!(matches!(
            p(&["init", "--force"]).unwrap(),
            Command::InitConfig { force: true, .. }
        ));
        assert!(matches!(
            p(&["check", "--config=x"]).unwrap(),
            Command::Check { .. }
        ));
    }

    #[test]
    fn unknown_command_is_an_error() {
        assert!(p(&["frobnicate"]).is_err());
    }

    #[test]
    fn bad_number_is_an_error() {
        assert!(p(&["simulate", "--flows=abc"]).is_err());
    }

    #[test]
    fn help_and_version() {
        assert_eq!(p(&[]).unwrap(), Command::Help);
        assert_eq!(p(&["--version"]).unwrap(), Command::Version);
    }
}
