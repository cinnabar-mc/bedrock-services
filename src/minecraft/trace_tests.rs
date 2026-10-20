//! Replays the Go libraries' golden request traces against the same fake peer.
//!
//! `tools/service-trace` hosts the peer and writes one golden per scenario from
//! go-xsapi, gophertunnel's auth/service packages and go-playfab. Each golden
//! carries its plan (`> step` lines), so this driver only interprets steps.

use super::*;
use crate::{
    oauth::{MicrosoftAuth, Poll},
    xbox::presence::{State, TitleUpdate},
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ORACLE_ENV: &str = "BEDROCK_SERVICES_TRACE_ORACLE";
const GOLDENS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/service-trace/testdata");

#[derive(Debug)]
enum Kind {
    /// Fewer requests or a recovery Go lacks, with the same final correctness.
    Better,
    /// More requests or a failure Go recovers from.
    Worse,
    /// A different trade-off with no strict ordering.
    Different,
}

/// A known divergence from the Go baseline. The test asserts it still
/// reproduces and that Rust still emits `<scenario>.rust.trace`, so a fix or
/// regression forces the entry to be updated.
struct Divergence {
    scenario: &'static str,
    kind: Kind,
    why: &'static str,
}

const DIVERGENCES: &[Divergence] = &[
    // Audit: Rust judges token validity on the server Date; Go uses the local clock.
    Divergence {
        scenario: "date-skew",
        kind: Kind::Better,
        why: "Go's local clock rejects every Xbox token from a lagging server; Rust uses the server Date",
    },
    // Audit: NSAL resolver PARTIAL, Go's 15 s failure cache is missing.
    Divergence {
        scenario: "nsal-current-failure",
        kind: Kind::Different,
        why: "no NSAL failure cache: Rust retries NSAL current at once and recovers 16s sooner",
    },
    // Audit: a response omitting the refresh token keeps the old one in Rust.
    Divergence {
        scenario: "refresh-rotation",
        kind: Kind::Better,
        why: "Rust keeps the previous refresh token; Go blanks it and cannot refresh again",
    },
    // Not in the audit: go-xsapi's NSAL failure cache also holds SISU errors.
    Divergence {
        scenario: "sisu-failure-cache",
        kind: Kind::Different,
        why: "Go replays a cached SISU error for 15s without a request; Rust asks SISU again",
    },
    // Audit: MCToken not persisted.
    Divergence {
        scenario: "warm-restart-join",
        kind: Kind::Worse,
        why: "6 requests vs Go's 2: no persisted MCToken, plus NSAL default calibration and NSAL current",
    },
    // Audit: concurrent acquisition is serialized by `&mut` instead of deduplicated.
    Divergence {
        scenario: "xsts-dedup",
        kind: Kind::Better,
        why: "the serialized second request reuses the first issuance; go-xsapi sends both",
    },
];

/// Spawned peer; closing its stdin on drop ends the process.
struct Oracle {
    _child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

impl Oracle {
    fn spawn(path: &std::ffi::OsStr) -> Self {
        let mut child = Command::new(path)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start the service-trace oracle");
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        Self {
            _child: child,
            input,
            output,
        }
    }

    /// Sends one length-prefixed JSON request and returns its reply.
    fn call(&mut self, request: Value) -> Value {
        let bytes = serde_json::to_vec(&request).unwrap();
        self.input
            .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
            .unwrap();
        self.input.write_all(&bytes).unwrap();
        self.input.flush().unwrap();
        let mut length = [0; 4];
        self.output.read_exact(&mut length).unwrap();
        let mut reply = vec![0; u32::from_be_bytes(length) as usize];
        self.output.read_exact(&mut reply).unwrap();
        let reply: Value = serde_json::from_slice(&reply).unwrap();
        assert!(reply.get("error").is_none(), "oracle: {reply}");
        reply
    }
}

/// One isolated scenario peer and its manual clock.
struct Peer<'a> {
    oracle: &'a mut Oracle,
    session: u64,
    address: SocketAddr,
    ca: Vec<u8>,
    /// Client clock: the peer's skew is only visible through its Date headers.
    now: SystemTime,
    elapsed: Duration,
}

impl Peer<'_> {
    fn open<'a>(oracle: &'a mut Oracle, scenario: &str) -> Peer<'a> {
        let reply = oracle.call(json!({"op": "open", "scenario": scenario}));
        Peer {
            session: reply["session"].as_u64().unwrap(),
            address: reply["addr"].as_str().unwrap().parse().unwrap(),
            ca: reply["ca"].as_str().unwrap().as_bytes().to_vec(),
            now: unix(&reply["now"]),
            elapsed: Duration::ZERO,
            oracle,
        }
    }

    fn advance(&mut self, seconds: u64) -> Duration {
        let reply = self
            .oracle
            .call(json!({"op": "advance", "session": self.session, "seconds": seconds}));
        self.now = unix(&reply["now"]);
        self.elapsed += Duration::from_secs(seconds);
        Duration::from_secs(seconds)
    }

    fn take(&mut self) -> Vec<String> {
        let reply = self
            .oracle
            .call(json!({"op": "take", "session": self.session}));
        serde_json::from_value(reply["steps"].clone()).unwrap()
    }

    /// Starts with no Date sample, its host clock moved by the time simulated so far.
    fn http(&self, user_agent: &str) -> Http {
        let mut http = Http::trace_fixture(self.address, &self.ca, user_agent);
        http.advance_fixture_time(self.elapsed);
        http
    }
}

impl Drop for Peer<'_> {
    fn drop(&mut self) {
        self.oracle
            .call(json!({"op": "close", "session": self.session}));
    }
}

fn unix(value: &Value) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(value.as_u64().unwrap())
}

/// Builds the Minecraft owner every scenario joins through.
fn minecraft(peer: &Peer<'_>, account: xbox::Account) -> Result<Minecraft, Error> {
    let mut minecraft = Minecraft::new(
        account,
        Config::desktop("1.26.50", 2193, uuid::Uuid::from_u128(1)),
    )?;
    minecraft.http = peer.http(USER_AGENT);
    Ok(minecraft)
}

/// Runs one plan step, mirroring the Go oracle's step of the same name.
async fn run(peer: &mut Peer<'_>, client: &mut Option<Minecraft>, step: &str) -> Result<(), Error> {
    let (verb, argument) = step.split_once(' ').unwrap_or((step, ""));
    if verb == "signin" {
        let config = xbox::Config::default();
        let mut auth = MicrosoftAuth {
            http: peer.http(&config.user_agent),
            config,
        };
        let mut attempt = auth.start(peer.now).await?;
        let credentials = loop {
            let wait = attempt
                .next_poll()
                .duration_since(peer.now)
                .unwrap_or_default();
            auth.http.advance_fixture_time(peer.advance(wait.as_secs()));
            if let Poll::Authorized(credentials) = auth.poll(&mut attempt, peer.now).await? {
                break credentials;
            }
        };
        *client = Some(minecraft(peer, auth.into_account(credentials)?)?);
        return Ok(());
    }
    let owner = client.as_mut().expect("plan step before signin");
    match verb {
        "join" => {
            let key = p384::ecdsa::SigningKey::from_slice(&[7; 48]).unwrap();
            owner.multiplayer_token(key.verifying_key()).await.map(drop)
        }
        "presence" => owner
            .title_presence()
            .update(&TitleUpdate::new(State::Active))
            .await
            .map(drop),
        "advance" => {
            let by = peer.advance(argument.parse().unwrap());
            owner.http.advance_fixture_time(by);
            owner.xbox.advance_fixture_time(by);
            Ok(())
        }
        "restart" => {
            let checkpoint = owner.checkpoint()?;
            let config = xbox::Config::default();
            let auth = MicrosoftAuth {
                http: peer.http(&config.user_agent),
                config,
            };
            *client = Some(minecraft(peer, auth.restore_account(checkpoint)?)?);
            Ok(())
        }
        // `&mut` ownership serializes the pair; the second finds the first's issuance.
        "xsts-pair" => {
            owner.xbox.authorize(argument).await?;
            owner.xbox.authorize(argument).await.map(drop)
        }
        _ => panic!("unknown plan step {step}"),
    }
}

/// Normalizes a step result exactly as the Go oracle does.
fn outcome(result: Result<(), Error>) -> String {
    match result {
        Ok(()) => "= ok".into(),
        Err(Error::Status {
            xerr: Some(code), ..
        }) => format!("= error xerr=0x{code:X}"),
        Err(_) => "= error".into(),
    }
}

/// Replays the golden's plan and returns the Rust SDK's transcript.
async fn replay(oracle: &mut Oracle, scenario: &str, golden: &str) -> String {
    let mut peer = Peer::open(oracle, scenario);
    let mut client = None;
    let mut lines = vec![format!("# {scenario}: Rust SDK")];
    for step in golden.lines().filter_map(|line| line.strip_prefix("> ")) {
        let result = run(&mut peer, &mut client, step).await;
        lines.push(format!("> {step}"));
        lines.extend(peer.take());
        lines.push(outcome(result));
    }
    lines.join("\n") + "\n"
}

/// Drops comment lines so only steps, requests and outcomes are compared.
fn comparable(trace: &str) -> Vec<&str> {
    trace
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect()
}

/// Every Go golden must match, or reproduce its listed divergence exactly.
#[tokio::test]
async fn service_traces_match_go_goldens() {
    let Some(path) = std::env::var_os(ORACLE_ENV) else {
        eprintln!("skipping: missing fixture {ORACLE_ENV} (build tools/service-trace)");
        return;
    };
    let mut oracle = Oracle::spawn(&path);
    let mut scenarios: Vec<String> = std::fs::read_dir(GOLDENS)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".trace") && !name.ends_with(".rust.trace"))
        .map(|name| name.trim_end_matches(".trace").to_owned())
        .collect();
    scenarios.sort();
    let mut failures = Vec::new();
    for scenario in &scenarios {
        let golden =
            std::fs::read_to_string(Path::new(GOLDENS).join(format!("{scenario}.trace"))).unwrap();
        let rust = replay(&mut oracle, scenario, &golden).await;
        let same = comparable(&rust) == comparable(&golden);
        match DIVERGENCES.iter().find(|entry| entry.scenario == scenario) {
            None if !same => failures.push(format!(
                "{scenario}: Rust differs from Go\n--- go\n{golden}--- rust\n{rust}"
            )),
            None => {}
            Some(entry) if same => failures.push(format!(
                "{scenario}: {:?} divergence ({}) no longer reproduces; remove its entry",
                entry.kind, entry.why
            )),
            Some(entry) => {
                let path = Path::new(GOLDENS).join(format!("{scenario}.rust.trace"));
                let expected = std::fs::read_to_string(&path).unwrap_or_default();
                if comparable(&expected) != comparable(&rust) {
                    failures.push(format!(
                        "{scenario}: {:?} divergence ({}) changed; update {}\n--- rust\n{rust}",
                        entry.kind,
                        entry.why,
                        path.display()
                    ));
                }
            }
        }
    }
    for entry in DIVERGENCES {
        assert!(
            scenarios.iter().any(|name| name == entry.scenario),
            "divergence for unknown scenario {}",
            entry.scenario
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
