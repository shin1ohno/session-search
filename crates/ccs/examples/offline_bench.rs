//! Benchmark-only probe for `ccs search <query> --offline`; never shipped.
//!
//! Run with HOME pointing at a tools/shadow snapshot:
//!   CCS_BUILD_COMMIT=$(git rev-parse HEAD) cargo run --locked --release -p ccs \
//!     --example offline_bench -- [--runs N] [--threads N] <query>
//! Each run prints one JSON line of numbers only, without paths or text, so
//! it is safe on real transcripts. It times candidate selection (rg plus the
//! per-agent cap), the scan through the production scheduler with its
//! per-worker counters, and the whole library offline search.
use ccs::{codex, fallback, query::Query};
use std::time::Instant;

struct Usage {
    user: f64,
    sys: f64,
    maxrss: i64,
}

fn usage(who: libc::c_int) -> Usage {
    // SAFETY: getrusage only writes into the zeroed struct we pass.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(who, &mut ru) };
    let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    Usage {
        user: seconds(ru.ru_utime),
        sys: seconds(ru.ru_stime),
        maxrss: ru.ru_maxrss as i64,
    }
}

fn ms(start: Instant) -> f64 {
    (start.elapsed().as_secs_f64() * 1e4).round() / 10.0
}

fn bail(message: &str) -> ! {
    eprintln!("offline_bench: {message}");
    std::process::exit(2)
}

fn main() {
    let mut runs = 1usize;
    let mut threads = fallback::SCAN_THREADS;
    let mut query = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--runs" => {
                runs = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| bail("--runs N"))
            }
            "--threads" => {
                threads = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| bail("--threads N"))
            }
            _ if query.is_none() => query = Some(arg),
            _ => bail("usage: offline_bench [--runs N] [--threads N] <query>"),
        }
    }
    let query = Query::from(
        query
            .unwrap_or_else(|| bail("a query is required"))
            .as_str(),
    )
    .trimmed();
    let scan_query: &[u32] = if query.points().len() < 2 {
        &[]
    } else {
        query.points()
    };
    // ru_maxrss is KiB on Linux and bytes on macOS.
    let rss_unit = if cfg!(target_os = "macos") {
        "B"
    } else {
        "KiB"
    };
    for run in 0..runs {
        let started = Instant::now();
        let paths = fallback::candidates_query(&query, None)
            .unwrap_or_else(|_| bail("candidate selection failed"));
        let candidates_ms = ms(started);
        let sizes: Vec<(bool, u64)> = paths
            .iter()
            .map(|p| {
                (
                    codex::is_path(p),
                    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
                )
            })
            .collect();
        let agent = |codex: bool| {
            let mine: Vec<u64> = sizes
                .iter()
                .filter(|(c, _)| *c == codex)
                .map(|(_, n)| *n)
                .collect();
            format!(
                "{{\"files\":{},\"bytes\":{},\"largest\":{}}}",
                mine.len(),
                mine.iter().sum::<u64>(),
                mine.iter().max().copied().unwrap_or(0)
            )
        };

        let before = usage(libc::RUSAGE_SELF);
        let started = Instant::now();
        let (scanned, stats) = fallback::scan_paths(&paths, scan_query, threads);
        let scan_ms = ms(started);
        let after = usage(libc::RUSAGE_SELF);
        let workers: Vec<String> = stats
            .workers
            .iter()
            .map(|w| {
                format!(
                    "{{\"tasks\":{},\"bytes\":{},\"busy_ms\":{:.1}}}",
                    w.tasks,
                    w.bytes,
                    w.busy.as_secs_f64() * 1e3
                )
            })
            .collect();

        let started = Instant::now();
        let found = fallback::search_options_query(&query, &fallback::SearchOptions::default());
        let search_ms = ms(started);
        let children = usage(libc::RUSAGE_CHILDREN);
        println!(
            "{{\"run\":{run},\"threads\":{threads},\"candidates_ms\":{candidates_ms},\"scan_ms\":{scan_ms},\
             \"scan_user_s\":{:.3},\"scan_sys_s\":{:.3},\"search_ms\":{search_ms},\"scan_ok\":{},\
             \"search_rows\":{},\"claude\":{},\"codex\":{},\"workers\":[{}],\
             \"children_user_s\":{:.3},\"maxrss\":{},\"maxrss_unit\":\"{rss_unit}\"}}",
            after.user - before.user,
            after.sys - before.sys,
            scanned.is_ok(),
            found.map(|rows| rows.len() as i64).unwrap_or(-1),
            agent(false),
            agent(true),
            workers.join(","),
            children.user,
            after.maxrss,
        );
    }
}
