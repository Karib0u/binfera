//! Process isolation for the native engine, with recovery performed by the parent.
use super::{decompile_error, decompiler_options, Cli, CliError, E_CORRUPT_FILE};
use clap::ValueEnum;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

struct Workers(Vec<Child>);
impl Drop for Workers {
    fn drop(&mut self) {
        for worker in &mut self.0 {
            let _ = worker.kill();
            let _ = worker.wait();
        }
    }
}
fn error(message: impl ToString) -> CliError {
    CliError::new(E_CORRUPT_FILE, message.to_string())
}
fn emit(out: &mut impl Write, event: &Value) -> Result<(), CliError> {
    serde_json::to_writer(&mut *out, event).map_err(error)?;
    writeln!(out).and_then(|()| out.flush()).map_err(error)
}

/// Run at most `jobs` processes, starting the next task as soon as a slot is free.
fn run_stage(
    commands: Vec<Command>,
    jobs: usize,
    mut on_event: impl FnMut(Value) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let mut pending: VecDeque<_> = commands.into_iter().collect();
    let mut workers = Workers(Vec::new());
    let mut readers = Vec::new();
    let (sender, receiver) = std::sync::mpsc::sync_channel(32);
    let mut sender = Some(sender);
    let mut active = 0;
    let mut done = BTreeSet::new();
    loop {
        while active < jobs {
            let Some(mut command) = pending.pop_front() else {
                break;
            };
            let mut child = command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(error)?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| error("worker stdout is unavailable"))?;
            let id = workers.0.len();
            workers.0.push(child);
            active += 1;
            let sender = sender
                .as_ref()
                .cloned()
                .ok_or_else(|| error("worker channel closed before dispatch"))?;
            readers.push(std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let record = line.map_err(|e| e.to_string()).and_then(|line| {
                        serde_json::from_str::<Value>(&line).map_err(|e| e.to_string())
                    });
                    let failed = record.is_err();
                    if sender.send((id, Some(record))).is_err() || failed {
                        return;
                    }
                }
                let _ = sender.send((id, None));
            }));
        }
        if pending.is_empty() {
            sender.take();
        }
        if active == 0 {
            break;
        }
        let (id, record) = receiver.recv().map_err(error)?;
        if let Some(record) = record {
            let event = record.map_err(error)?;
            if event["type"] == "done" {
                done.insert(id);
            }
            on_event(event)?;
        } else {
            let status = workers.0[id].wait().map_err(error)?;
            if !status.success() || !done.contains(&id) {
                return Err(error(format!(
                    "decompiler worker {id} stopped before completing (status {status})"
                )));
            }
            active -= 1;
        }
    }
    for reader in readers {
        reader
            .join()
            .map_err(|_| error("worker output reader failed"))?;
    }
    Ok(())
}

pub(super) fn run(bytes: &[u8], cli: &Cli) -> Result<bool, CliError> {
    if cli.shard.is_some() {
        return Err(error(
            "--jobs greater than 1 cannot be combined with --shard",
        ));
    }
    let directory = tempfile::Builder::new()
        .prefix(&format!("binfera-decompile-{}-", std::process::id()))
        .tempdir()
        .map_err(error)?;
    let cache = directory.path().join("recovery.bin");
    let started = std::time::Instant::now();
    if !binfera::decompiler::prepare_decompile_all(bytes, &decompiler_options(cli), &cache)
        .map_err(decompile_error)?
    {
        return Ok(false);
    }
    let input = directory.path().join("input.bin");
    std::fs::write(&input, bytes).map_err(error)?;
    let executable = std::env::current_exe().map_err(error)?;
    let jobs = cli
        .jobs
        .map_or(1, |jobs| jobs.get())
        .min(binfera::parallel::Jobs::available().get())
        .min(16);
    if cli.timing {
        eprintln!(
            "Decompile preparation: {:.3}s; persistent workers: {jobs}; recovery prepared once",
            started.elapsed().as_secs_f64()
        );
    }
    let format = cli
        .format
        .to_possible_value()
        .ok_or_else(|| error("invalid input format"))?;
    let command = || {
        let mut command = Command::new(&executable);
        command
            .arg(&input)
            .arg("--decompile-all")
            .arg("--decompile-cache")
            .arg(&cache)
            .arg("--format")
            .arg(format.get_name())
            .arg("--arch")
            .arg(&cli.arch)
            .arg("--os")
            .arg(&cli.os);
        if cli.timing {
            command.arg("--timing");
        }
        command
    };
    let shards = (0..jobs)
        .map(|shard| {
            let mut worker = command();
            worker
                .arg("--no-resource-retry")
                .arg("--shard")
                .arg(format!("{shard}/{jobs}"));
            worker
        })
        .collect();
    let mut out = std::io::stdout().lock();
    let mut start: Option<Value> = None;
    let mut warnings = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut failed = BTreeMap::new();
    let mut deferred = BTreeSet::new();
    run_stage(shards, jobs, |event| {
        match event["type"].as_str() {
            Some("start") => {
                if let Some(previous) = &start {
                    if event["functions"] != previous["functions"] {
                        return Err(error("worker function inventories disagree"));
                    }
                } else {
                    emit(&mut out, &event)?;
                    start = Some(event);
                }
            }
            Some("function") => {
                let address = event["address"]
                    .as_u64()
                    .ok_or_else(|| error("worker function has no address"))?;
                if seen.contains(&address) {
                    return Ok(());
                }
                if event["retry_pending"] == true {
                    // Different shards can discover the same supporting callee.
                    if deferred.insert(address) {
                        emit(&mut out, &event)?;
                    }
                } else if event["text"].as_str().is_some() && event["error"].is_null() {
                    deferred.remove(&address);
                    failed.remove(&address);
                    seen.insert(address);
                    emit(&mut out, &event)?;
                } else {
                    failed.insert(address, event);
                }
            }
            Some("settled") => {}
            Some("done") => {
                if let Some(items) = event["warnings"].as_array() {
                    warnings.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
                }
            }
            _ => return Err(error("unexpected worker event")),
        }
        Ok(())
    })?;
    if start.is_none() {
        return Err(error("decompiler workers emitted no inventory"));
    }
    for (address, event) in failed {
        if !deferred.contains(&address) {
            emit(&mut out, &event)?;
        }
    }
    emit(&mut out, &serde_json::json!({"type":"settled"}))?;
    if !cli.no_resource_retry {
        // The retry cap applies to the image, independently of its shard count.
        let retries = deferred
            .into_iter()
            .take(16)
            .map(|address| {
                let mut worker = command();
                worker
                    .arg("--decompile-retry")
                    .arg(format!("0x{address:x}"));
                worker
            })
            .collect();
        run_stage(retries, jobs, |event| {
            match event["type"].as_str() {
                Some("start" | "settled") => {}
                Some("function") => {
                    let address = event["address"]
                        .as_u64()
                        .ok_or_else(|| error("worker function has no address"))?;
                    if !seen.contains(&address) {
                        if event["retry_pending"] != true {
                            seen.insert(address);
                        }
                        emit(&mut out, &event)?;
                    }
                }
                Some("done") => {
                    if let Some(items) = event["warnings"].as_array() {
                        warnings.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                }
                _ => return Err(error("unexpected retry worker event")),
            }
            Ok(())
        })?;
    }
    emit(
        &mut out,
        &serde_json::json!({"type":"done", "warnings":warnings}),
    )?;
    Ok(true)
}
