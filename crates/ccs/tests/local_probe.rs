use ccs::{codex, extract, fallback, session_codex, util::*};
use ccs_pytext::json::Value;
use std::io::{BufRead, Write};
use std::path::Path;
fn call(v: &Value) -> ccs::errors::Result<Value> {
    let input = get(v, "input");
    match text(get(v, "op")).unwrap_or_default().as_str() {
        "normalize" | "index_sequence" => {
            session_codex::conformance_case(&text(get(v, "op")).unwrap(), input, get(v, "kwargs"))
        }
        "normalize_full" => session_codex::normalize(input),
        "index_state" => {
            let mut state =
                session_codex::IndexState::new(get(v, "session_id").clone(), Some(get(v, "saved")));
            let Value::Array(records) = input else {
                return Err(invalid("records required"));
            };
            let accepted = records
                .iter()
                .map(|rec| Value::Bool(state.accept(rec)))
                .collect();
            Ok(object([
                ("accepted", Value::Array(accepted)),
                ("state", state.state),
            ]))
        }
        "scan" => extract::scan_checked(
            Path::new(&text(input).unwrap()),
            text(get(v, "query")).as_deref(),
            4,
        )
        .map(|s| s.value()),
        "extract" => extract::extract(Path::new(&text(input).unwrap())),
        "record_text" => Ok(Value::String(extract::record_text_points(input))),
        "casefold_points" => match input {
            Value::String(s) => Ok(Value::String(ccs_pytext::casefold_points(s))),
            _ => Err(invalid("string required")),
        },
        "strict" => extract::loads_strict(&text(input).unwrap()),
        "classify" => Ok(codex::classify(Path::new(&text(input).unwrap())).unwrap_or(Value::Null)),
        "find_local" => Ok(codex::find_local(
            &text(input).unwrap(),
            text(get(v, "hint")).as_deref().map(Path::new),
        )
        .map(|p| string(p.to_string_lossy()))
        .unwrap_or(Value::Null)),
        "metadata" => Ok(codex::metadata(Path::new(&text(input).unwrap()))),
        "home" => Ok(object([
            ("home", string(home().to_string_lossy())),
            ("short", string(short_cwd(&text(input).unwrap(), 80))),
        ])),
        "is_within" => Ok(Value::Bool(is_within(
            Path::new(&text(input).unwrap()),
            Path::new(&text(get(v, "root")).unwrap()),
        ))),
        "paths" => Ok(Value::Array(
            codex::paths()
                .iter()
                .map(|p| string(p.to_string_lossy()))
                .collect(),
        )),
        "main_files" => Ok(Value::Array(
            fallback::main_files(Path::new(&text(input).unwrap()))
                .iter()
                .map(|p| string(p.to_string_lossy()))
                .collect(),
        )),
        "newest" => {
            let Value::Array(paths) = input else {
                return Err(invalid("paths required"));
            };
            Ok(Value::Array(
                fallback::newest(
                    paths.iter().map(|p| text(p).unwrap().into()).collect(),
                    None,
                )
                .iter()
                .map(|p| string(p.to_string_lossy()))
                .collect(),
            ))
        }
        "log" => {
            log("WARN", &text(input).unwrap());
            Ok(Value::Null)
        }
        "search" => fallback::search(input),
        "validate" => Ok(object([
            (
                "session",
                Value::Bool(valid_session_id(&text(input).unwrap())),
            ),
            ("host", Value::Bool(valid_host_label(&text(input).unwrap()))),
            (
                "tool",
                Value::Bool(valid_tool_result_name(&text(input).unwrap())),
            ),
        ])),
        "parse_ts" => Ok(parse_ts(input).map(number).unwrap_or(Value::Null)),
        "iso" => Ok(string(iso(text(input).unwrap().parse().unwrap()))),
        _ => Err(invalid("unknown probe")),
    }
}
#[test]
#[ignore = "driven by the Python differential oracles"]
fn json_probe() {
    let requests =
        std::fs::File::open(std::env::var_os("CCS_ORACLE_REQUESTS").expect("request file"))
            .unwrap();
    let mut responses =
        std::fs::File::create(std::env::var_os("CCS_ORACLE_RESPONSES").expect("response file"))
            .unwrap();
    for line in std::io::BufReader::new(requests).lines() {
        let v = parse_json(&line.unwrap()).unwrap();
        let result = call(&v).unwrap_or_else(|_| object([("error", Value::Bool(true))]));
        writeln!(responses, "{}", json_string(&result, true, false).unwrap()).unwrap();
    }
}
