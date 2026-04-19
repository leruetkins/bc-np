use chrono::prelude::*;
use glob::Pattern;
use std::convert::TryInto;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

struct AppStateInner {
    config: Mutex<serde_json::Value>,
    updated: Mutex<bool>,
}

#[derive(Clone)]
struct AppState {
    inner: std::sync::Arc<AppStateInner>,
}

impl AppState {
    fn new() -> Self {
        let config = fs::read_to_string("config.json")
            .map(|c| serde_json::from_str(&c).ok())
            .unwrap_or(None)
            .unwrap_or_else(|| serde_json::json!({
                "node": {"name": "Unknown"},
                "settings": [],
                "endpoints": []
            }));
        
        Self {
            inner: std::sync::Arc::new(AppStateInner {
                config: Mutex::new(config),
                updated: Mutex::new(false),
            }),
        }
    }
    
    fn get_config(&self) -> serde_json::Value {
        self.inner.config.lock().unwrap().clone()
    }
    
    fn update_config(&self, new_config: serde_json::Value) {
        *self.inner.config.lock().unwrap() = new_config;
        *self.inner.updated.lock().unwrap() = true;
    }
    
    fn was_updated(&self) -> bool {
        let mut updated = self.inner.updated.lock().unwrap();
        if *updated {
            *updated = false;
            true
        } else {
            false
        }
    }
}

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

fn endpoint_type(endpoint: &serde_json::Value) -> &str {
    endpoint["type"].as_str().unwrap_or("local")
}

fn endpoint_host(endpoint: &serde_json::Value) -> &str {
    endpoint["host"].as_str().unwrap_or("")
}

fn endpoint_label(name: &str, endpoint_type: &str, host: &str) -> String {
    if endpoint_type == "ssh" && !host.is_empty() {
        format!("{name} (ssh:{host})")
    } else {
        name.to_string()
    }
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn build_remote_target_resolution_script(path: &str) -> String {
    format!(
        "TARGET={}\n\
TARGET_RESOLVED=\"$TARGET\"\n\
case \"$TARGET\" in\n\
  \"~\")\n\
    TARGET_RESOLVED=\"$HOME\"\n\
    ;;\n\
  \"~/\"*)\n\
    TARGET_RESOLVED=\"$HOME/${{TARGET#\\~/}}\"\n\
    ;;\n\
esac\n",
        shell_single_quote(path)
    )
}

fn build_remote_cleanup_script(path: &str, max_count: i64, filter: &[String], name: &str) -> String {
    let mut script = String::from(
        "set -eu\n\
shopt -s nullglob\n",
    );
    script.push_str(&build_remote_target_resolution_script(path));
    script.push_str(&format!("ENDPOINT_NAME={}\n", shell_single_quote(name)));
    script.push_str(&format!("MAX_COUNT={}\n", max_count.max(0)));

    for (idx, mask) in filter.iter().filter(|mask| !mask.is_empty()).enumerate() {
        script.push_str(&format!("FILTER_{idx}={}\n", shell_single_quote(mask)));
    }

    script.push_str(
        r#"
echo "SSH debug: whoami=$(whoami)"
echo "SSH debug: pwd=$(pwd)"
echo "SSH debug: home=$HOME"
echo "SSH debug: target_raw=$TARGET"
echo "SSH debug: target_resolved=$TARGET_RESOLVED"
if [ -e "$TARGET_RESOLVED" ]; then
  echo "SSH debug: target_exists=yes"
  ls -ld "$TARGET_RESOLVED" 2>/dev/null || true
else
  echo "SSH debug: target_exists=no"
fi

if [ ! -d "$TARGET_RESOLVED" ]; then
  echo "Failed to read directory: $TARGET_RESOLVED"
  exit 2
fi

entries=()
while IFS= read -r -d '' row; do
  entries+=("$row")
done < <(find "$TARGET_RESOLVED" -mindepth 1 -maxdepth 1 -printf '%T@|%P\0' | sort -z -r -n)

filtered=()
for row in "${entries[@]}"; do
  name="${row#*|}"
  skip=0
"#,
    );

    for (idx, mask) in filter.iter().filter(|mask| !mask.is_empty()).enumerate() {
        script.push_str(&format!(
            "  if [[ \"$name\" == $FILTER_{idx} ]]; then skip=1; fi\n"
        ));
        if !mask.contains('*') && !mask.contains('?') && !mask.contains('[') {
            script.push_str(&format!(
                "  if [[ \"$name\" == *.* && \"${{name##*.}}\" == {} ]]; then skip=1; fi\n",
                shell_single_quote(mask)
            ));
        }
    }

    script.push_str(
        r#"
  if [ "$skip" -eq 0 ]; then
    filtered+=("$row")
  fi
done

deleted_files=()
deleted_dirs=()
index=0
for row in "${filtered[@]}"; do
  if [ "$index" -lt "$MAX_COUNT" ]; then
    index=$((index + 1))
    continue
  fi

  name="${row#*|}"
  full_path="$TARGET_RESOLVED/$name"
  if [ -d "$full_path" ]; then
    if rm -rf -- "$full_path"; then
      deleted_dirs+=("$name")
    fi
  else
    if rm -f -- "$full_path"; then
      deleted_files+=("$name")
    fi
  fi
  index=$((index + 1))
done

remaining_files=$(find "$TARGET_RESOLVED" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')
remaining_dirs=$(find "$TARGET_RESOLVED" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
filtered_count=${#filtered[@]}
deleted_files_count=${#deleted_files[@]}
deleted_dirs_count=${#deleted_dirs[@]}
timestamp=$(date '+%d-%m-%Y %H:%M:%S')

free_space="n/a"
total_space="n/a"
space_percent="n/a"
if df_line=$(df -BG "$TARGET_RESOLVED" 2>/dev/null | tail -n 1); then
  total_space=$(printf '%s' "$df_line" | awk '{print $2}')
  free_space=$(printf '%s' "$df_line" | awk '{print $4}')
  space_percent=$(printf '%s' "$df_line" | awk '{print $5}')
fi

printf '====================================\n'
printf '%s\n' "$timestamp"
printf '===================================\n'
printf 'Endpoint: %s\n' "$ENDPOINT_NAME"
printf 'Path: %s\n' "$TARGET_RESOLVED"
printf 'Max count: %s\n' "$MAX_COUNT"
printf 'Filter: '"#,
    );
    script.push_str(&shell_single_quote(&format!("{filter:?}")));
    script.push_str(
        r#"
printf '\n'

if [ "$filtered_count" -le "$MAX_COUNT" ]; then
  printf 'Files: %s\n' "$filtered_count"
  printf 'Nothing to delete ;)\n'
else
  printf 'Deleted %s files' "$deleted_files_count"
  if [ "$deleted_files_count" -gt 0 ]; then
    printf ':\n'
    printf '%s\n' "${deleted_files[@]}"
  else
    printf '\n'
  fi

  printf 'Deleted %s folders' "$deleted_dirs_count"
  if [ "$deleted_dirs_count" -gt 0 ]; then
    printf ':\n'
    printf '%s\n' "${deleted_dirs[@]}"
  else
    printf '\n'
  fi
fi

printf 'Remaining files: %s\n' "$remaining_files"
printf 'Remaining folders: %s\n' "$remaining_dirs"
printf 'Free space: %s (%s)\n' "$free_space" "$space_percent"
printf 'Total space: %s\n' "$total_space"
 "#,
    );

    script
}

fn build_remote_status_script(path: &str) -> String {
    let mut script = String::from(
        "set -eu\n\
shopt -s nullglob\n",
    );
    script.push_str(&build_remote_target_resolution_script(path));
    script.push_str(
        r#"
if [ ! -d "$TARGET_RESOLVED" ]; then
  printf 'ok=0\n'
  printf 'error=%s\n' "Failed to read directory: $TARGET_RESOLVED"
  exit 0
fi

files=$(find "$TARGET_RESOLVED" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
remaining_files=$(find "$TARGET_RESOLVED" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')
remaining_dirs=$(find "$TARGET_RESOLVED" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
free_space="n/a"
total_space="n/a"
space_percent="n/a"
if df_line=$(df -BG "$TARGET_RESOLVED" 2>/dev/null | tail -n 1); then
  total_space=$(printf '%s' "$df_line" | awk '{print $2}')
  free_space=$(printf '%s' "$df_line" | awk '{print $4}')
  space_percent=$(printf '%s' "$df_line" | awk '{print $5}')
fi

printf 'ok=1\n'
printf 'resolved_path=%s\n' "$TARGET_RESOLVED"
printf 'file_count=%s\n' "$files"
printf 'remaining_files=%s\n' "$remaining_files"
printf 'remaining_dirs=%s\n' "$remaining_dirs"
printf 'free_space=%s\n' "$free_space"
printf 'total_space=%s\n' "$total_space"
printf 'space_percent=%s\n' "$space_percent"
"#,
    );
    script
}

fn run_ssh_script(host: &str, script: &str) -> Result<(String, String, std::process::ExitStatus), String> {
    let remote_command = format!("bash -lc {}", shell_single_quote(script));
    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            host,
            &remote_command,
        ])
        .output()
        .map_err(|err| format!("Failed to execute ssh: {}", err))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok((stdout, stderr, output.status))
}

fn delete_old_files_over_ssh(
    host: &str,
    path: &str,
    max_count: i64,
    filter: &[String],
    name: &str,
) -> Result<String, String> {
    if host.trim().is_empty() {
        return Err("SSH endpoint host is empty".to_string());
    }

    let remote_script = build_remote_cleanup_script(path, max_count, filter, name);
    let (stdout, stderr, status) = run_ssh_script(host, &remote_script)?;

    if status.success() {
        Ok(stdout)
    } else {
        if !stderr.is_empty() && !stdout.is_empty() {
            Err(format!(
                "ssh exited with status {}\nstdout:\n{}\nstderr:\n{}",
                status, stdout, stderr
            ))
        } else if !stderr.is_empty() {
            Err(format!("ssh exited with status {}\nstderr:\n{}", status, stderr))
        } else if !stdout.is_empty() {
            Err(format!("ssh exited with status {}\nstdout:\n{}", status, stdout))
        } else {
            Err(format!("ssh exited with status {}", status))
        }
    }
}

fn parse_space_gb(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("n/a") || trimmed.is_empty() {
        return None;
    }
    let digits = trimmed.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    digits.parse::<u64>().ok()
}

fn ssh_endpoint_status(host: &str, path: &str) -> serde_json::Value {
    if host.trim().is_empty() {
        return serde_json::json!({
            "path": path,
            "fileCount": serde_json::Value::Null,
            "remainingFiles": serde_json::Value::Null,
            "remainingDirs": serde_json::Value::Null,
            "freeSpaceGb": serde_json::Value::Null,
            "wholeSpaceGb": serde_json::Value::Null,
            "spacePercent": serde_json::Value::Null,
            "statusError": "SSH host is empty"
        });
    }

    let script = build_remote_status_script(path);
    let (stdout, stderr, status) = match run_ssh_script(host, &script) {
        Ok(result) => result,
        Err(err) => {
            return serde_json::json!({
                "path": path,
                "fileCount": serde_json::Value::Null,
                "remainingFiles": serde_json::Value::Null,
                "remainingDirs": serde_json::Value::Null,
                "freeSpaceGb": serde_json::Value::Null,
                "wholeSpaceGb": serde_json::Value::Null,
                "spacePercent": serde_json::Value::Null,
                "statusError": err
            });
        }
    };

    if !status.success() {
        return serde_json::json!({
            "path": path,
            "fileCount": serde_json::Value::Null,
            "remainingFiles": serde_json::Value::Null,
            "remainingDirs": serde_json::Value::Null,
            "freeSpaceGb": serde_json::Value::Null,
            "wholeSpaceGb": serde_json::Value::Null,
            "spacePercent": serde_json::Value::Null,
            "statusError": if !stderr.is_empty() { stderr } else { format!("ssh exited with status {}", status) }
        });
    }

    let mut values = std::collections::HashMap::new();
    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    let ok = values.get("ok").map(|v| v == "1").unwrap_or(false);
    let resolved_path = values.get("resolved_path").cloned().unwrap_or_else(|| path.to_string());
    let status_error = if ok {
        serde_json::Value::Null
    } else {
        serde_json::json!(values.get("error").cloned().unwrap_or_else(|| "Unknown SSH status error".to_string()))
    };

    serde_json::json!({
        "path": resolved_path,
        "fileCount": values.get("file_count").and_then(|v| v.parse::<u64>().ok()),
        "remainingFiles": values.get("remaining_files").and_then(|v| v.parse::<u64>().ok()),
        "remainingDirs": values.get("remaining_dirs").and_then(|v| v.parse::<u64>().ok()),
        "freeSpaceGb": values.get("free_space").and_then(|v| parse_space_gb(v)),
        "wholeSpaceGb": values.get("total_space").and_then(|v| parse_space_gb(v)),
        "spacePercent": values.get("space_percent").cloned(),
        "statusError": status_error
    })
}

fn normalize_ssh_config_host(host: &str) -> Option<String> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains('*') || trimmed.contains('?') || trimmed.starts_with('!') {
        return None;
    }
    Some(trimmed.to_string())
}

fn ssh_config_candidates() -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(profile) = env::var("USERPROFILE") {
        candidates.push(Path::new(&profile).join(".ssh").join("config"));
    }
    if let Ok(home) = env::var("HOME") {
        candidates.push(Path::new(&home).join(".ssh").join("config"));
    }
    if let (Ok(home_drive), Ok(home_path)) = (env::var("HOMEDRIVE"), env::var("HOMEPATH")) {
        candidates.push(Path::new(&format!("{home_drive}{home_path}")).join(".ssh").join("config"));
    }

    let mut unique = std::collections::HashSet::new();
    candidates
        .into_iter()
        .filter(|path| unique.insert(path.clone()))
        .collect()
}

fn read_ssh_config_hosts_with_debug(debug: bool) -> Vec<String> {
    let mut hosts = std::collections::BTreeSet::new();
    let candidates = ssh_config_candidates();

    if debug {
        println!("--- SSH config debug start ---");
        println!("USERPROFILE = {:?}", env::var("USERPROFILE").ok());
        println!("HOME = {:?}", env::var("HOME").ok());
        println!("HOMEDRIVE = {:?}", env::var("HOMEDRIVE").ok());
        println!("HOMEPATH = {:?}", env::var("HOMEPATH").ok());
        for path in &candidates {
            println!("SSH config candidate: {}", path.display());
        }
    }

    let mut selected_path = None;
    let mut contents = None;
    for path in candidates {
        match fs::read(&path) {
            Ok(file_bytes) => {
                let file_contents = String::from_utf8_lossy(&file_bytes).into_owned();
                if debug {
                    println!(
                        "SSH config loaded from {} ({} bytes, decoded with UTF-8 lossy)",
                        path.display(),
                        file_bytes.len()
                    );
                }
                selected_path = Some(path);
                contents = Some(file_contents);
                break;
            }
            Err(err) => {
                if debug {
                    println!("SSH config read failed for {}: {}", path.display(), err);
                }
            }
        }
    }

    let contents = match contents {
        Some(contents) => contents,
        None => {
            if debug {
                println!("SSH config was not found in any candidate path");
                println!("--- SSH config debug end ---");
            }
            return vec![];
        }
    };

    for (line_no, line) in contents.lines().enumerate() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let directive = match parts.next() {
            Some(value) => value,
            None => continue,
        };

        if !directive.eq_ignore_ascii_case("Host") {
            continue;
        }

        if debug {
            println!("SSH config line {} matched Host: {}", line_no + 1, line);
        }

        for raw_host in parts {
            if let Some(host) = normalize_ssh_config_host(raw_host) {
                if debug {
                    println!("  accepted host alias: {}", host);
                }
                hosts.insert(host);
            } else if debug {
                println!("  skipped host token: {}", raw_host);
            }
        }
    }

    let result: Vec<String> = hosts.into_iter().collect();
    if debug {
        println!(
            "SSH config parse result from {}: {} host(s)",
            selected_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            result.len()
        );
        println!("SSH config hosts: {:?}", result);
        println!("--- SSH config debug end ---");
    }
    result
}

fn read_ssh_config_hosts() -> Vec<String> {
    read_ssh_config_hosts_with_debug(false)
}

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use actix_web::{get, post, HttpResponse, App, HttpServer, web, HttpRequest};

use actix_web::{dev::ServiceRequest, Error};
use actix_web_httpauth::{extractors::basic::BasicAuth, middleware::HttpAuthentication};
use actix_web::error::ErrorUnauthorized;

mod ui_assets;
use ui_assets::UiAssets;

// Health check endpoint (unprotected) to verify service availability
#[get("/api/health")]
async fn api_health() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/json")
        .body("{\"status\":\"ok\"}")
}

fn serve_ui_file(path: &str) -> HttpResponse {
    let files: Vec<_> = UiAssets::iter().collect();
    
    let asset = UiAssets::get(path)
        .or_else(|| UiAssets::get(&format!("dist-ui/{}", path)))
        .or_else(|| UiAssets::get(&format!("assets/{}", path)))
        .or_else(|| {
            let p = format!("dist-ui/{}", path);
            UiAssets::get(&p.trim_start_matches('/'))
        })
        .or_else(|| UiAssets::get(&format!("assets/{}", path).trim_start_matches('/')));
        // Disk fallback will be attempted after embedded asset checks below
    
    eprintln!("Looking for: '{}'", path);
    eprintln!("Available: {:?}", files);
    eprintln!("Result: {:?}", asset.is_some());
    
    if let Some(asset) = asset {
        let content_type = if path.ends_with(".html") {
            "text/html"
        } else if path.ends_with(".css") {
            "text/css"
        } else if path.ends_with(".js") {
            "application/javascript"
        } else if path.ends_with(".ico") || path.ends_with(".png") {
            "image/png"
        } else if path.ends_with(".svg") {
            "image/svg+xml"
        } else {
            "text/plain"
        };
        return HttpResponse::Ok()
            .content_type(content_type)
            .body(asset.data.to_vec());
    }

    // Disk fallback removed to rely solely on embedded assets for reliability

    HttpResponse::NotFound().body(format!("File not found: {}", path))
}

#[get("/config")]
async fn get_config(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    // Basic auth gate with explicit decode to ensure credentials are correct
    // Load current config to know what credentials to expect
    let cfg = read_config_simple();
    let settings_login = cfg.get("settings").and_then(|s| s.as_array()).and_then(|arr| arr.get(0)).and_then(|m| m.get("login")).and_then(|v| v.as_str()).unwrap_or("admin");
    let settings_passw = cfg.get("settings").and_then(|s| s.as_array()).and_then(|arr| arr.get(0)).and_then(|m| m.get("password")).and_then(|v| v.as_str()).unwrap_or("admin");

    // Parse Authorization header
    let authorized = if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Basic ") {
                let b64 = &auth_str[6..];
                if let Ok(decoded) = base64::decode(b64) {
                    if let Ok(creds) = std::str::from_utf8(&decoded) {
                        let mut parts = creds.splitn(2, ':');
                        let user = parts.next().unwrap_or("");
                        let pass = parts.next().unwrap_or("");
                        user == settings_login && pass == settings_passw
                    } else { false }
                } else { false }
            } else { false }
        } else { false }
    } else {
        false
    };

    if !authorized {
        return HttpResponse::Unauthorized()
            .append_header(("WWW-Authenticate", "Basic realm=\"Restricted\""))
            .finish();
    }

    // Return the in-memory config (which is safe even if config.json is missing on disk)
    HttpResponse::Ok().content_type("application/json").body(state.get_config().to_string())
}

#[get("/log")]
async fn log() -> HttpResponse {
    match fs::read_to_string("delete.log") {
        Ok(log_file) => HttpResponse::Ok().content_type("text/plain; charset=utf-8").body(log_file),
        Err(_) => HttpResponse::NotFound().content_type("text/html; charset=utf-8").body("<h1>There is no log file. Nothing was still deleted.</h1>"),
    }
}

#[get("/status")]
async fn api_status(state: web::Data<AppState>) -> HttpResponse {
    let config = state.get_config();
    
    let node_name = config["node"]["name"].as_str().unwrap_or("Unknown");
    let node_place = config["node"]["place"].as_str().unwrap_or("");
    let node_description = config["node"]["description"].as_str().unwrap_or("");

    let empty: Vec<serde_json::Value> = vec![];
    let groups_raw = config["groups"].as_array().unwrap_or(&empty);
    let default_period = config["settings"][0]["period"].as_i64().unwrap_or(15);
    
    let groups: Vec<_> = groups_raw.iter()
        .map(|group| {
            let group_name = group["name"].as_str().unwrap_or("Unnamed");
            let endpoints_raw = group["endpoints"].as_array().unwrap_or(&empty);
            
            let endpoints: Vec<_> = endpoints_raw.iter()
                .map(|ep| {
                    let endpoint_type = endpoint_type(ep);
                    let host = endpoint_host(ep);
                    let configured_path = ep["path"].as_str().unwrap_or("");
                    let period = ep["period"].as_i64().unwrap_or(default_period);
                    let stats = if endpoint_type == "ssh" {
                        ssh_endpoint_status(host, configured_path)
                    } else {
                        serde_json::json!({
                            "path": configured_path,
                            "fileCount": fs::read_dir(configured_path).map(|d| d.count()).unwrap_or(0),
                            "remainingFiles": serde_json::Value::Null,
                            "remainingDirs": serde_json::Value::Null,
                            "freeSpaceGb": get_free_space(configured_path).unwrap_or(0) / 1_000_000_000,
                            "wholeSpaceGb": get_whole_space(configured_path).unwrap_or(0) / 1_000_000_000,
                            "spacePercent": serde_json::Value::Null,
                            "statusError": serde_json::Value::Null
                        })
                    };

                    let filter: Vec<String> = ep["filter"]
                        .as_array()
                        .unwrap_or(&empty)
                        .iter()
                        .map(|v| v.as_str().unwrap_or("").to_string())
                        .collect();

                    serde_json::json!({
                        "name": ep["name"].as_str().unwrap_or(""),
                        "type": endpoint_type,
                        "host": host,
                        "path": stats["path"].clone(),
                        "count": ep["count"].as_i64().unwrap_or(0),
                        "enabled": ep["enabled"].as_bool().unwrap_or(false),
                        "filter": filter,
                        "period": period,
                        "fileCount": stats["fileCount"].clone(),
                        "remainingFiles": stats["remainingFiles"].clone(),
                        "remainingDirs": stats["remainingDirs"].clone(),
                        "freeSpaceGb": stats["freeSpaceGb"].clone(),
                        "wholeSpaceGb": stats["wholeSpaceGb"].clone(),
                        "spacePercent": stats["spacePercent"].clone(),
                        "statusError": stats["statusError"].clone()
                    })
                })
                .collect();

            serde_json::json!({
                "name": group_name,
                "endpoints": endpoints
            })
        })
        .collect();

    let status = serde_json::json!({
        "version": APP_VERSION,
        "node": {
            "name": node_name,
            "place": node_place,
            "description": node_description
        },
        "groups": groups
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .body(status.to_string())
}

#[get("/ssh-hosts")]
async fn api_ssh_hosts() -> HttpResponse {
    let hosts = read_ssh_config_hosts_with_debug(true);
    HttpResponse::Ok()
        .content_type("application/json")
        .body(serde_json::json!({ "hosts": hosts }).to_string())
}

#[derive(serde::Deserialize)]
struct ConfigUpdate {
    node: Option<serde_json::Value>,
    settings: Option<Vec<serde_json::Value>>,
    groups: Option<Vec<serde_json::Value>>,
}

#[derive(serde::Deserialize)]
struct GroupUpdate {
    name: Option<String>,
    endpoints: Option<Vec<serde_json::Value>>,
}

#[post("/config")]
async fn api_update_config(
    state: web::Data<AppState>,
    config: actix_web::web::Json<ConfigUpdate>
) -> HttpResponse {
    let mut current_config = state.get_config();

    if let Some(node) = config.node.clone() {
        current_config["node"] = node;
    }
    if let Some(settings) = config.settings.clone() {
        current_config["settings"] = serde_json::Value::Array(settings);
    }
    if let Some(groups) = config.groups.clone() {
        current_config["groups"] = serde_json::Value::Array(groups);
    }

    // Update state
    state.update_config(current_config.clone());
    
    // Also save to file
    let json_str = current_config.to_string();
    match fs::write("config.json", &json_str) {
        Ok(_) => {
            println!("Config updated and state notified");
            HttpResponse::Ok().content_type("application/json").body(r#"{"status":"ok"}"#)
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to write config: {}", e)),
    }
}

#[post("/groups/{group_index}")]
async fn api_update_group(
    state: web::Data<AppState>,
    group_index: web::Path<usize>,
    group: actix_web::web::Json<GroupUpdate>
) -> HttpResponse {
    let mut current_config = state.get_config();
    let idx = group_index.into_inner();
    
    let groups = current_config["groups"].as_array_mut().unwrap();
    
    if idx >= groups.len() {
        return HttpResponse::NotFound().body("Group not found");
    }
    
    let current_group = &mut groups[idx];
    
    if let Some(name) = group.name.clone() {
        current_group["name"] = serde_json::Value::String(name);
    }
    if let Some(endpoints) = group.endpoints.clone() {
        current_group["endpoints"] = serde_json::Value::Array(endpoints);
    }

    state.update_config(current_config.clone());
    
    let json_str = current_config.to_string();
    match fs::write("config.json", &json_str) {
        Ok(_) => HttpResponse::Ok().content_type("application/json").body(r#"{"status":"ok"}"#),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed: {}", e)),
    }
}

#[actix_web::delete("/groups/{group_index}")]
async fn api_delete_group(
    state: web::Data<AppState>,
    group_index: web::Path<usize>
) -> HttpResponse {
    let mut current_config = state.get_config();
    let idx = group_index.into_inner();
    
    let groups = current_config["groups"].as_array_mut().unwrap();
    
    if idx >= groups.len() {
        return HttpResponse::NotFound().body("Group not found");
    }
    
    groups.remove(idx);

    state.update_config(current_config.clone());
    
    let json_str = current_config.to_string();
    match fs::write("config.json", &json_str) {
        Ok(_) => HttpResponse::Ok().content_type("application/json").body(r#"{"status":"ok"}"#),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed: {}", e)),
    }
}

#[post("/groups")]
async fn api_create_group(
    state: web::Data<AppState>,
    group: actix_web::web::Json<GroupUpdate>
) -> HttpResponse {
    let mut current_config = state.get_config();
    
    let new_group = serde_json::json!({
        "name": group.name.clone().unwrap_or_else(|| "New Group".to_string()),
        "endpoints": group.endpoints.clone().unwrap_or_else(|| vec![])
    });
    
    current_config["groups"].as_array_mut().unwrap().push(new_group);

    state.update_config(current_config.clone());
    
    let json_str = current_config.to_string();
match fs::write("config.json", &json_str) {
        Ok(_) => HttpResponse::Ok().content_type("application/json").body(r#"{"status":"ok"}"#),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed: {}", e)),
    }
}

#[get("/log")]
async fn api_log() -> HttpResponse {
    match fs::read_to_string("delete.log") {
        Ok(log_file) => HttpResponse::Ok().content_type("application/json").body(serde_json::json!({ "log": log_file }).to_string()),
        Err(_) => HttpResponse::Ok().content_type("application/json").body(r#"{"log":""}"#),
    }
}

#[get("/")]
async fn index() -> HttpResponse {
    HttpResponse::Found()
        .append_header(("Location", "/ui"))
        .body("")
}

#[get("/index")]
async fn indexRedirect(state: web::Data<AppState>) -> HttpResponse {
    let config = state.get_config();
    let node_name = config["node"]["name"].as_str().unwrap();

    let html = format!(
        r#"<html>
        <h1>Welcome to bc-np {}</h1>
        <div><h2>Node: {}</h2></div>
        <ul>
            <li><a href="/ui">Web UI</a></li>
            <li><a href="/log">View Log</a></li>
            <li><a href="/config">View Config</a></li>
        </ul>
        </html>"#,
        APP_VERSION,
        node_name
    );

HttpResponse::Ok().content_type("text/html").body(html)
}

#[get("/ui/{file:.*}")]
async fn ui_file_handler(file: web::Path<String>) -> HttpResponse {
    serve_ui_file(&file)
}

#[get("/assets/{file:.*}")]
async fn assets_handler(file: web::Path<String>) -> HttpResponse {
    serve_ui_file(&file)
}

#[get("/ui")]
async fn ui_index() -> HttpResponse {
    serve_ui_file("index.html")
}

#[get("/ui/dashboard")]
async fn ui_dashboard() -> HttpResponse {
    serve_ui_file("index.html")
}

#[get("/ui/endpoints")]
async fn ui_endpoints() -> HttpResponse {
    serve_ui_file("index.html")
}

#[get("/ui/settings")]
async fn ui_settings() -> HttpResponse {
    serve_ui_file("index.html")
}

fn read_config_simple() -> serde_json::Value {
    // Try to read user config, but fall back to a safe defaults if missing or invalid
    let cfg = if let Ok(config_str) = std::fs::read_to_string("config.json") {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&config_str) {
            parsed
        } else {
            serde_json::json!({})
        }
    } else {
        serde_json::json!({})
    };
    // Debug logs removed
    // Return full cfg or defaults
    if cfg.as_object().unwrap_or(&serde_json::Map::new()).is_empty() {
        serde_json::json!({
            "node": { "name": "Unknown" },
            "settings": [
                {
                    "port": 8000,
                    "login": "admin",
                    "password": "admin",
                    "period": 15
                }
            ],
            "groups": []
        })
    } else {
        cfg
    }
}

async fn validator(
    req: ServiceRequest,
    credentials: BasicAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let path = req.path();
    // Debug logs removed for production
    
    // Skip auth for UI assets and static pages
    if path.starts_with("/ui") || path.starts_with("/assets") || path == "/" || path == "/index" {
        return Ok(req);
    }
    
    let config = read_config_simple();
    // Safer access to login/password with graceful fallback
    let settings_login = config
        .get("settings")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.get(0))
        .and_then(|m| m.get("login"))
        .and_then(|v| v.as_str())
        .unwrap_or("admin")
        .to_string();
    let settings_passw = config
        .get("settings")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.get(0))
        .and_then(|m| m.get("password"))
        .and_then(|v| v.as_str())
        .unwrap_or("admin")
        .to_string();

    // Allow login if username matches and password matches OR no password was provided (debug-friendly)
    let user_ok = credentials.user_id().eq(&settings_login);
    let pass_ok = credentials.password().map(|p| p == settings_passw).unwrap_or(false);
    if user_ok && pass_ok {
        Ok(req)
    } else {
        Err((ErrorUnauthorized("Unauthorized"), req))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = AppState::new();
    let port = state.get_config()["settings"][0]["port"].as_u64().unwrap_or(8000) as u16;
    
    let state_clone = state.clone();
    thread::spawn(move || run_config_job(state_clone));

    let state_web = web::Data::new(state);
    let state_for_handler = state_web.clone();

    HttpServer::new(move || {
        let auth = HttpAuthentication::basic(validator);

        App::new()
            .wrap(auth)
            .app_data(state_for_handler.clone())
            .service(ui_index)
            .service(ui_dashboard)
            .service(ui_endpoints)
            .service(ui_settings)
            .service(ui_file_handler)
            .service(assets_handler)
            .service(index)
            .service(indexRedirect)
            .service(api_health)
            .service(get_config)
            .service(log)
            .service(
                web::scope("/api")
                    .service(api_status)
                    .service(api_ssh_hosts)
                    .service(api_update_config)
                    .service(api_create_group)
                    .service(api_update_group)
                    .service(api_delete_group)
                    .service(api_log)
            )
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct MyULARGE_INTEGER {
    low_part: u32,
    high_part: u32,
}

impl From<MyULARGE_INTEGER> for u64 {
    fn from(value: MyULARGE_INTEGER) -> Self {
        ((value.high_part as u64) << 32) | (value.low_part as u64)
    }
}

fn get_free_space(path: &str) -> Option<u64> {
    let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    let mut free_bytes = MyULARGE_INTEGER {
        low_part: 0,
        high_part: 0,
    };
    let success = unsafe {
        winapi::um::fileapi::GetDiskFreeSpaceExW(
            wide_path.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut free_bytes as *mut _ as *mut _,
        ) != 0
    };
    if success {
        Some(u64::from(free_bytes))
    } else {
        None
    }
}

fn get_whole_space(path: &str) -> Option<u64> {
    let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    let mut total_bytes = MyULARGE_INTEGER {
        low_part: 0,
        high_part: 0,
    };
    let mut free_bytes = MyULARGE_INTEGER {
        low_part: 0,
        high_part: 0,
    };
    let mut dummy = MyULARGE_INTEGER {
        low_part: 0,
        high_part: 0,
    };
    let success = unsafe {
        winapi::um::fileapi::GetDiskFreeSpaceExW(
            wide_path.as_ptr(),
            &mut free_bytes as *mut _ as *mut _,
            &mut total_bytes as *mut _ as *mut _,
            &mut dummy as *mut _ as *mut _,
        ) != 0
    };
    if success {
        Some(u64::from(total_bytes))
    } else {
        None
    }
}

fn write_to_log_file(message: &str) -> Result<(), String> {
    let log_file_path = Path::new(".").join("delete.log");

    let mut log_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&log_file_path)
        .map_err(|err| format!("Failed to open log file: {}", err))?;

    let mut contents = String::new();
    log_file.read_to_string(&mut contents).unwrap_or_default();

    let mut log_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log_file_path)
        .map_err(|err| format!("Failed to reopen log file: {}", err))?;

        writeln!(log_file, "{}{}", message, contents.trim())
        .map_err(|err| format!("Failed to write to log file: {}", err))?;

    Ok(())
}

fn delete_old_files(
    path: &str,
    max_count: i64,
    filter: &[String],
    name: &str,
) -> Result<String, String> {
    let mut files: Vec<_> = match fs::read_dir(path) {
        Ok(entries) => entries.map(|res| res.unwrap()).collect(),
        Err(e) => return Err(format!("Failed to read directory: {}", e)),
    };

    files.sort_by(|a, b| {
        b.metadata()
            .unwrap_or_else(|e| panic!("Failed to read metadata ({:?}): {}", b.path(), e))
            .modified()
            .unwrap_or_else(|e| panic!("Failed to read modified time ({:?}): {}", b.path(), e))
            .cmp(
                &a.metadata()
                    .unwrap_or_else(|e| panic!("Failed to read metadata ({:?}): {}", a.path(), e))
                    .modified()
                    .unwrap_or_else(|e| {
                        panic!("Failed to read modified time ({:?}): {}", a.path(), e)
                    }),
            )
    });

    let mut deleted_files = 0;
    let mut deleted_folders = 0;
    let mut deleted_file_names = Vec::new();
    let mut deleted_folder_names = Vec::new();

    for file in files
        .iter()
        .filter(|file| {
            let name = file.file_name().to_string_lossy().to_string();
            let is_included_by_extension = {
                if let Some(extension) = file.path().extension().and_then(|ext| ext.to_str()) {
                    let ext_str = extension.to_string();
                    filter.iter().any(|mask| ext_str == *mask)
                } else {
                    false
                }
            };
            let is_included_by_name = filter.iter().any(|mask| {
                // glob Pattern matches against filename with wildcards support
                // e.g., "*.zip", "backup_*.*", "*_old.*"
                Pattern::new(mask).map(|p| p.matches(&name)).unwrap_or(false)
            });
            !is_included_by_extension && !is_included_by_name
        })
        .skip(max_count.try_into().unwrap())
    {
        if file.path().is_dir() {
            if let Err(e) = fs::remove_dir_all(file.path()) {
                println!("Failed to delete directory ({:?}): {}", file.path(), e);
            } else {
                deleted_folders += 1;
                deleted_folder_names.push(file.file_name().to_string_lossy().to_string());
            }
        } else {
            if let Err(e) = fs::remove_file(file.path()) {
                println!("Failed to delete file ({:?}): {}", file.path(), e);
            } else {
                deleted_files += 1;
                deleted_file_names.push(file.file_name().to_string_lossy().to_string());
            }
        }
    }

    let timestamp = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
    let deleted_file_names_str = deleted_file_names.join(",\n");
    let deleted_folder_names_str = deleted_folder_names.join(",\n");

    let mut free_space_str = String::new();
    let mut whole_space_str = String::new();
    let mut whole_space_gb = 0;
    let free_space_gb: u64;

    match get_whole_space(path) {
        Some(whole_space) => {
            whole_space_gb = whole_space / 1_000_000_000;
            whole_space_str = format!("{} GB", whole_space_gb);
        }
        None => println!("Failed to get free space on {}", path),
    }
    let mut space_percent: f64 = 0.0;
    match get_free_space(path) {
        Some(free_space) => {
            free_space_gb = free_space / 1_000_000_000;
            free_space_str = format!("{} GB", free_space_gb);
            space_percent = (free_space_gb as f64 / whole_space_gb as f64 * 100.0).round();
        }
        None => println!("Failed to get free space on {}", path),
    }

    let mut num_files = 0;
    let mut num_dirs = 0;

    for result in fs::read_dir(path).unwrap() {
        let entry = result.unwrap();
        if entry.path().is_file() {
            num_files += 1;
        } else if entry.path().is_dir() {
            num_dirs += 1;
        }
    }

    let message = format!(
r#"====================================
{timestamp}
===================================
Endpoint: {name}
Path: {path}
Max count: {max_count}
Filter: {:?}
Deleted {deleted_files} files{}
Deleted {deleted_folders} folders{}
Remaining files: {num_files}
Remaining folders: {num_dirs}
Free space: {free_space_str} ({space_percent}%)
Total space: {whole_space_str}
"#,
        filter,
        if deleted_files == 0 {
            "".to_string()
        } else {
            format!(":\n{}", deleted_file_names_str)
        },
        if deleted_folders == 0 {
            "".to_string()
        } else {
            format!(":\n{}", deleted_folder_names_str)
        },
    );

    Ok(message)
}

fn run_config_job(state: AppState) {
    let current_dir = env::current_dir().unwrap();

    std::thread::sleep(Duration::from_secs(2));

    let config = state.get_config();
    let port = config["settings"][0]["port"].as_u64().unwrap_or(8000);

    let node_name = config["node"]["name"].as_str().unwrap();
    let node_place = config["node"]["place"].as_str().unwrap();
    let node_description = config["node"]["description"].as_str().unwrap();

    println!("bc-np {}. All rights reserved.", APP_VERSION);
    println!(
        "Node: {}\nPlace: {}\nDescription: {}\nhttp port: {}\nPath: {}",
        node_name,
        node_place,
        node_description,
        port,
        current_dir.display()
    );

    std::thread::sleep(Duration::from_secs(3));

    let mut running = true;
    let mut last_config_str = String::new();

    loop {
        // Check if config was updated
        if state.was_updated() {
            println!("*** Config changed! Reloading... ***");
        }
        
        let config = state.get_config();
        let config_str = config.to_string();
        
        // Only process if config changed
        if config_str != last_config_str {
            println!("*** Config changed, processing... ***");
            last_config_str = config_str;
            running = true;
        }
        
        if !running {
            wait_with_config_interrupt(&state, 2);
            continue;
        }
        
        let default_period = config["settings"][0]["period"].as_u64().unwrap_or(15);
        
        let enabled_count_check = config["groups"].as_array().unwrap()
            .iter()
            .flat_map(|g| g["endpoints"].as_array().unwrap())
            .filter(|ep| ep["enabled"].as_bool().unwrap_or(false))
            .count();
        
        println!("--- Config check: {} enabled endpoints ---", enabled_count_check);
        
        let mut enabled_count = 0;
        let mut message = String::new();
        let mut formatted_message = String::new();
        
        for group in config["groups"].as_array().unwrap() {
            for endpoint in group["endpoints"].as_array().unwrap() {
                let name = endpoint["name"].as_str().unwrap();
                let endpoint_type = endpoint_type(endpoint);
                let host = endpoint_host(endpoint);
                let endpoint_name = endpoint_label(name, endpoint_type, host);
                let path = endpoint["path"].as_str().unwrap();
                let max_count = endpoint["count"].as_i64().unwrap();
                let is_enabled = endpoint["enabled"].as_bool().unwrap();
                let _period = endpoint["period"].as_u64().unwrap_or(default_period);
                let filter: Vec<String> = endpoint["filter"]
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .map(|value| value.as_str().unwrap_or_default().to_string())
                    .filter(|mask| !mask.is_empty())
                    .collect();

                if is_enabled {
                    enabled_count += 1;
                    if endpoint_type == "ssh" {
                        match delete_old_files_over_ssh(host, path, max_count, &filter, &endpoint_name) {
                            Ok(msg) => {
                                println!("{}", msg);
                                message.push_str(&msg);
                                message.push('\n');
                            }
                            Err(err) => println!(
                                "Endpoint: {}\nFailed to clean remote path {} on host {}: {}",
                                endpoint_name,
                                path,
                                host,
                                err
                            ),
                        }
                    } else {
                        let files = match fs::read_dir(path) {
                            Ok(dir) => dir,
                            Err(_) => {
                                println!("Endpoint: {}\nThere isn't such directory: {}", endpoint_name, path);
                                continue;
                            }
                        };
                        let file_count = files.count();

                        if file_count > max_count.try_into().unwrap() {
                            match delete_old_files(path, max_count, &filter, &endpoint_name) {
                                Ok(msg) => {
                                    message.push_str(&msg);
                                }
                                Err(e) => println!("Error deleting old files: {}", e),
                            }
                        } else {
                            let mut free_space_str = String::new();
                            let mut whole_space_str = String::new();
                            let mut whole_space_gb = 0;
                            let mut free_space_gb = 0;
                            let space_percent: f64;

                            match get_whole_space(path) {
                                Some(whole_space) => {
                                    whole_space_gb = whole_space / 1_000_000_000;
                                    whole_space_str = format!("{} GB", whole_space_gb);
                                }
                                None => println!("Failed to get free space on {}", path),
                            }

                            match get_free_space(path) {
                                Some(free_space) => {
                                    free_space_gb = free_space / 1_000_000_000;
                                    free_space_str = format!("{} GB", free_space_gb);
                                }
                                None => println!("Failed to get free space on {}", path),
                            }

                            space_percent = (free_space_gb as f64 / whole_space_gb as f64 * 100.0).round();
                            let timestamp = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
                            formatted_message = format!(
r#"====================================
{timestamp}
===================================
Endpoint: {endpoint_name}
Path: {path}
Max count: {max_count}
Files: {file_count}
Filter: {filter:?}
Nothing to delete ;)
Free space: {free_space_str} ({space_percent}%)
Total space: {whole_space_str}
"#);
                        }
                        println!("{}", formatted_message);
                        message += &formatted_message;
                    }
                }
            }
        }
        match write_to_log_file(&message) {
            Ok(_) => {},
            Err(err) => eprintln!("Error to write to log file: {:?}", err),
        }
        
        if enabled_count == 0 {
            println!("No enabled endpoints, waiting for config change...");
            running = false;
            wait_with_config_interrupt(&state, 3);
            continue;
        }
        
        // Find min period among enabled endpoints
        let min_period = config["groups"].as_array().unwrap()
            .iter()
            .flat_map(|g| g["endpoints"].as_array().unwrap())
            .filter(|ep| ep["enabled"].as_bool().unwrap_or(false))
            .map(|ep| ep["period"].as_u64().unwrap_or(default_period))
            .min()
            .unwrap_or(default_period);
        
        println!("--- Next check in {}s ---", min_period);
        if wait_with_config_interrupt(&state, min_period) {
            println!("*** Config changed during wait, applying new schedule... ***");
        }
    }
}

fn wait_with_config_interrupt(state: &AppState, seconds: u64) -> bool {
    for _ in 0..seconds {
        std::thread::sleep(Duration::from_secs(1));
        if state.was_updated() {
            return true;
        }
    }
    false
}
