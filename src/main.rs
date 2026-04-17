use chrono::prelude::*;
use glob::Pattern;
use once_cell::sync::Lazy;
use std::convert::TryInto;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::thread;
use std::time::Duration;

fn read_config() -> serde_json::Value {
    let config = fs::read_to_string("config.json").expect("Unable to read config");
    serde_json::from_str(&config).expect("Invalid JSON format")
}

static CONFIG_JSON: Lazy<serde_json::Value> = Lazy::new(|| read_config());

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use actix_web::{get, post, HttpResponse, App, HttpServer, web};

use actix_web::{dev::ServiceRequest, Error};
use actix_web_httpauth::{extractors::basic::BasicAuth, middleware::HttpAuthentication};
use actix_web::error::ErrorUnauthorized;


#[get("/favicon.ico")]
async fn favicon() -> Result<HttpResponse, Error> {
    let pixel = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVQI12P4//8/AAX+Av7czFnnAAAAAElFTkSuQmCC";
    let decoded = base64::decode(pixel).map_err(|_| Error::from(std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to decode base64 image")))?;
    let body = actix_web::web::Bytes::copy_from_slice(&decoded);
    Ok(HttpResponse::Ok().content_type("image/png").body(body))
}

#[get("/config")]
async fn get_config() -> HttpResponse {
    match fs::read_to_string("config.json") {
        Ok(config_file) => HttpResponse::Ok().content_type("application/json").body(config_file),
        Err(_) => HttpResponse::NotFound().content_type("text/html; charset=utf-8").body("<h1>Unable to read the config file</h1>"),
    }
}

#[get("/log")]
async fn log() -> HttpResponse {
    match fs::read_to_string("delete.log") {
        Ok(log_file) => HttpResponse::Ok().content_type("text/plain; charset=utf-8").body(log_file),
        Err(_) => HttpResponse::NotFound().content_type("text/html; charset=utf-8").body("<h1>There is no log file. Nothing was still deleted.</h1>"),
    }
}

#[get("/api/status")]
async fn api_status() -> HttpResponse {
    let config = read_config();
    
    let node_name = config["node"]["name"].as_str().unwrap_or("Unknown");
    
    let node_name = config["node"]["name"].as_str().unwrap_or("Unknown");
    let node_place = config["node"]["place"].as_str().unwrap_or("");
    let node_description = config["node"]["description"].as_str().unwrap_or("");

    let empty: Vec<serde_json::Value> = vec![];
    let endpoints_raw = config["endpoints"].as_array().unwrap_or(&empty);
    
    let endpoints: Vec<_> = endpoints_raw.iter()
        .map(|ep| {
            let path = ep["path"].as_str().unwrap_or("");
            let file_count = fs::read_dir(path).map(|d| d.count()).unwrap_or(0);
            let free_space = get_free_space(path).unwrap_or(0) / 1_000_000_000;
            let whole_space = get_whole_space(path).unwrap_or(0) / 1_000_000_000;

            let filter: Vec<String> = ep["filter"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();

            serde_json::json!({
                "name": ep["name"].as_str().unwrap_or(""),
                "path": path,
                "count": ep["count"].as_i64().unwrap_or(0),
                "enabled": ep["enabled"].as_bool().unwrap_or(false),
                "filter": filter,
                "fileCount": file_count,
                "freeSpaceGb": free_space,
                "wholeSpaceGb": whole_space
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
        "endpoints": endpoints
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .body(status.to_string())
}

#[derive(serde::Deserialize)]
struct ConfigUpdate {
    node: Option<serde_json::Value>,
    settings: Option<Vec<serde_json::Value>>,
    endpoints: Option<Vec<serde_json::Value>>,
}

#[post("/api/config")]
async fn api_update_config(config: actix_web::web::Json<ConfigUpdate>) -> HttpResponse {
    let mut current_config = match fs::read_to_string("config.json") {
        Ok(c) => match serde_json::from_str::<serde_json::Value>(&c) {
            Ok(v) => v,
            Err(_) => return HttpResponse::BadRequest().body("Invalid config format"),
        },
        Err(_) => return HttpResponse::NotFound().body("Config file not found"),
    };

    if let Some(node) = config.node.clone() {
        current_config["node"] = node;
    }
    if let Some(settings) = config.settings.clone() {
        current_config["settings"] = serde_json::Value::Array(settings);
    }
    if let Some(endpoints) = config.endpoints.clone() {
        current_config["endpoints"] = serde_json::Value::Array(endpoints);
    }

    match fs::write("config.json", current_config.to_string()) {
        Ok(_) => {
            // Force lazy to reload
            let _ = Lazy::force(&CONFIG_JSON);
            HttpResponse::Ok().content_type("application/json").body(r#"{"status":"ok"}"#)
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to write config: {}", e)),
    }
}

#[get("/api/log")]
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
async fn indexRedirect() -> HttpResponse {
    let config = Lazy::force(&CONFIG_JSON);
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

fn serve_ui_file(path: &str) -> HttpResponse {
    let file_path = std::path::Path::new("src/ui").join(path);

    match fs::read(&file_path) {
        Ok(contents) => {
            let content_type = if path.ends_with(".html") {
                "text/html"
            } else if path.ends_with(".css") {
                "text/css"
            } else if path.ends_with(".js") {
                "application/javascript"
            } else if path.ends_with(".ico") {
                "image/png"
            } else {
                "text/plain"
            };
            HttpResponse::Ok().content_type(content_type).body(contents)
        }
        Err(_) => HttpResponse::NotFound().body("File not found"),
    }
}

#[get("/ui/{file:.*}")]
async fn ui_file_handler(file: web::Path<String>) -> HttpResponse {
    serve_ui_file(&file)
}

#[get("/ui")]
async fn ui_index() -> HttpResponse {
    serve_ui_file("login.html")
}

async fn validator(
    req: ServiceRequest,
    credentials: BasicAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let path = req.path();
    
    // Skip auth for /ui paths
    if path.starts_with("/ui") || path == "/" || path.is_empty() {
        return Ok(req);
    }
    
    let config = read_config();
    let settings_login = config["settings"][0]["login"].as_str().unwrap().to_string();
    let settings_passw = config["settings"][0]["password"].as_str().unwrap().to_string();

    if credentials.user_id().eq(&settings_login) && credentials.password().unwrap().eq(&settings_passw) {
        Ok(req)
    } else {
        Err((ErrorUnauthorized("Unauthorized"), req))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = read_config();
    let port = config["settings"][0]["port"].as_u64().unwrap_or(8000) as u16;
    thread::spawn(|| run_config_job());

    HttpServer::new(move || {
        let auth = HttpAuthentication::basic(validator);
        
        App::new()
            .service(ui_index)
            .service(ui_file_handler)
            .service(index)
            .service(indexRedirect)
            .service(favicon)
            .service(get_config)
            .service(log)
            .service(api_status)
            .service(api_update_config)
            .service(api_log)
            .wrap(auth)
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
                let path = Path::new(&name);
                Pattern::new(mask).unwrap().matches_path(path)
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

fn run_config_job() {
    let current_dir = env::current_dir().unwrap();

    let config = Lazy::force(&CONFIG_JSON);
    let period = config["settings"][0]["period"].as_u64().unwrap();
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

    std::thread::sleep(Duration::from_secs(5));

    loop {
        let config = Lazy::force(&CONFIG_JSON);
        let period = config["settings"][0]["period"].as_u64().unwrap();
        
        let mut enabled_count = 0;
        let mut message = String::new();
        let mut formatted_message = String::new();
        for endpoint in config["endpoints"].as_array().unwrap() {
            let name = endpoint["name"].as_str().unwrap();
            let path = endpoint["path"].as_str().unwrap();
            let max_count = endpoint["count"].as_i64().unwrap();
            let is_enabled = endpoint["enabled"].as_bool().unwrap();
            let filter: Vec<String> = endpoint["filter"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .map(|value| value.as_str().unwrap_or_default().to_string())
                .filter(|mask| !mask.is_empty())
                .collect();


            if is_enabled {
                enabled_count += 1;
                let files = match fs::read_dir(path) {
                    Ok(dir) => dir,
                    Err(_) => {
                        println!("Endpoint: {}\nThere isn't such directory: {}", name, path);
                        continue;
                    }
                };
                let file_count = files.count();


                if file_count > max_count.try_into().unwrap() {
                    match delete_old_files(path, max_count, &filter, name) {
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
Endpoint: {name}
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
        match write_to_log_file(&message) {
            Ok(_) => {},
            Err(err) => eprintln!("Error to write to log file: {:?}", err),
        }
        if enabled_count == 0 {
            println!("There are no activated endpoints. Turn on at least one and restart app.");
            break
        }
        std::thread::sleep(Duration::from_secs(period));
    }
}