use chrono::prelude::*;
use glob::Pattern;
use std::convert::TryInto;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::thread;
use std::time::Duration;

use once_cell::sync::Lazy; 
static CONFIG_JSON: Lazy<serde_json::Value> = Lazy::new(|| {
    let config = fs::read_to_string("config.json").expect("Unable to read config");
    serde_json::from_str(&config).expect("Invalid JSON format")
});


const APP_VERSION: f64 = 0.1;
static mut NODE_NAME: Option<String> = None;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use actix_web::{get, HttpResponse, Result, App, HttpServer};
use serde::{Serialize};

use actix_web::{dev::ServiceRequest, Error};
use actix_web_httpauth::{extractors::basic::BasicAuth, middleware::HttpAuthentication};
use actix_web::error::ErrorUnauthorized;


#[derive(Serialize)]
struct Config {
    name: String,
    version: String,
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

#[get("/")]
async fn index() -> HttpResponse {
    let node_name = unsafe { NODE_NAME.clone() }.expect("NODE_NAME is not set");

    let html = format!(
        r#"<html>
        <h1>Welcome to bc-np {}</h1>
        <div><h2>Node: {}</h2></div>
        <ul>
            <li><a href="/log">View Log File</a></li>
            <li><a href="/config">View Config File</a></li>
        </ul>
        </html>"#,
        APP_VERSION,
        node_name
    );

    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn validator(
    req: ServiceRequest,
    credentials: BasicAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let settings_login = CONFIG_JSON["settings"][0]["login"].as_str().unwrap().to_string();
    let settings_passw = CONFIG_JSON["settings"][0]["password"].as_str().unwrap().to_string();

    if credentials.user_id().eq(&settings_login) && credentials.password().unwrap().eq(&settings_passw) {
        // eprintln!("{credentials:?}");
        Ok(req)
    } else {
        Err((ErrorUnauthorized("unauthorized"), req))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
        let node_name = CONFIG_JSON["node"]["name"].as_str().unwrap().to_string();
        unsafe {
            NODE_NAME = Some(node_name);
        }

    let port = CONFIG_JSON["settings"][0]["port"].as_u64().unwrap_or(8000);
    // Start the config job in a new thread
    thread::spawn(|| run_config_job());

    // Start the HTTP server
    HttpServer::new(|| {
        let auth = HttpAuthentication::basic(validator);
                App::new()
            .wrap(auth)   
            .service(index)
            .service(get_config)
            .service(log)
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

    writeln!(log_file, "{}{}", message, contents)
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
r#"
====================================
{timestamp}
====================================
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

    let period = CONFIG_JSON["settings"][0]["period"].as_u64().unwrap();
    let port = CONFIG_JSON["settings"][0]["port"].as_u64().unwrap_or(8000);

    let node_name = CONFIG_JSON["node"]["name"].as_str().unwrap();
    let node_place = CONFIG_JSON["node"]["place"].as_str().unwrap();
    let node_description = CONFIG_JSON["node"]["description"].as_str().unwrap();

    println!("bc-np {}", APP_VERSION);
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
        let mut enabled_count = 0;
        for endpoint in CONFIG_JSON["endpoints"].as_array().unwrap() {
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
                        break;
                    }
                };
                let file_count = files.count();

                let mut message = String::new();
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
                    message = format!(
r#"====================================
{timestamp}
====================================
Endpoint: {name}
Path: {path}
Max count: {max_count}
Files: {file_count}
Filter: {filter:?}
Nothing to delete ;)
Free space: {free_space_str} ({space_percent}%)
Total space: {whole_space_str}
"#
                    );
                }
                match write_to_log_file(&message) {
                    Ok(_) => {}, 
                    Err(err) => eprintln!("Error to write to log file: {:?}", err),
                }
                println!("{}", message);
            }
        }
        if enabled_count ==0 {
        println!("There are no activated endpoints. Turn on at least one and restart app.");
        break
        }
        std::thread::sleep(Duration::from_secs(period));
    }
}