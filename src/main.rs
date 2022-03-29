mod nixstore;

use actix_web::http::{header, StatusCode};
use actix_web::web::Bytes;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use config::Config;
use derive_more::{Display, Error};
use log::info;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Mutex;
use std::{collections::HashMap, path::Path};

// TODO(conni2461): conf file
// - users to restrict access
// - signing

// TODO(conni2461): still missing
// - handle downloadHash/downloadSize and fileHash/fileSize after implementing compression

// Credit actix_web actix-files: https://github.com/actix/actix-web/blob/master/actix-files/src/range.rs
#[derive(Debug, Clone, Copy)]
pub struct HttpRange {
    /// Start of range.
    pub start: usize,

    /// Length of range.
    pub length: usize,
}

#[derive(Debug, Clone, Display, Error)]
#[display(fmt = "Parse HTTP Range failed")]
pub struct ParseRangeErr(#[error(not(source))] ());

impl HttpRange {
    /// Parses Range HTTP header string as per RFC 2616.
    ///
    /// `header` is HTTP Range header (e.g. `bytes=bytes=0-9`).
    /// `size` is full size of response (file).
    pub fn parse(header: &str, size: usize) -> Result<Vec<HttpRange>, ParseRangeErr> {
        info!("header: {}, size: {}", header, size);
        match http_range::HttpRange::parse(header, size as u64) {
            Ok(ranges) => Ok(ranges
                .iter()
                .map(|range| HttpRange {
                    start: range.start as usize,
                    length: range.length as usize,
                })
                .collect()),
            Err(_) => Err(ParseRangeErr(())),
        }
    }
}

fn nixhash(hash: &str) -> Option<String> {
    if hash.len() != 32 {
        return None;
    }
    nixstore::query_path_from_hash_part(hash)
}

#[derive(Debug, Serialize)]
struct NarInfo {
    store_path: String,
    url: String,
    compression: String,
    nar_hash: String,
    nar_size: usize,
    references: Vec<String>,
    deriver: Option<String>,
    system: Option<String>,
    sig: Option<String>,
    ca: Option<String>,
}

fn format_narinfo_txt(narinfo: &NarInfo) -> String {
    let mut res = vec![
        format!("StorePath: {}", narinfo.store_path),
        format!("URL: {}", narinfo.url),
        format!("Compression: {}", narinfo.compression),
        format!("FileHash: {}", narinfo.nar_hash),
        format!("FileSize: {}", narinfo.nar_size),
        format!("NarHash: {}", narinfo.nar_hash),
        format!("NarSize: {}", narinfo.nar_size),
    ];

    if !narinfo.references.is_empty() {
        res.push(format!("References: {}", &narinfo.references.join(" ")));
    }

    if let Some(drv) = &narinfo.deriver {
        res.push(format!("Deriver: {}", drv));
    }

    if let Some(sys) = &narinfo.system {
        res.push(format!("System: {}", sys));
    }

    if let Some(sig) = &narinfo.sig {
        res.push(format!("Sig: {}", sig));
    }

    if let Some(ca) = &narinfo.ca {
        res.push(format!("CA: {}", ca));
    }

    res.push("".into());
    res.join("\n")
}

fn fingerprint_path(
    store_path: &str,
    nar_hash: &str,
    nar_size: &str,
    refs: &[&str],
) -> Result<Option<String>, Box<dyn Error>> {
    let root_store_dir = nixstore::get_store_dir().ok_or("could not get nixstore dir")?;
    if store_path[0..root_store_dir.len()] != root_store_dir {
        return Ok(None);
    }
    if &nar_hash[0..7] != "sha256:" {
        return Ok(None);
    }

    let mut nar_hash = nar_hash.to_owned();
    if nar_hash.len() == 71 {
        let con = nixstore::convert_hash("sha256", &nar_hash[7..], true)
            .ok_or("could not convert nar_hash to sha256")?;
        nar_hash = format!("sha256:{}", con);
    }

    if nar_hash.len() != 59 {
        return Ok(None);
    }

    for r in refs {
        if r[0..root_store_dir.len()] != root_store_dir {
            return Ok(None);
        }
    }

    Ok(Some(format!(
        "1;{};{};{};{}",
        store_path,
        nar_hash,
        nar_size,
        refs.join(",")
    )))
}

fn query_narinfo(store_dir: &str) -> Result<NarInfo, Box<dyn Error>> {
    let path_info = nixstore::query_path_info(store_dir, true)?;
    let mut res = NarInfo {
        store_path: store_dir.into(),
        url: format!(
            "nar/{}.nar",
            path_info
                .narhash
                .split(':')
                .nth(1)
                .ok_or("Could not split hash on :")?
        ),
        compression: "none".into(),
        nar_hash: path_info.narhash,
        nar_size: path_info.size,
        references: Vec::<String>::new(),
        deriver: None,
        system: None,
        sig: None,
        ca: None,
    };

    if !path_info.refs.is_empty() {
        // TODO(conni2461): This is kinda ugly find a better solution
        res.references = path_info
            .refs
            .into_iter()
            .map(|r| -> Result<String, Box<dyn Error>> {
                Ok(Path::new(&r)
                    .file_name()
                    .ok_or("could not get file_name of path")?
                    .to_str()
                    .ok_or("os_str to str yeild a none")?
                    .to_owned())
            })
            .filter_map(Result::ok)
            .collect::<Vec<String>>();
    }

    if let Some(drv) = path_info.drv {
        res.deriver = Some(
            Path::new(&drv)
                .file_name()
                .ok_or("could not get file_name of path")?
                .to_str()
                .ok_or("os_str to str yeild a none")?
                .into(),
        );

        if nixstore::is_valid_path(&drv)? {
            let drvpath = nixstore::derivation_from_path(&drv)?;
            res.system = Some(drvpath.platform);
        }
    }

    if let Some(ca) = path_info.ca {
        res.ca = Some(ca);
    }

    //TODO(conni2461): sign_sk
    // if (defined $sign_sk) {
    //   my $fp  = fingerprintPath($storePath, $narhash, $size, $refs);
    //   my $sig = signString($sign_sk, $fp);
    //   push @res, "Sig: $sig";
    // }
    Ok(res)
}

type NarStore = HashMap<String, String>;

#[derive(Debug, Deserialize)]
pub struct Param {
    json: Option<String>,
}

async fn get_narinfo(
    hash: web::Path<String>,
    param: web::Query<Param>,
    data: web::Data<Mutex<NarStore>>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let hash = hash.into_inner();
    let store_path = nixhash(&hash);
    if store_path.is_none() {
        // TODO(conni2461): handle_miss
        return Ok(HttpResponse::NotFound().body("missed hash"));
    }
    let store_path = store_path.unwrap();
    let narinfo = query_narinfo(&store_path)?;
    {
        let mut nars = data.lock().expect("could not lock nars hashmap");
        nars.entry(
            narinfo
                .nar_hash
                .split(':')
                .nth(1)
                .ok_or("Could not split hash on :")?
                .to_owned(),
        )
        .or_insert(hash);
    }

    if param.json.is_some() {
        Ok(HttpResponse::Ok().json(narinfo))
    } else {
        let res = format_narinfo_txt(&narinfo);
        Ok(HttpResponse::Ok()
            .append_header(("content-type", "text/x-nix-narinfo"))
            .append_header(("Nix-Link", narinfo.url))
            .body(res))
    }
}

async fn stream_nar(
    nar_hash: web::Path<String>,
    data: web::Data<Mutex<NarStore>>,
    req: HttpRequest,
) -> Result<HttpResponse, Box<dyn Error>> {
    let hash = {
        let nars = data.lock().expect("Could not lock nars hashmap");
        nars.get(&nar_hash.into_inner()).cloned()
    };
    if hash.is_none() {
        // TODO(conni2461): handle_miss
        return Ok(HttpResponse::NotFound().body("missed hash"));
    }
    let hash = hash.unwrap();

    let store_path = nixhash(&hash);
    if store_path.is_none() {
        // TODO(conni2461): handle_miss
        return Ok(HttpResponse::NotFound().body("missed hash"));
    }
    let store_path = store_path.unwrap();
    let path_info = nixstore::query_path_info(&store_path, true)?;
    let exported =
        nixstore::export_path(&store_path, path_info.size).ok_or("Could not export path")?;

    let mut length = exported.len();
    let mut offset = 0;

    let mut res = HttpResponse::Ok();

    // Credit actix_web actix-files: https://github.com/actix/actix-web/blob/master/actix-files/src/named.rs#L525
    if let Some(ranges) = req.headers().get(header::RANGE) {
        if let Ok(ranges_header) = ranges.to_str() {
            if let Ok(ranges) = HttpRange::parse(ranges_header, length) {
                length = ranges[0].length;
                offset = ranges[0].start;

                // don't allow compression middleware to modify partial content
                res.insert_header((
                    header::CONTENT_ENCODING,
                    header::HeaderValue::from_static("identity"),
                ));

                res.insert_header((
                    header::CONTENT_RANGE,
                    format!(
                        "bytes {}-{}/{}",
                        offset,
                        offset + length - 1,
                        exported.len()
                    ),
                ));
            } else {
                res.insert_header((header::CONTENT_RANGE, format!("bytes */{}", length)));
                return Ok(res.status(StatusCode::RANGE_NOT_SATISFIABLE).finish());
            };
        } else {
            return Ok(res.status(StatusCode::BAD_REQUEST).finish());
        };
    };

    let bytes = Bytes::from(exported).slice(offset..(offset + length));

    Ok(res
        .append_header(("content-type", "application/x-nix-archive"))
        .append_header((header::ACCEPT_RANGES, "bytes"))
        .body(bytes))
}

async fn version() -> Result<HttpResponse, Box<dyn Error>> {
    Ok(HttpResponse::Ok().body("0.1.0"))
}

async fn cache_info(config: web::Data<Mutex<Config>>) -> Result<HttpResponse, Box<dyn Error>> {
    let config = config.lock().expect("could not lock config");
    Ok(HttpResponse::Ok()
        .append_header(("content-type", "text/x-nix-cache-info"))
        .body(
            vec![
                format!(
                    "StoreDir: {}",
                    nixstore::get_store_dir().ok_or("could not get nixstore dir")?
                ),
                "WantMassQuery: 1".to_owned(),
                format!("Priority: {}", config.get::<usize>("priority")?),
                "".to_owned(),
            ]
            .join("\n"),
        ))
}

fn init_config() -> Result<Config, Box<dyn Error>> {
    Ok(Config::builder()
        .set_default("bind", "127.0.0.1:8080")?
        .set_default("workers", 4)?
        .set_default("max_connection_rate", 256)?
        .set_default("priority", 30)?
        .set_default("loglevel", "info")?
        .add_source(config::File::with_name(
            &std::env::var("CONFIG_FILE").unwrap_or_else(|_| "settings.toml".to_owned()),
        ))
        .build()?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = init_config().expect("Could not parse config file");
    std::env::set_var(
        "RUST_LOG",
        format!(
            "{},actix_web=debug",
            config
                .get::<String>("loglevel")
                .expect("No loglevel was set in the config")
        ),
    );
    env_logger::init();
    let bind = config
        .get::<String>("bind")
        .expect("No hostname to bind on set");
    let workers = config
        .get::<usize>("workers")
        .expect("No workers option as usize was set");
    let max_connection_rate = config
        .get::<usize>("max_connection_rate")
        .expect("No max_connection_rate option as usize was set");
    let config_data = web::Data::new(Mutex::new(config));

    let actix_data = web::Data::new(Mutex::new(NarStore::new()));
    info!("listening on {}", bind);
    HttpServer::new(move || {
        App::new()
            .app_data(actix_data.clone())
            .app_data(config_data.clone())
            .route("/{hash}.narinfo", web::get().to(get_narinfo))
            .route("/nar/{hash}.nar", web::get().to(stream_nar))
            .route("/version", web::get().to(version))
            .route("/nix-cache-info", web::get().to(cache_info))
    })
    .workers(workers)
    .max_connection_rate(max_connection_rate)
    .bind(bind)?
    .run()
    .await
}
