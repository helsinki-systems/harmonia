use actix_web::{http, web, App, HttpRequest, HttpResponse, HttpServer};
use libnixstore::Radix;
use serde::{Deserialize, Serialize};
use std::{error::Error, fs::read_to_string, path::Path};
use tokio::{sync, task};
use base64::engine::general_purpose;
use base64::Engine;

// TODO(conni2461): still missing
// - handle downloadHash/downloadSize and fileHash/fileSize after implementing compression

// Credit actix_web actix-files: https://github.com/actix/actix-web/blob/master/actix-files/src/range.rs
#[derive(Debug)]
struct HttpRange {
    start: usize,
    length: usize,
}

impl HttpRange {
    /// Parses Range HTTP header string as per RFC 2616.
    ///
    /// `header` is HTTP Range header (e.g. `bytes=bytes=0-9`).
    /// `size` is full size of response (file).
    fn parse(header: &str, size: usize) -> Result<Vec<Self>, http_range::HttpRangeParseError> {
        http_range::HttpRange::parse(header, size as u64).map(|ranges| {
            ranges
                .iter()
                .map(|range| Self {
                    start: range.start as usize,
                    length: range.length as usize,
                })
                .collect()
        })
    }
}

fn nixhash(hash: &str) -> Option<String> {
    if hash.len() != 32 {
        return None;
    }
    libnixstore::query_path_from_hash_part(hash)
}

fn query_drv_path(drv: &str) -> Option<String> {
    nixhash(if drv.len() > 32 { &drv[0..32] } else { drv })
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
    nar_size: usize,
    refs: &[String],
) -> Result<Option<String>, Box<dyn Error>> {
    let root_store_dir = libnixstore::get_store_dir();
    if store_path[0..root_store_dir.len()] != root_store_dir || &nar_hash[0..7] != "sha256:" {
        return Ok(None);
    }

    let mut nar_hash = nar_hash.to_owned();
    if nar_hash.len() == 71 {
        nar_hash = format!(
            "sha256:{}",
            libnixstore::convert_hash("sha256", &nar_hash[7..], Radix::default())?
        );
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

fn extract_filename(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|v| v.to_str().map(ToOwned::to_owned))
}

fn cache_control_max_age(max_age: u32) -> http::header::CacheControl {
    http::header::CacheControl(vec![http::header::CacheDirective::MaxAge(max_age)])
}

fn cache_control_max_age_1y() -> http::header::CacheControl {
    cache_control_max_age(365 * 24 * 60 * 60)
}

fn cache_control_max_age_1d() -> http::header::CacheControl {
    cache_control_max_age(24 * 60 * 60)
}

fn cache_control_no_store() -> http::header::CacheControl {
    http::header::CacheControl(vec![http::header::CacheDirective::NoStore])
}

fn query_narinfo(
    store_path: &str,
    hash: &str,
    sign_key: Option<&str>,
) -> Result<NarInfo, Box<dyn Error>> {
    let path_info = libnixstore::query_path_info(store_path, Radix::default())?;
    let mut res = NarInfo {
        store_path: store_path.into(),
        url: format!(
            "nar/{}.nar?hash={}",
            path_info.narhash.split_once(':').map_or(hash, |x| x.1),
            hash
        ),
        compression: "none".into(),
        nar_hash: path_info.narhash,
        nar_size: path_info.size,
        references: vec![],
        deriver: None,
        system: None,
        sig: None,
        ca: path_info.ca,
    };

    let refs = path_info.refs.clone();
    if !path_info.refs.is_empty() {
        res.references = path_info
            .refs
            .into_iter()
            .filter_map(|r| extract_filename(&r))
            .collect::<Vec<String>>();
    }

    if let Some(drv) = path_info.drv {
        res.deriver = extract_filename(&drv);

        if libnixstore::is_valid_path(&drv) {
            res.system = Some(libnixstore::derivation_from_path(&drv)?.platform);
        }
    }

    if let Some(sk) = sign_key {
        let fingerprint = fingerprint_path(store_path, &res.nar_hash, res.nar_size, &refs)?;
        if let Some(fp) = fingerprint {
            res.sig = Some(libnixstore::sign_string(sk, &fp)?);
        }
    }

    Ok(res)
}

macro_rules! some_or_404 {
    ($res:expr) => {
        match $res {
            Some(val) => val,
            None => {
                return Ok(HttpResponse::NotFound()
                    .insert_header(cache_control_no_store())
                    .body("missed hash"))
            }
        }
    };
}

#[derive(Debug, Deserialize)]
pub struct Param {
    json: Option<String>,
}

async fn get_narinfo(
    hash: web::Path<String>,
    param: web::Query<Param>,
    settings: web::Data<Config>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let hash = hash.into_inner();
    let store_path = some_or_404!(nixhash(&hash));
    let narinfo = query_narinfo(&store_path, &hash, settings.secret_key.as_deref())?;

    if param.json.is_some() {
        Ok(HttpResponse::Ok()
            .insert_header(cache_control_max_age_1d())
            .json(narinfo))
    } else {
        let res = format_narinfo_txt(&narinfo);
        Ok(HttpResponse::Ok()
            .insert_header((http::header::CONTENT_TYPE, "text/x-nix-narinfo"))
            .insert_header(("Nix-Link", narinfo.url))
            .insert_header(cache_control_max_age_1d())
            .body(res))
    }
}

#[derive(Debug, Deserialize)]
pub struct NarRequest {
    hash: String,
}

// We send this error across thread boundaries, so it must be Send + Sync
#[derive(Debug)]
enum ThreadSafeError {}
impl std::error::Error for ThreadSafeError {}
impl std::fmt::Display for ThreadSafeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error")
    }
}

async fn stream_nar(
    _nar_hash: web::Path<String>,
    req: HttpRequest,
    info: web::Query<NarRequest>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let store_path = some_or_404!(libnixstore::query_path_from_hash_part(&info.hash));

    let size = libnixstore::query_path_info(&store_path, Radix::default())?.size;
    let mut rlength = size;
    let offset;
    let mut res = HttpResponse::Ok();

    let (tx, rx) =
        sync::mpsc::unbounded_channel::<Result<actix_web::web::Bytes, ThreadSafeError>>();
    let rx = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);

    // Credit actix_web actix-files: https://github.com/actix/actix-web/blob/master/actix-files/src/named.rs#L525
    let closure = if let Some(ranges) = req.headers().get(http::header::RANGE) {
        if let Ok(ranges_header) = ranges.to_str() {
            if let Ok(ranges) = HttpRange::parse(ranges_header, rlength) {
                rlength = ranges[0].length;
                offset = ranges[0].start;

                // don't allow compression middleware to modify partial content
                res.insert_header((
                    http::header::CONTENT_ENCODING,
                    http::header::HeaderValue::from_static("identity"),
                ));

                res.insert_header((
                    http::header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", offset, offset + rlength - 1, size,),
                ));
            } else {
                res.insert_header((http::header::CONTENT_RANGE, format!("bytes */{}", rlength)));
                return Ok(res.status(http::StatusCode::RANGE_NOT_SATISFIABLE).finish());
            };
        } else {
            return Ok(res.status(http::StatusCode::BAD_REQUEST).finish());
        };
        let mut send = 0;

        // we keep this closure extra to avoid unaligned copies in the non-range request case.
        Box::new(move |data: &[u8]| {
            let length = data.len();
            if offset <= send + length {
                let start = if offset > send { offset - send } else { 0 };
                let end = if (offset + rlength) < (send + length) {
                    start + rlength
                } else {
                    length
                };
                tx.send(Ok(web::Bytes::copy_from_slice(&data[start..end])))
                  .is_ok()
            } else {
                send += length;
                true
            }
        }) as Box<dyn FnMut(&[u8]) -> bool + Send + Sync>
    } else {
        Box::new(move |data: &[u8]| {
            // The copy here is not ideal but due async ownership tracking
            // with C++ seems impossible here.
            tx.send(Ok(web::Bytes::copy_from_slice(data))).is_ok()
        }) as Box<dyn FnMut(&[u8]) -> bool + Send + Sync>
    };

    task::spawn(async move {
        libnixstore::dump_path(&store_path, closure);
    });

    Ok(res
        .insert_header((http::header::CONTENT_TYPE, "application/x-nix-archive"))
        .insert_header((http::header::ACCEPT_RANGES, "bytes"))
        .insert_header(cache_control_max_age_1y())
        .body(actix_web::body::SizedStream::new(rlength as u64, rx)))
}

async fn get_build_log(drv: web::Path<String>) -> Result<HttpResponse, Box<dyn Error>> {
    let drv_path = some_or_404!(query_drv_path(&drv));
    if libnixstore::is_valid_path(&drv_path) {
        let build_log = some_or_404!(libnixstore::get_build_log(&drv_path));
        return Ok(HttpResponse::Ok()
            .insert_header(http::header::ContentType(mime::TEXT_PLAIN_UTF_8))
            .insert_header(cache_control_max_age_1y())
            .body(build_log));
    }
    Ok(HttpResponse::NotFound()
        .insert_header(cache_control_no_store())
        .finish())
}

async fn get_nar_list(hash: web::Path<String>) -> Result<HttpResponse, Box<dyn Error>> {
    let store_path = some_or_404!(nixhash(&hash));
    Ok(HttpResponse::Ok()
        .insert_header(cache_control_max_age_1y())
        .insert_header(http::header::ContentType(mime::APPLICATION_JSON))
        .body(libnixstore::get_nar_list(&store_path)?))
}

async fn index(config: web::Data<Config>) -> Result<HttpResponse, Box<dyn Error>> {
    Ok(HttpResponse::Ok()
        .insert_header(http::header::ContentType(mime::TEXT_HTML_UTF_8))
        .body(format!(
            r#"
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <title>Nix binary cache ({name} {version})</title>

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
        integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65"
         crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"
          integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4"
          crossorigin="anonymous"></script>
</head>
<body>
  <div class="container mt-3">
    <div class="row justify-content-md-center">
      <div class="col-md-auto">
        <p class="lead">
          This service, provides a "binary cache" for the
          <a href="https://nixos.org/nix/">Nix package manager</a>
        </p>
      </div>
    </div>
    <hr>
    <div class="row">
      <div class="col text-center">
        <h4 class="mb-3">Cache Info</h4>
        <p>Store Dir: {store}</p>
        <p>Want Mass Query: 1</p>
        <p>Priority: {priority}</p>
      </div>
    </div>
    <hr>
    <div class="row">
      <div class="col text-center">
        <small class="d-block mb-3 text-muted">
          Powered by <a href="{repo}">{name}</a>
        </small>
      </div>
    </div>
  </div>
</body>
</html>
"#,
            name = env!("CARGO_PKG_NAME"),
            version = env!("CARGO_PKG_VERSION"),
            repo = env!("CARGO_PKG_HOMEPAGE"),
            store = libnixstore::get_store_dir(),
            priority = config.priority,
        )))
}

async fn version() -> Result<HttpResponse, Box<dyn Error>> {
    Ok(HttpResponse::Ok().body(format!(
        "{} {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )))
}

async fn cache_info(config: web::Data<Config>) -> Result<HttpResponse, Box<dyn Error>> {
    Ok(HttpResponse::Ok()
        .insert_header((http::header::CONTENT_TYPE, "text/x-nix-cache-info"))
        .body(
            vec![
                format!("StoreDir: {}", libnixstore::get_store_dir()),
                "WantMassQuery: 1".to_owned(),
                format!("Priority: {}", config.priority),
                "".to_owned(),
            ]
            .join("\n"),
        ))
}

fn default_bind() -> String {
    "127.0.0.1:8080".into()
}

fn default_workers() -> usize {
    4
}

fn default_connection_rate() -> usize {
    256
}

fn default_priority() -> usize {
    30
}

// TODO(conni2461): users to restrict access
#[derive(Deserialize, Debug)]
struct Config {
    #[serde(default = "default_bind")]
    bind: String,
    #[serde(default = "default_workers")]
    workers: usize,
    #[serde(default = "default_connection_rate")]
    max_connection_rate: usize,
    #[serde(default = "default_priority")]
    priority: usize,
    #[serde(default)]
    sign_key_path: Option<String>,
    #[serde(default)]
    secret_key: Option<String>,
}

#[derive(Debug)]
struct ConfigError {
    details: String,
}

impl ConfigError {
    fn new(details: String) -> Self {
        Self { details }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.details)
    }
}

fn init_config() -> Result<Config, ConfigError> {
    let settings_file = std::env::var("CONFIG_FILE").unwrap_or_else(|_| "settings.toml".to_owned());
    let mut settings: Config = toml::from_str(
        &read_to_string(settings_file)
            .map_err(|e| ConfigError::new(format!("Couldn't read config file: {}", e)))?,
    )
    .map_err(|e| ConfigError::new(format!("Couldn't parse config file: {}", e)))?;
    settings.secret_key = get_secret_key(settings.sign_key_path.as_deref())?;
    Ok(settings)
}

fn get_secret_key(sign_key_path: Option<&str>) -> Result<Option<String>, ConfigError> {
    if let Some(path) = sign_key_path {
        let sign_key = read_to_string(path)
            .map_err(|e| ConfigError::new(format!("Couldn't read sign_key file: {}", e)))?;
        let (_sign_host, sign_key64) = sign_key
            .split_once(':')
            .ok_or_else(|| ConfigError::new("Sign key does not contain a ':'".into()))?;
        let sign_keyno64 = general_purpose::STANDARD.decode(sign_key64.trim())
            .map_err(|e| ConfigError::new(format!("Couldn't base64::decode sign key: {}", e)))?;
        if sign_keyno64.len() == 64 {
            return Ok(Some(sign_key.to_owned()));
        }
        log::error!("invalid signing key provided. signing disabled");
    }
    Ok(None)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    libnixstore::init();

    let config = match init_config() {
        Ok(v) => web::Data::new(v),
        Err(e) => {
            log::error!("{e}");
            std::process::exit(1);
        }
    };
    let config_data = config.clone();

    log::info!("listening on {}", config.bind);
    HttpServer::new(move || {
        App::new()
            .app_data(config_data.clone())
            .route("/", web::get().to(index))
            .route("/{hash}.ls", web::get().to(get_nar_list))
            .route("/{hash}.ls", web::head().to(get_nar_list))
            .route("/{hash}.narinfo", web::get().to(get_narinfo))
            .route("/{hash}.narinfo", web::head().to(get_narinfo))
            .route("/nar/{hash}.nar", web::get().to(stream_nar))
            .route("/log/{drv}", web::get().to(get_build_log))
            .route("/version", web::get().to(version))
            .route("/nix-cache-info", web::get().to(cache_info))
    })
    .workers(config.workers)
    .max_connection_rate(config.max_connection_rate)
    .bind(config.bind.clone())?
    .run()
    .await
}
