use actix_files::NamedFile;
use actix_web::Responder;
use actix_web::{http, web, App, HttpRequest, HttpResponse, HttpServer};
use anyhow::{Result, Context};
use askama_escape::{escape as escape_html_entity, Html};
use base64::engine::general_purpose;
use base64::Engine;
use libnixstore::Radix;
use percent_encoding::{utf8_percent_encode, CONTROLS};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{error::Error, fs::read_to_string};
use std::{fmt::Write, path::Path};
use tokio::{sync, task};

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

const BOOTSTRAP_SOURCE: &str = r#"
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
        integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65"
         crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"
          integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4"
          crossorigin="anonymous"></script>
"#;

const CARGO_NAME: &str = env!("CARGO_PKG_NAME");
const CARGO_VERSION: &str = env!("CARGO_PKG_VERSION");
const CARGO_HOME_PAGE: &str = env!("CARGO_PKG_HOMEPAGE");

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
  <title>Nix binary cache ({CARGO_NAME} {CARGO_VERSION})</title>
  {BOOTSTRAP_SOURCE}
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
          Powered by <a href="{CARGO_HOME_PAGE}">{CARGO_NAME}</a>
        </small>
      </div>
    </div>
  </div>
</body>
</html>
"#,
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

async fn health() -> Result<HttpResponse, Box<dyn Error>> {
    Ok(HttpResponse::Ok().body("OK\n"))
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


fn init_config() -> Result<Config> {
    let settings_file = std::env::var("CONFIG_FILE").unwrap_or_else(|_| "settings.toml".to_owned());
    let mut settings: Config = toml::from_str(
        &read_to_string(&settings_file)
            .with_context(|| format!("Couldn't read config file '{settings_file}'"))?
    ).with_context(|| format!("Couldn't parse config file '{settings_file}'"))?;
    settings.secret_key = get_secret_key(settings.sign_key_path.as_deref())?;
    Ok(settings)
}

fn get_secret_key(sign_key_path: Option<&str>) -> Result<Option<String>> {
    if let Some(path) = sign_key_path {
        let sign_key = read_to_string(path)
            .with_context(|| format!("Couldn't read sign_key file '{path}'"))?;
        let (_sign_host, sign_key64) = sign_key
            .split_once(':')
            .with_context(|| format!("Sign key in '{path}' does not contain a ':'"))?;
        let sign_keyno64 = general_purpose::STANDARD
            .decode(sign_key64.trim())
            .with_context(|| format!("Couldn't base64::decode sign key from '{path}'"))?;
        if sign_keyno64.len() == 64 {
            return Ok(Some(sign_key.to_owned()));
        }
        log::error!("invalid signing key provided. signing disabled");
    }
    Ok(None)
}

/// Returns percent encoded file URL path.
macro_rules! encode_file_url {
    ($path:ident) => {
        utf8_percent_encode(&$path, CONTROLS)
    };
}

/// Returns HTML entity encoded formatter.
///
/// ```plain
/// " => &quot;
/// & => &amp;
/// ' => &#x27;
/// < => &lt;
/// > => &gt;
/// / => &#x2f;
/// ```
macro_rules! encode_file_name {
    ($entry:ident) => {
        escape_html_entity(&$entry.file_name().to_string_lossy(), Html)
    };
}

pub(crate) fn directory_listing(
    url_prefix: &Path,
    fs_path: &Path,
) -> Result<HttpResponse, Box<dyn Error>> {
    let path_without_store = fs_path
        .strip_prefix(libnixstore::get_store_dir())
        .unwrap_or(fs_path);
    let index_of = format!(
        "Index of {}",
        escape_html_entity(&path_without_store.to_string_lossy(), Html)
    );
    let mut rows = String::new();

    for entry in fs_path.read_dir()? {
        let entry = entry.unwrap();
        let p = match entry.path().strip_prefix(fs_path) {
            Ok(p) => url_prefix.join(p).to_string_lossy().into_owned(),
            Err(_) => continue,
        };

        // if file is a directory, add '/' to the end of the name
        if let Ok(metadata) = entry.metadata() {
            if metadata.is_dir() {
                let _ = write!(
                    rows,
                    "<tr><td><a href=\"{}\">{}/</a></td><td>-</td></tr>\n",
                    encode_file_url!(p),
                    encode_file_name!(entry),
                );
            } else {
                let _ = write!(
                    rows,
                    "<tr><td><a href=\"{}\">{}</a></td><td>-</td></tr>\n",
                    encode_file_url!(p),
                    encode_file_name!(entry),
                );
            }
        } else {
            continue;
        }
    }

    let html = format!(
        r#"
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <title>Nix binary cache ({CARGO_NAME} {CARGO_VERSION})</title>
  {BOOTSTRAP_SOURCE}
</head>
<body>
  <div class="container mt-4">
     <h1>{index_of}</h1>
     <hr>

     <ul>
     <table class="table table-striped">
             <thead>
                     <tr>
                             <th>Name</th>
                             <th>Size</th>
                     </tr>
             </thead>
             <tbody>
             {rows}
             </tbody>
     </table>
   </div>
</body>"#,
    );
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

async fn serve_nar_content(
    path: web::Path<(String, PathBuf)>,
    req: HttpRequest,
) -> Result<HttpResponse, Box<dyn Error>> {
    let (hash, dir) = path.into_inner();
    let dir = dir.strip_prefix("/").unwrap_or(&dir);

    let store_path = PathBuf::from(some_or_404!(nixhash(&hash)));
    let full_path = if dir == Path::new("") {
        store_path.clone()
    } else {
        store_path.join(dir)
    };
    if full_path.is_dir() {
        if full_path.join("index.html").exists() {
            return Ok(NamedFile::open_async(full_path.join("index.html"))
                .await?
                .respond_to(&req));
        }

        let url_prefix = PathBuf::from("/serve").join(&hash);
        let url_prefix = if dir == Path::new("") {
            url_prefix
        } else {
            url_prefix.join(dir)
        };
        directory_listing(&url_prefix, &full_path)
    } else {
        Ok(NamedFile::open_async(&full_path).await
           .with_context(|| format!("cannot open file: {}", full_path.display()))?.respond_to(&req))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    libnixstore::init();

    let config = match init_config() {
        Ok(v) => web::Data::new(v),
        Err(e) => {
            log::error!("{e}");
            e.chain().skip(1).for_each(|cause| log::error!("because: {}", cause));
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
            .route("/serve/{hash}{path:.*}", web::get().to(serve_nar_content))
            .route("/log/{drv}", web::get().to(get_build_log))
            .route("/version", web::get().to(version))
            .route("/health", web::get().to(health))
            .route("/nix-cache-info", web::get().to(cache_info))
    })
    .workers(config.workers)
    .max_connection_rate(config.max_connection_rate)
    .bind(config.bind.clone())?
    .run()
    .await
}
