use actix_web::{http, middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use config::{Config, ConfigError};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error, path::Path};
use tokio::sync;

// TODO(conni2461): conf file
// - users to restrict access

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
    fn parse(header: &str, size: usize) -> Result<Vec<HttpRange>, http_range::HttpRangeParseError> {
        log::info!("header: {}, size: {}", header, size);
        match http_range::HttpRange::parse(header, size as u64) {
            Ok(ranges) => Ok(ranges
                .iter()
                .map(|range| HttpRange {
                    start: range.start as usize,
                    length: range.length as usize,
                })
                .collect()),
            Err(e) => Err(e),
        }
    }
}

fn nixhash(hash: &str) -> Option<String> {
    if hash.len() != 32 {
        return None;
    }
    libnixstore::query_path_from_hash_part(hash)
}

fn query_drv_path(drv: &str) -> Option<String> {
    let drv = if drv.len() > 32 { &drv[0..32] } else { drv };
    if drv.len() != 32 {
        return None;
    }
    libnixstore::query_path_from_hash_part(drv)
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
            libnixstore::convert_hash("sha256", &nar_hash[7..], true)?
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
    match Path::new(path).file_name() {
        Some(v) => v.to_str().map(|v| v.to_owned()),
        None => None,
    }
}

fn query_narinfo(store_path: &str, sign_key: Option<&str>) -> Result<NarInfo, Box<dyn Error>> {
    let path_info = libnixstore::query_path_info(store_path, true)?;
    let mut res = NarInfo {
        store_path: store_path.into(),
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
            None => return Ok(HttpResponse::NotFound().body("missed hash")),
        }
    };
}

type NarStore = HashMap<String, String>;

#[derive(Debug, Deserialize)]
pub struct Param {
    json: Option<String>,
}

async fn get_narinfo(
    hash: web::Path<String>,
    param: web::Query<Param>,
    data: web::Data<sync::Mutex<NarStore>>,
    sign_key: web::Data<Option<String>>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let hash = hash.into_inner();
    let store_path = some_or_404!(nixhash(&hash));
    let narinfo = query_narinfo(&store_path, sign_key.as_deref())?;
    let mut nars = data.lock().await;
    nars.entry(
        narinfo
            .nar_hash
            .split(':')
            .nth(1)
            .ok_or("Could not split hash on :")?
            .to_owned(),
    )
    .or_insert(hash);
    drop(nars);

    if param.json.is_some() {
        Ok(HttpResponse::Ok().json(narinfo))
    } else {
        let res = format_narinfo_txt(&narinfo);
        Ok(HttpResponse::Ok()
            .insert_header((http::header::CONTENT_TYPE, "text/x-nix-narinfo"))
            .insert_header(("Nix-Link", narinfo.url))
            .body(res))
    }
}

async fn stream_nar(
    nar_hash: web::Path<String>,
    data: web::Data<sync::Mutex<NarStore>>,
    req: HttpRequest,
) -> Result<HttpResponse, Box<dyn Error>> {
    let hash = some_or_404!({
        let nars = data.lock().await;
        nars.get(&nar_hash.into_inner()).cloned()
    });
    let store_path = some_or_404!(nixhash(&hash));

    let size = libnixstore::query_path_info(&store_path, true)?.size;
    let mut rlength = size;
    let mut offset = 0;
    let mut res = HttpResponse::Ok();

    // Credit actix_web actix-files: https://github.com/actix/actix-web/blob/master/actix-files/src/named.rs#L525
    if let Some(ranges) = req.headers().get(http::header::RANGE) {
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
    };

    let (tx, rx) =
        sync::mpsc::unbounded_channel::<Result<actix_web::web::Bytes, actix_web::Error>>();
    let rx = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
    let mut send = 0;
    let closure = |data: &[u8]| {
        let length = data.len();
        if offset <= send + length {
            let start = if offset > send { offset - send } else { 0 };
            let end = if (offset + rlength) < (send + length) {
                start + rlength
            } else {
                length
            };
            // The copy here is not idea but due to async ownership tracking with C++ would be kind of hard.
            let data = Vec::from(data);
            tx.send(Ok(web::Bytes::from(data).slice(start..end))).is_ok()
        } else {
            send += length;
            true
        }
    };

    libnixstore::dump_path(&store_path, closure);

    Ok(res
        .insert_header((http::header::CONTENT_TYPE, "application/x-nix-archive"))
        .insert_header((http::header::ACCEPT_RANGES, "bytes"))
        .body(actix_web::body::SizedStream::new(rlength as u64, rx)))
}

async fn get_build_log(drv: web::Path<String>) -> Result<HttpResponse, Box<dyn Error>> {
    let drv_path = some_or_404!(query_drv_path(&drv));
    if libnixstore::is_valid_path(&drv_path) {
        let build_log = some_or_404!(libnixstore::get_build_log(&drv_path));
        return Ok(HttpResponse::Ok()
            .insert_header(http::header::ContentType(mime::TEXT_PLAIN_UTF_8))
            .body(build_log));
    }
    Ok(HttpResponse::NotFound().finish())
}

async fn get_nar_list(hash: web::Path<String>) -> Result<HttpResponse, Box<dyn Error>> {
    let store_path = some_or_404!(nixhash(&hash));
    Ok(HttpResponse::Ok().json(libnixstore::get_nar_list(&store_path)?))
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
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css"
        rel="stylesheet"
        integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC"
        crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"
          integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
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
            priority = config.get::<usize>("priority")?,
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
                format!("Priority: {}", config.get::<usize>("priority")?),
                "".to_owned(),
            ]
            .join("\n"),
        ))
}

fn init_config() -> Result<Config, ConfigError> {
    let settings_file = std::env::var("CONFIG_FILE").unwrap_or_else(|_| "settings.toml".to_owned());

    let mut builder = Config::builder()
        .set_default("bind", "127.0.0.1:8080")?
        .set_default("workers", 4)?
        .set_default("max_connection_rate", 256)?
        .set_default("priority", 30)?
        .set_default::<_, Option<String>>("sign_key_path", None)?;

    if Path::new(&settings_file).exists() {
        builder = builder.add_source(config::File::with_name(&settings_file))
    } else {
        log::warn!(
            "Config file {} was not found. Using default values",
            settings_file
        )
    }

    builder.build()
}

fn get_secret_key(sign_key_path: Option<&str>) -> Result<Option<String>, Box<dyn Error>> {
    if let Some(path) = sign_key_path {
        let sign_key = std::fs::read_to_string(path)?;
        let (_sign_host, sign_key64) = sign_key
            .split_once(':')
            .ok_or("Sign key does not contain a ':'")?;
        let sign_keyno64 = base64::decode(sign_key64)?;
        if sign_keyno64.len() != 64 {
            log::error!("invalid signing key provided. signing disabled");
        } else {
            return Ok(Some(sign_key.to_owned()));
        }
    }
    Ok(None)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,actix_web=debug"),
    )
    .init();

    libnixstore::init();

    let config = init_config().expect("Could not parse config file");
    let bind = config
        .get::<String>("bind")
        .expect("No hostname to bind on set");
    let workers = config
        .get::<usize>("workers")
        .expect("No workers option as usize was set");
    let max_connection_rate = config
        .get::<usize>("max_connection_rate")
        .expect("No max_connection_rate option as usize was set");
    let sign_key_path = config
        .get::<Option<String>>("sign_key_path")
        .expect("sign_key_path should be at least None, but it isn't. This shouldn't happen");
    let secret_key = get_secret_key(sign_key_path.as_deref())
        .expect("Unexpected error while extracting the secret key");

    let narstore_data = web::Data::new(sync::Mutex::new(NarStore::new()));
    let conf_data = web::Data::new(config);
    let secret_key_data = web::Data::new(secret_key);

    log::info!("listening on {}", bind);
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            // .wrap(middleware::Compress::default())
            .app_data(narstore_data.clone())
            .app_data(conf_data.clone())
            .app_data(secret_key_data.clone())
            .route("/", web::get().to(index))
            .route("/{hash}.ls", web::get().to(get_nar_list))
            .route("/{hash}.narinfo", web::get().to(get_narinfo))
            .route("/{hash}.narinfo", web::head().to(get_narinfo))
            .route("/nar/{hash}.nar", web::get().to(stream_nar))
            .route("/log/{drv}", web::get().to(get_build_log))
            .route("/version", web::get().to(version))
            .route("/nix-cache-info", web::get().to(cache_info))
    })
    .workers(workers)
    .max_connection_rate(max_connection_rate)
    .bind(bind)?
    .run()
    .await
}
