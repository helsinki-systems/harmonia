mod nixstore;

use actix_web::{web, App, Error, HttpResponse, HttpServer};
use log::info;
use serde::{Deserialize, Serialize};
use std::path::Path;

// TODO(conni2461): conf file
// - users to restrict access
// - signing
// - listen, array multiple addresses
// - proxy
// - workers
// - clients?
// - status (no status page by default)
// - index_page (index page enabled by default)
// - priority 30
// - upstream (no default upstream)
// - handle downloadHash/downloadSize and fileHash/fileSize after implementing compression
const PRIORITY: u32 = 30;

// http types:
// - narinfo -> 'text/x-nix-narinfo'

// TODO(conni2461):
// always_use_upstream logic
// const ALWAYS_USE_UPSTREAM: bool = false;

fn nixhash(hash: &str) -> Option<String> {
    if hash.len() != 32 {
        return None;
    }
    nixstore::query_path_from_hash_part(&hash)
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
) -> Option<String> {
    let root_store_dir = nixstore::get_store_dir().unwrap();
    if store_path[0..root_store_dir.len()] != root_store_dir {
        return None;
    }
    if &nar_hash[0..7] != "sha256:" {
        return None;
    }

    let mut nar_hash = nar_hash.to_owned();
    if nar_hash.len() == 71 {
        let con = nixstore::convert_hash("sha256", &nar_hash[7..], true);
        if con.is_none() {
            return None;
        }
        nar_hash = format!("sha256:{}", con.unwrap());
    }

    if nar_hash.len() != 59 {
        return None;
    }

    for r in refs {
        if r[0..root_store_dir.len()] != root_store_dir {
            return None;
        }
    }

    Some(format!(
        "1;{};{};{};{}",
        store_path,
        nar_hash,
        nar_size,
        refs.join(",")
    ))
}

fn query_narinfo(hash: &str, store_dir: &str) -> NarInfo {
    let path_info = nixstore::query_path_info(store_dir, true).unwrap();
    let mut res = NarInfo {
        store_path: store_dir.into(),
        url: format!("nar/{}.nar", hash),
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
        res.references = path_info
            .refs
            .into_iter()
            .map(|r| {
                Path::new(&r)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<String>>();
    }

    if let Some(drv) = path_info.drv {
        res.deriver = Some(
            Path::new(&drv)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .into(),
        );

        if nixstore::is_valid_path(&drv).unwrap() {
            let drvpath = nixstore::derivation_from_path(&drv).unwrap();
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
    res
}

#[derive(Debug, Deserialize)]
pub struct Param {
    json: Option<String>,
}

async fn get_narinfo(
    hash: web::Path<String>,
    param: web::Query<Param>,
) -> Result<HttpResponse, Error> {
    let hash = hash.into_inner();
    let store_path = nixhash(&hash);
    if store_path.is_none() {
        // TODO(conni2461): handle_miss
        return Ok(HttpResponse::NotFound().body("missed hash"));
    }
    let store_path = store_path.unwrap();
    let narinfo = query_narinfo(&hash, &store_path);
    if param.json.is_some() {
        Ok(HttpResponse::Ok().json(narinfo))
    } else {
        let res = format_narinfo_txt(&narinfo);
        Ok(HttpResponse::Ok()
            .append_header(("content-type", "text/x-nix-narinfo"))
            .append_header(("Nix-Link", format!("/nar/{}.nar", narinfo.nar_hash)))
            .body(res))
    }
}

async fn stream_nar(hash: web::Path<String>) -> Result<HttpResponse, Error> {
    let hash = hash.into_inner();
    let store_path = nixhash(&hash);
    if store_path.is_none() {
        // TODO(conni2461): handle_miss
        return Ok(HttpResponse::NotFound().body("missed hash"));
    }
    let store_path = store_path.unwrap();
    let path_info = nixstore::query_path_info(&store_path, true).unwrap();
    let export_new = nixstore::export_path(&store_path, path_info.size).unwrap();

    Ok(HttpResponse::Ok()
        .append_header(("content-type", "application/x-nix-archive"))
        .body(export_new))
}

async fn version() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().body("0.1.0"))
}

async fn cache_info() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok()
        .append_header(("content-type", "text/x-nix-cache-info"))
        .body(
            vec![
                format!("StoreDir: {}", nixstore::get_store_dir().unwrap()),
                "WantMassQuery: 1".to_owned(),
                format!("Priority: {}", PRIORITY),
                "".to_owned(),
            ]
            .join("\n"),
        ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info,actix_web=debug");
    env_logger::init();

    info!("listening on port 8080");
    HttpServer::new(move || {
        App::new()
            .route("/{hash}.narinfo", web::get().to(get_narinfo))
            .route("/nar/{hash}.nar", web::get().to(stream_nar))
            .route("/version", web::get().to(version))
            .route("/nix-cache-info", web::get().to(cache_info))
    })
    .bind("127.0.0.1:8081")?
    .run()
    .await
}
