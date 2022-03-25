mod nixstore;

use std::path::Path;

use actix_web::{web, App, Error, HttpResponse, HttpServer};
use log::info;

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
const PRIORITY: u32 = 30;

// http types:
// - narinfo -> 'text/x-nix-narinfo'

// TODO(conni2461):
// always_use_upstream logic
const ALWAYS_USE_UPSTREAM: bool = false;

fn nixhash(hash: String) -> (String, Option<String>) {
    if hash.len() != 32 {
        return (hash, None);
    }
    let store_path = nixstore::query_path_from_hash_part(&hash);
    (hash, store_path)
}

fn format_narinfo_txt(hash: &str, store_dir: &str) -> (String, (String, String)) {
    let path_info = nixstore::query_path_info(store_dir, true).unwrap();

    let mut res = vec![
        format!("StorePath: {}", store_dir),
        format!("URL: nar/{}.nar", hash),
        "Compression: none".into(),
        format!("NarHash: {}", path_info.narhash),
        format!("NarSize: {}", path_info.size),
    ];

    if path_info.refs.len() > 0 {
        res.push(format!(
            "References: {}",
            path_info
                .refs
                .into_iter()
                .map(|r| Path::new(&r)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned())
                .collect::<Vec<String>>()
                .join(" ")
        ));
    }

    if let Some(drv) = path_info.drv {
        res.push(format!(
            "Deriver: {}",
            Path::new(&drv).file_name().unwrap().to_str().unwrap()
        ));

        if nixstore::is_valid_path(&drv).unwrap() {
            let drvpath = nixstore::derivation_from_path(&drv).unwrap();
            res.push(format!("System: {}", drvpath.platform));
        }
    }

    //TODO(conni2461): sign_sk
    // if (defined $sign_sk) {
    //   my $fp  = fingerprintPath($storePath, $narhash, $size, $refs);
    //   my $sig = signString($sign_sk, $fp);
    //   push @res, "Sig: $sig";
    // }

    res.push("".into());
    (
        res.join("\n"),
        ("Nix-Link".into(), format!("/nar/{}.nar", path_info.narhash)),
    )
}

async fn get_narinfo(hash: web::Path<String>) -> Result<HttpResponse, Error> {
    let (hash, store_path) = nixhash(hash.into_inner());
    if store_path.is_none() {
        // TODO(conni2461): handle_miss
        return Ok(HttpResponse::Ok().body("missed hash"));
    }
    let store_path = store_path.unwrap();
    let (narinfo, header) = format_narinfo_txt(&hash, &store_path);
    Ok(HttpResponse::Ok().append_header(header).body(narinfo))
}

async fn stream_nar(hash: web::Path<String>) -> Result<HttpResponse, Error> {
    let (_, store_path) = nixhash(hash.into_inner());
    if store_path.is_none() {
        // TODO(conni2461): handle_miss
        return Ok(HttpResponse::Ok().body("missed hash"));
    }
    let store_path = store_path.unwrap();
    let path_info = nixstore::query_path_info(&store_path, true).unwrap();
    let export = nixstore::export_path(&store_path, path_info.size);

    Ok(HttpResponse::Ok()
        .append_header(("content_length", path_info.size))
        .append_header(("content_type", "application/x-nix-archive"))
        .body(export.unwrap()))
}

async fn version() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().body("0.1.0"))
}

async fn cache_info() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().body(
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
