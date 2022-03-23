mod nixstore;

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
    return (hash, Some(nixstore::get_store_dir().unwrap()));
}

fn format_narinfo_txt(hash: &str, store_dir: &str) -> String {
    "".into()
}

async fn index(hash: web::Path<String>) -> Result<HttpResponse, Error> {
    let (hash, store_path) = nixhash(hash.into_inner());
    if store_path.is_none() {
        // TODO(conni2461): handle_miss
        return Ok(HttpResponse::Ok().body("missed hash"));
    }
    let store_path = store_path.unwrap();
    let narinfo = format_narinfo_txt(&hash, &store_path);

    Ok(HttpResponse::Ok().json({}))
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
            .route("/{hash}", web::get().to(index))
            .route("/version", web::get().to(version))
            .route("/nix-cache-info", web::get().to(cache_info))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
