mod nixstore;

use actix_web::{web, App, Error, HttpResponse, HttpServer};
use log::info;
use serde_json::json;

async fn index() -> Result<HttpResponse, Error> {
    let data = json!({});
    Ok(HttpResponse::Ok().json(data))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("{}", nixstore::get_store_dir().unwrap());
    println!("{}", nixstore::get_bin_dir().unwrap());
    std::env::set_var("RUST_LOG", "info,actix_web=debug");
    env_logger::init();

    info!("listening on port 8080");
    HttpServer::new(move || App::new().route("/", web::get().to(index)))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
