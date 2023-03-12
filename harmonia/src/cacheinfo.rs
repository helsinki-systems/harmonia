use std::error::Error;

use actix_web::{HttpResponse, web, http};
use crate::config;

pub(crate) async fn get(config: web::Data<config::Config>) -> Result<HttpResponse, Box<dyn Error>> {
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
