use std::error::Error;

use actix_web::{http, web, HttpResponse};

use crate::{cache_control_max_age_1y, nixhash, some_or_404};

pub(crate) async fn get(hash: web::Path<String>) -> Result<HttpResponse, Box<dyn Error>> {
    let store_path = some_or_404!(nixhash(&hash));
    Ok(HttpResponse::Ok()
        .insert_header(cache_control_max_age_1y())
        .insert_header(http::header::ContentType(mime::APPLICATION_JSON))
        .body(libnixstore::get_nar_list(&store_path)?))
}
