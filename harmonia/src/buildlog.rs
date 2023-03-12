use std::error::Error;

use actix_web::{http, web, HttpResponse};

use crate::{cache_control_max_age_1y, cache_control_no_store, nixhash, some_or_404};

fn query_drv_path(drv: &str) -> Option<String> {
    nixhash(if drv.len() > 32 { &drv[0..32] } else { drv })
}

pub(crate) async fn get(drv: web::Path<String>) -> Result<HttpResponse, Box<dyn Error>> {
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
