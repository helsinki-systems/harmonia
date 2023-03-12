use std::error::Error;

use actix_web::{http, web, HttpRequest, HttpResponse};
use libnixstore::Radix;
use serde::Deserialize;

use crate::{cache_control_max_age_1y, some_or_404};
use tokio::{sync, task};

#[derive(Debug, Deserialize)]
pub struct NarRequest {
    hash: String,
}

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

// We send this error across thread boundaries, so it must be Send + Sync
#[derive(Debug)]
enum ThreadSafeError {}
impl std::error::Error for ThreadSafeError {}
impl std::fmt::Display for ThreadSafeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error")
    }
}

pub(crate) async fn get(
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
