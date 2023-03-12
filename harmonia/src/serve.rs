use std::{error::Error, path::{PathBuf, Path}};

use actix_files::NamedFile;
use actix_web::{web, HttpRequest, HttpResponse};
use std::fmt::Write;
use anyhow::Context;
use actix_web::Responder;
use percent_encoding::{utf8_percent_encode, CONTROLS};
use askama_escape::{escape as escape_html_entity, Html};

use crate::{BOOTSTRAP_SOURCE, CARGO_NAME, CARGO_VERSION, nixhash, some_or_404};

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

pub(crate) async fn get(
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
