use actix_web::{ web, error, Result, HttpResponse, HttpRequest, http::{ StatusCode }, HttpMessage };
use crate::config;
use std::sync::Arc;
use tokio::process::Command;
use std::process::Stdio;
use tokio::io::BufReader;
use tokio::prelude::*;
use bytes::{ Bytes, BytesMut };
use std::task::{ Poll, Context };
use std::pin::Pin;
use std::io::Result as IoResult;
use futures::StreamExt;
use std::collections::BTreeMap;

pub(super) async fn info() -> String {
    // todo: more human info here
    format!("this git repository is a crate index")
}

struct BytesStream<T: AsyncRead + Unpin> {
    inner: T,
    buf: Vec<u8>,
}

impl<T: AsyncRead + Unpin> tokio::stream::Stream for BytesStream<T> {
    type Item = IoResult<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mself = Pin::into_inner(self);
        match Pin::new(&mut mself.inner).poll_read(cx, &mut mself.buf[..]) {
            Poll::Ready(Ok(count)) => {
                if count == 0 {
                    Poll::Ready(None)
                } else {
                    let bytes = Bytes::copy_from_slice(&mself.buf[0..count]);
                    Poll::Ready(Some(Ok(bytes)))
                }
            },
            Poll::Ready(Err(e)) => {
                Poll::Ready(Some(Err(e)))
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn serve_cgi(config: &Arc<config::Config>, req: &HttpRequest, path: &str, body: Option<&[u8]>) -> Result<HttpResponse> {
    // let path = req.path();
    // let git_index = path.find(".git/").unwrap();
    // let path = &path[git_index + 4..];

    let mut cgi_params: BTreeMap<&str, &str> = BTreeMap::new();
    let t = format!("{}", config.index_dir.display());
    cgi_params.insert("GIT_PROJECT_ROOT", &t);
    cgi_params.insert("PATH_INFO", path);
    cgi_params.insert("PATH_TRANSLATED", "");
    cgi_params.insert("REMOTE_USER", "registry");
    let t = req.connection_info();
    let addr = t.remote().unwrap_or(":").split(':').next().unwrap_or("");
    cgi_params.insert("REMOTE_ADDR", addr);
    cgi_params.insert("REMOTE_HOST", addr);
    cgi_params.insert("REMOTE_PORT", t.remote().unwrap_or(":").split(':').last().unwrap_or(""));
    cgi_params.insert("CONTENT_TYPE", req.content_type());
    cgi_params.insert("QUERY_STRING", req.query_string());
    let t = req.method().to_string();
    cgi_params.insert("REQUEST_METHOD", &t);
    cgi_params.insert("GIT_HTTP_EXPORT_ALL", "true");
    

    cgi_params.insert("REQUEST_URI", path);
    let t = format!("{}", body.as_ref().map(|x| x.len()).unwrap_or(0));
    cgi_params.insert("CONTENT_LENGTH", &t);
    cgi_params.insert("GATEWAY_INTERFACE", "CGI/1.1");
    cgi_params.insert("REDIRECT_STATUS", "200");

    // for (name, value) in cgi_params.iter() {
    //     println!("env: {}={}", name, value);
    // }
    let output = Command::new("git")
        .arg("http-backend")
        .envs(cgi_params)
        .current_dir(&config.index_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| {
            config.log_ingestor.error(format!("failed to spawn git http-backend: {:?}", e));
            error::ErrorServiceUnavailable("")
        })?;
    if let Some(body) = body {
        output.stdin.unwrap().write_all(body).await
            .map_err(|e| {
                config.log_ingestor.error(format!("failed to write stdin to git http-backend: {:?}", e));
                error::ErrorServiceUnavailable("")
            })?;
    } else {
        output.stdin.unwrap(); // drops
    }
    let mut builder = HttpResponse::build(StatusCode::OK);

    let mut stdout = BufReader::new(output.stdout.unwrap());
    let mut line = String::new();
    'outer: loop {
        stdout.read_line(&mut line).await.map_err(|e| {
            config.log_ingestor.error(format!("failed to read stdout header from git http-backend: {:?}", e));
            error::ErrorServiceUnavailable("")
        })?;
        if line.trim() == "" {
            break 'outer;
        }
        let (name, value) = match line.find(':') {
            None => {
                config.log_ingestor.error(format!("corrupt http header from git http-backend: {}", line));
                return Err(error::ErrorServiceUnavailable(""));
            },
            Some(i) => line.split_at(i),
        };
        let name = name.trim();
        let value = value[1..].trim();
        if name.to_lowercase() == "status" {
            let value = match value.find(' ') {
                None => value,
                Some(i) => &value[0..i],
            };

            builder.status(
                StatusCode::from_u16(
                    value.parse()
                        .map_err(|e| {
                            config.log_ingestor.error(format!("invalid status number from git http-backend: {:?}", e));
                            error::ErrorServiceUnavailable("")
                        })?
                )
                .map_err(|e| {
                    config.log_ingestor.error(format!("invalid status number from git http-backend: {:?}", e));
                    error::ErrorServiceUnavailable("")
                })?
            );
        } else {
            builder.header(name, value);
        }
        line.clear();
    }

    Ok(builder.streaming(
        BytesStream { inner: stdout, buf: vec![0; 1024] }
    ))
}

pub(super) async fn refs(req: HttpRequest) -> Result<HttpResponse> {
    let config: &Arc<config::Config> = req.app_data().unwrap();
    serve_cgi(config, &req, "/info/refs", None).await
}

pub(super) async fn upload_pack(req: HttpRequest, mut body: web::Payload) -> Result<HttpResponse> {
    let config: &Arc<config::Config> = req.app_data().unwrap();

    let mut bytes = BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item?);
    }

    serve_cgi(config, &req, "/git-upload-pack", Some(&bytes[..])).await
}

pub(super) async fn receive_pack() -> Result<String> {
    Err(error::ErrorForbidden("use cargo publish to update this index"))
}
