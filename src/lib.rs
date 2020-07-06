#[macro_use]
pub mod result;

#[macro_use]
extern crate lazy_static;

mod api;
mod config;
mod git;
mod git_manager;
mod registry_api;

use actix_web::{middleware::Logger, web, App, HttpServer};
pub use async_trait::async_trait;
pub use config::*;
pub use result::*;
pub use semver::{Version, VersionReq};
use std::sync::Arc;
use std::thread;

async fn index() -> String {
    format!("registry_api crate")
}

async fn me() -> String {
    format!("registry_api crate me")
}

pub async fn spawn_within_actix(config: Config) {
    let config = Arc::new(config.clone());
    let bind_addr = config.bind_addr.clone();
    tokio::spawn(config.git_manager.clone().reset_git_worker(config.clone()));

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::new(
                r#"%a "%r" %s %b "%{Referer}i" "%{User-Agent}i" %T"#,
            ))
            .app_data(config.clone())
            .route("/", web::get().to(index))
            .route("/registry/me", web::get().to(me))
            .service(web::scope("/api"))
            .service(
                web::scope("/registry/api/v1/crates")
                    .route("/new", web::put().to(registry_api::new))
                    .route(
                        "/{crate_name}/{version}/yank",
                        web::delete().to(registry_api::yank),
                    )
                    .route(
                        "/{crate_name}/{version}/unyank",
                        web::put().to(registry_api::unyank),
                    )
                    .route(
                        "/{crate_name}/{version}/download",
                        web::get().to(registry_api::download),
                    )
                    .route(
                        "/{crate_name}/owners",
                        web::get().to(registry_api::get_owners),
                    )
                    .route(
                        "/{crate_name}/owners",
                        web::put().to(registry_api::add_owners),
                    )
                    .route(
                        "/{crate_name}/owners",
                        web::delete().to(registry_api::remove_owners),
                    )
                    .route("", web::get().to(registry_api::search)),
            )
            .service(
                web::scope("/registry/index.git")
                    .route("/", web::get().to(git::info))
                    .route("/info/refs", web::get().to(git::refs))
                    .route("/git-upload-pack", web::post().to(git::upload_pack))
                    .route("/git-receive-pack", web::post().to(git::receive_pack)),
            )
    })
    .bind(&bind_addr)
    .unwrap()
    .run()
    .await
    .unwrap();
}

#[actix_rt::main]
pub async fn spawn_actix(config: Config) {
    spawn_within_actix(config).await;
}

pub fn spawn_thread(config: Config) {
    thread::spawn(move || {
        spawn_actix(config);
    });
}
