use actix_web::{ web::{self, Json}, error, Result, HttpRequest, HttpResponse, http::{ StatusCode } };
use futures::{StreamExt};
use bytes::BytesMut;
use crate::config;
use std::sync::Arc;
use serde::{ Deserialize, Serialize };
use sha2::Sha256;
use sha2::Digest;
use semver::Version;
use crc::crc32;
use regex::Regex;

lazy_static! {
    pub static ref CRATE_NAME_REGEX: Regex = Regex::new(r#"^[a-zA-Z][a-zA-Z0-9-_]{0,63}$"#).unwrap();
}

fn ascii_check(s: &str) -> bool {
    !s.as_bytes().iter().any(|x| *x == 0 || *x >= 127)
}


#[derive(Serialize, Deserialize)]
pub(super) struct RegistryError {
    pub detail: String,
}

#[derive(Serialize, Deserialize)]
pub(super) enum RegistryResponse {
    #[serde(rename = "ok")]
    Ok(bool),
    #[serde(rename = "warnings")]
    Warnings(config::Warnings),
    #[serde(rename = "errors")]
    Errors(Vec<RegistryError>),
}

// cargo doesn't include Basic
#[derive(Debug, Clone)]
pub struct CargoAuth {
    user_id: String,
    token: String,
}

impl actix_web::FromRequest for CargoAuth {
    type Future = futures::future::Ready<Result<Self, Self::Error>>;
    type Error = error::Error;
    type Config = ();

    fn from_request(
        req: &HttpRequest,
        _: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let header = req.headers().get("authorization").map(|x| x.to_str().ok()).flatten();
        if let Some(header) = header {
            let split_index = header.find(':');
            if let Some(split_index) = split_index {
                let (user_id, token) = header.split_at(split_index);
                return futures::future::ready(Ok(CargoAuth {
                    user_id: user_id.to_string(),
                    token: (&token[1..]).to_string(),
                }));
            }
        }
        futures::future::ready(Err(error::ErrorUnauthorized("no authorization header found or invalid. ex. 'Authorization: username:token'")))
    }
}


async fn authenticate<'a>(config: &Arc<config::Config>, auth: &'a CargoAuth) -> Result<&'a str> {
    match config.user_provider.authenticate_user(&auth.user_id, &auth.token).await {
        Ok(false) => Err(error::ErrorForbidden("invalid username/token")),
        Ok(true) => Ok(&auth.user_id),
        Err(e) => {
            config.log_ingestor.error(format!("error authenticating user: {:?}", e));
            Err(error::ErrorServiceUnavailable("service unavailable"))
        },
    }
}

pub(super) async fn new(req: HttpRequest, auth: CargoAuth, mut body: web::Payload) -> Result<Json<RegistryResponse>> {
    let config: &Arc<config::Config> = req.app_data().unwrap();
    let username = authenticate(config, &auth).await?;

    let mut bytes = BytesMut::new();
    while let Some(item) = body.next().await {
        bytes.extend_from_slice(&item?);
    }

    if bytes.len() < 4 {
        return Err(error::ErrorBadRequest("body too short"));
    }
    let mut metadata_len: [u8; 4] = [0; 4];
    metadata_len.copy_from_slice(&bytes[0..4]);
    let metadata_len = u32::from_le_bytes(metadata_len) as usize;
    if bytes.len() < 4 + metadata_len {
        return Err(error::ErrorBadRequest("body too short"));
    }

    let metadata = &bytes[4..4 + metadata_len];
    let metadata = String::from_utf8_lossy(metadata);
    if !ascii_check(&metadata) {
        return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "invalid non-ascii characters present in metadata".to_string() }])));
    }
    let metadata: config::ApiCrate = serde_json::from_str(&metadata)
        .map_err(|e| {
            error::ErrorBadRequest(format!("malformed json: {:?}", e))
        })?;
    
    let existing_crate = config.crate_provider.get(&metadata.name, None).await
        .map_err(|e| {
            config.log_ingestor.error(format!("error fetching crate: {:?}", e));
            error::ErrorServiceUnavailable("service unavailable")
        })?;
    
    if let Some(existing_crate) = &existing_crate {
        if !existing_crate.owners.iter().any(|x| x == username) {
            return Err(error::ErrorUnauthorized(""));
        }

        if existing_crate.api_crate.vers >= metadata.vers {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "a newer or equal version is already published".to_string() }])));
        }
    }

    if !CRATE_NAME_REGEX.is_match(&metadata.name) {
        return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "crate name must match the following regex: ^[a-zA-Z][a-zA-Z0-9-_]{0,63}$".to_string() }])));
    }
    if metadata.authors.len() < 1 {
        return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "you must specify at least 1 author in your Cargo.toml".to_string() }])));
    }
    if metadata.description.is_none() || metadata.description.as_ref().unwrap().trim() == "" {
        return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "you must specify a description in your Cargo.toml".to_string() }])));
    }
    for (feature_name, features) in metadata.features.iter() {
        if !ascii_check(feature_name) || features.iter().any(|x| !ascii_check(x)) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in features".to_string() }])));
        }
    }
    for author in metadata.authors.iter() {
        if !ascii_check(author) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in authors".to_string() }])));
        }
    }
    if let Some(description) = &metadata.description {
        if !ascii_check(description) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in description".to_string() }])));
        }
    }
    if let Some(documentation) = &metadata.documentation {
        if !ascii_check(documentation) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in documentation".to_string() }])));
        }
    }
    if let Some(homepage) = &metadata.homepage {
        if !ascii_check(homepage) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in homepage".to_string() }])));
        }
    }
    if let Some(readme) = &metadata.readme {
        if !ascii_check(readme) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in readme".to_string() }])));
        }
    }
    if let Some(readme_file) = &metadata.readme_file {
        if !ascii_check(readme_file) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in readme_file".to_string() }])));
        }
    }
    for keyword in metadata.keywords.iter() {
        if !CRATE_NAME_REGEX.is_match(keyword) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in keywords".to_string() }])));
        }
    }
    for keyword in metadata.categories.iter() {
        if !CRATE_NAME_REGEX.is_match(keyword) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected categories in categories".to_string() }])));
        }
    }
    if let Some(license) = &metadata.license {
        if !ascii_check(license) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in license".to_string() }])));
        }
    }
    if let Some(license_file) = &metadata.license_file {
        if !ascii_check(license_file) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in license_file".to_string() }])));
        }
    }
    if let Some(repository) = &metadata.repository {
        if !ascii_check(repository) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in repository".to_string() }])));
        }
    }
    for (name, data) in metadata.badges.iter() {
        if !CRATE_NAME_REGEX.is_match(name) || data.iter().any(|(name, value)| !ascii_check(name) || !ascii_check(value)) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in badges".to_string() }])));
        }
    }
    if let Some(links) = &metadata.links {
        if !ascii_check(links) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in links".to_string() }])));
        }
    }
    for dependency in metadata.deps.iter() {
        if !CRATE_NAME_REGEX.is_match(&dependency.name) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in dependency name".to_string() }])));
        }
        if dependency.features.iter().any(|x| !ascii_check(x)) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in dependency features".to_string() }])));
        }
        if let Some(target) = &dependency.target {
            if !ascii_check(target) {
                return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in dependency target".to_string() }])));
            }
        }
        if !ascii_check(&dependency.kind) {
            return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in dependency kind".to_string() }])));
        }
        if let Some(registry) = &dependency.registry {
            if !ascii_check(registry) {
                return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in dependency registry".to_string() }])));
            }
        }
        if let Some(explicit_name_in_toml) = &dependency.explicit_name_in_toml {
            if !ascii_check(explicit_name_in_toml) {
                return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "unexpected tokens in dependency explicit_name_in_toml".to_string() }])));
            }
        }
    }
    if existing_crate.is_none() && !config.crate_provider.check_name_availability(&metadata.name).await
        .map_err(|e| {
            config.log_ingestor.error(format!("error checking name availability for crate crate: {:?}", e));
            error::ErrorServiceUnavailable("service unavailable")
        })? {
        return Ok(Json(RegistryResponse::Errors(vec![RegistryError { detail: "crate name was taken by a similar crate".to_string() }])));
    }

    let bytes = &bytes[4 + metadata_len..];
    if bytes.len() < 4 {
        return Err(error::ErrorBadRequest("body too short"));
    }
    let mut crate_len: [u8; 4] = [0; 4];
    crate_len.copy_from_slice(&bytes[0..4]);
    let crate_len = u32::from_le_bytes(crate_len) as usize;
    if bytes.len() < 4 + crate_len {
        return Err(error::ErrorBadRequest("body too short"));
    }
    let crate_file = &bytes[4..4 + crate_len];
    let mut crate_sha = Sha256::new();
    crate_sha.input(crate_file);
    let result = crate_sha.result();

    let warnings = config.crate_provider.publish(config::RegistryCrate {
        api_crate: metadata,
        yanked: false,
        cksum: hex::encode(result),
        owners: vec![username.to_string()],
        fetcher: config::CrateFetch::DirectFetch(Arc::new(crate_file.to_owned())),
    }).await.map_err(|e| {
        config.log_ingestor.error(format!("error publishing crate: {:?}", e));
        error::ErrorServiceUnavailable("service unavailable")
    })?;

    Ok(Json(RegistryResponse::Warnings(warnings)))
}

#[derive(Deserialize)]
pub(super) struct CrateInfo {
    crate_name: String,
    version: Version,
}

#[derive(Deserialize)]
pub(super) struct PartialCrateInfo {
    crate_name: String,
}

async fn get_crate(config: &Arc<config::Config>, crate_name: &str, version: Option<&Version>) -> Result<config::RegistryCrate> {
    let ccrate = config.crate_provider.get(crate_name, version).await
        .map_err(|e| {
            config.log_ingestor.error(format!("error fetching crate: {:?}", e));
            error::ErrorServiceUnavailable("service unavailable")
        })?;

    if let Some(_) = &ccrate {
        Ok(ccrate.unwrap())
    } else {
        Err(error::ErrorNotFound(""))
    }
}

async fn authorize_crate(config: &Arc<config::Config>, username: &str, crate_name: &str, version: Option<&Version>) -> Result<config::RegistryCrate> {
    let ccrate = get_crate(config, crate_name, version).await?;

    if !ccrate.owners.iter().any(|x| x == username) {
        Err(error::ErrorUnauthorized(""))
    } else {
        Ok(ccrate)
    }
}

pub(super) async fn yank(req: HttpRequest, auth: CargoAuth, info: web::Path<CrateInfo>) -> Result<Json<RegistryResponse>> {
    let config: &Arc<config::Config> = req.app_data().unwrap();
    let username = authenticate(config, &auth).await?;

    authorize_crate(config, username, &info.crate_name, Some(&info.version)).await?;

    config.crate_provider.yank(&info.crate_name, &info.version)
        .await
        .map_err(|e| {
            config.log_ingestor.error(format!("error yanking crate: {:?}", e));
            error::ErrorServiceUnavailable("service unavailable")
        })?;

    Ok(Json(RegistryResponse::Ok(true)))
}

pub(super) async fn unyank(req: HttpRequest, auth: CargoAuth, info: web::Path<CrateInfo>) -> Result<Json<RegistryResponse>> {
    let config: &Arc<config::Config> = req.app_data().unwrap();
    let username = authenticate(config, &auth).await?;

    authorize_crate(config, username, &info.crate_name, Some(&info.version)).await?;

    config.crate_provider.unyank(&info.crate_name, &info.version)
        .await
        .map_err(|e| {
            config.log_ingestor.error(format!("error yanking crate: {:?}", e));
            error::ErrorServiceUnavailable("service unavailable")
        })?;

    Ok(Json(RegistryResponse::Ok(true)))
}

pub(super) async fn download(req: HttpRequest, info: web::Path<CrateInfo>) -> Result<HttpResponse> {
    let config: &Arc<config::Config> = req.app_data().unwrap();

    let ccrate = get_crate(config, &info.crate_name, Some(&info.version)).await?;
    match &ccrate.fetcher {
        config::CrateFetch::DirectFetch(fetcher) => {
            let body = fetcher.fetch(&ccrate)
                .await
                .map_err(|e| {
                    config.log_ingestor.error(format!("error pulling crate: {:?}", e));
                    error::ErrorServiceUnavailable("service unavailable")
                })?;
            Ok(HttpResponse::from(body))
        },
        config::CrateFetch::Redirect(url) => {
            let mut builder = HttpResponse::build(StatusCode::FOUND);
            builder.set_header("Location", url.to_string());
            Ok(builder.finish())
        },
    }
}

#[derive(Serialize)]
pub(super) enum OwnerUsersResponse {
    #[serde(rename = "users")]
    Users(Vec<OwnerUser>),
}

#[derive(Serialize)]
pub(super) struct OwnerUser {
    id: u32,
    login: String,
    name: Option<String>,
}

pub(super) async fn get_owners(req: HttpRequest, info: web::Path<PartialCrateInfo>) -> Result<Json<OwnerUsersResponse>> {
    let config: &Arc<config::Config> = req.app_data().unwrap();

    let ccrate = get_crate(config, &info.crate_name, None).await?;
    Ok(Json(OwnerUsersResponse::Users(ccrate.owners.into_iter().map(|owner| {
        OwnerUser {
            id: crc32::checksum_ieee(owner.as_bytes()),
            login: owner,
            name: None,
        }
    }).collect())))
}

#[derive(Serialize)]
pub(super) struct OwnerChangeResponse {
    ok: bool,
    msg: String,
}

#[derive(Deserialize)]
pub(super) struct OwnerChangeRequest {
    users: Vec<String>,
}

pub(super) async fn add_owners(req: HttpRequest, auth: CargoAuth, info: web::Path<PartialCrateInfo>, body: web::Json<OwnerChangeRequest>) -> Result<Json<OwnerChangeResponse>> {
    let config: &Arc<config::Config> = req.app_data().unwrap();
    let username = authenticate(config, &auth).await?;

    let ccrate = authorize_crate(config, username, &info.crate_name, None).await?;
    let mut new_owners = ccrate.owners.clone();
    for owner in body.0.users {
        if ascii_check(&owner) && !new_owners.contains(&owner) {
            new_owners.push(owner);
        }
    }

    config.crate_provider.update_owners(&ccrate.api_crate.name, &ccrate.api_crate.vers, new_owners).await
        .map_err(|e| {
            config.log_ingestor.error(format!("error updating owners on crate: {:?}", e));
            error::ErrorServiceUnavailable("service unavailable")
        })?;
    Ok(Json(OwnerChangeResponse {
        ok: true,
        msg: format!("users have been added as owners of crate {}", ccrate.api_crate.name),
    }))
}

pub(super) async fn remove_owners(req: HttpRequest, auth: CargoAuth, info: web::Path<PartialCrateInfo>, body: web::Json<OwnerChangeRequest>) -> Result<Json<OwnerChangeResponse>> {
    let config: &Arc<config::Config> = req.app_data().unwrap();
    let username = authenticate(config, &auth).await?;

    let ccrate = authorize_crate(config, username, &info.crate_name, None).await?;
    let new_owners = ccrate.owners.clone().into_iter().filter(|x| !body.0.users.contains(x) || x == username).collect();

    config.crate_provider.update_owners(&ccrate.api_crate.name, &ccrate.api_crate.vers, new_owners).await
        .map_err(|e| {
            config.log_ingestor.error(format!("error updating owners on crate: {:?}", e));
            error::ErrorServiceUnavailable("service unavailable")
        })?;
    Ok(Json(OwnerChangeResponse { ok: true, msg: format!("users have been removed as owners of crate {}", &ccrate.api_crate.name) }))
}

#[derive(Deserialize)]
pub(super) struct SearchArgs {
    q: String,
    per_page: Option<u32>,
}

#[derive(Serialize)]
pub(super) struct SearchResults {
    crates: Vec<config::SearchResult>,
    meta: SearchResultMeta,
}

#[derive(Serialize)]
pub(super) struct SearchResultMeta {
    total: u32,
}

pub(super) async fn search(req: HttpRequest, args: web::Query<SearchArgs>) -> Result<Json<SearchResults>> {
    let config: &Arc<config::Config> = req.app_data().unwrap();

    let mut per_page = args.per_page.unwrap_or(10);
    if per_page < 1 {
        per_page = 1;
    } else if per_page > 100 {
        per_page = 100;
    }

    let crates = config.crate_provider.search(&args.q, per_page).await
        .map_err(|e| {
            config.log_ingestor.error(format!("error searching for crates: {:?}", e));
            error::ErrorServiceUnavailable("service unavailable")
        })?;
    Ok(Json(SearchResults {
        meta: SearchResultMeta { total: crates.len() as u32 },
        crates,
    }))
}
