
use crate::result::*;
use serde::{ Deserialize, Serialize };
use std::collections::BTreeMap;
use semver::{ Version, VersionReq };
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use log::*;
use crate::git_manager::*;
use url::Url;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub bind_addr: String,
    pub index_dir: PathBuf,
    pub crate_provider: Arc<dyn CrateProvider>,
    pub user_provider: Arc<dyn UserProvider>,
    // default is Arc::new(())
    pub log_ingestor: Arc<dyn LogIngestor>,
    pub git_manager: Arc<Git>,
}

impl Config {
    pub fn new(bind_addr: &str, index_dir: &str, exposed_url: Url, crate_provider: Arc<dyn CrateProvider>, user_provider: Arc<dyn UserProvider>, log_ingestor: Option<Arc<dyn LogIngestor>>) -> Result<Config> {
        let index_dir = index_dir.parse::<PathBuf>()?;
        std::fs::create_dir_all(index_dir.parent().unwrap())?;
        let mut index_dir_parent = index_dir.parent().unwrap().canonicalize()?;
        index_dir_parent.push(index_dir.components().last().unwrap());

        Ok(Config {
            bind_addr: bind_addr.to_string(),
            index_dir: index_dir_parent.clone(),
            crate_provider,
            user_provider, 
            log_ingestor: log_ingestor.unwrap_or_else(|| Arc::new(())),
            git_manager: Arc::new(Git::new(index_dir_parent, exposed_url)?),
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApiDependency {
    /// Name of the dependency.
    /// If the dependency is renamed from the original package name,
    /// this is the original name. The new package name is stored in
    /// the `explicit_name_in_toml` field.
    pub name: String,
    /// The semver requirement for this dependency.
    pub version_req: VersionReq,
    /// Array of features (as strings) enabled for this dependency.
    pub features: Vec<String>,
    /// Boolean of whether or not this is an optional dependency.
    pub optional: bool,
    /// Boolean of whether or not default features are enabled.
    pub default_features: bool,
    /// The target platform for the dependency.
    /// null if not a target dependency.
    /// Otherwise, a string such as "cfg(windows)".
    pub target: Option<String>,
    /// The dependency kind.
    /// "dev", "build", or "normal".
    pub kind: String,
    /// The URL of the index of the registry where this dependency is
    /// from as a string. If not specified or null, it is assumed the
    /// dependency is in the current registry.
    pub registry: Option<String>,
    /// If the dependency is renamed, this is a string of the new
    /// package name. If not specified or null, this dependency is not
    /// renamed.
    pub explicit_name_in_toml: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct IndexDependency {
    /// Name of the dependency.
    /// If the dependency is renamed from the original package name,
    /// this is the original name. The new package name is stored in
    /// the `package` field.
    pub name: String,
    /// The semver requirement for this dependency.
    /// This must be a valid version requirement defined at
    /// https://github.com/steveklabnik/semver#requirements.
    pub req: VersionReq,
    /// Array of features (as strings) enabled for this dependency.
    pub features: Vec<String>,
    /// Boolean of whether or not this is an optional dependency.
    pub optional: bool,
    /// Boolean of whether or not default features are enabled.
    pub default_features: bool,
    /// The target platform for the dependency.
    /// null if not a target dependency.
    /// Otherwise, a string such as "cfg(windows)".
    pub target: Option<String>,
    /// The dependency kind.
    /// "dev", "build", or "normal".
    pub kind: String,
    /// The URL of the index of the registry where this dependency is
    /// from as a string. If not specified or null, it is assumed the
    /// dependency is in the current registry.
    pub registry: Option<String>,
    /// If the dependency is renamed, this is a string of the new
    /// package name. If not specified or null, this dependency is not
    /// renamed.
    pub package: Option<String>,
}

impl From<ApiDependency> for IndexDependency {
    fn from(dep: ApiDependency) -> IndexDependency {
        IndexDependency {
            name: dep.name,
            req: dep.version_req,
            features: dep.features,
            optional: dep.optional,
            default_features: dep.default_features,
            target: dep.target,
            kind: dep.kind,
            registry: dep.registry,
            package: dep.explicit_name_in_toml,
        }
    }
}

impl From<IndexDependency> for ApiDependency {
    fn from(dep: IndexDependency) -> ApiDependency {
        ApiDependency {
            name: dep.name,
            version_req: dep.req,
            features: dep.features,
            optional: dep.optional,
            default_features: dep.default_features,
            target: dep.target,
            kind: dep.kind,
            registry: dep.registry,
            explicit_name_in_toml: dep.package,
        }
    }
}

// api level crate
#[derive(Serialize, Deserialize, Clone)]
pub struct ApiCrate {
    /// The name of the package.
    pub name: String,
    /// The version of the package being published.
    pub vers: Version,
    /// Array of direct dependencies of the package.
    pub deps: Vec<ApiDependency>,
    /// Set of features defined for the package.
    /// Each feature maps to an array of features or dependencies it enables.
    /// Cargo does not impose limitations on feature names, but crates.io
    /// requires alphanumeric ASCII, `_` or `-` characters.
    pub features: BTreeMap<String, Vec<String>>,
    /// List of strings of the authors.
    /// May be empty. crates.io requires at least one entry.
    pub authors: Vec<String>,
    /// Description field from the manifest.
    /// May be null. crates.io requires at least some content.
    pub description: Option<String>,
    /// String of the URL to the website for this package's documentation.
    /// May be null.
    pub documentation: Option<String>,
    /// String of the URL to the website for this package's home page.
    /// May be null.
    pub homepage: Option<String>,
    /// String of the content of the README file.
    /// May be null.
    pub readme: Option<String>,
    /// String of a relative path to a README file in the crate.
    /// May be null.
    pub readme_file: Option<String>,
    /// Array of strings of keywords for the package.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Array of strings of categories for the package.
    #[serde(default)]
    pub categorires: Vec<String>,
    /// String of the license for the package.
    /// May be null. crates.io requires either `license` or `license_file` to be set.
    pub license: Option<String>,
    /// String of a relative path to a license file in the crate.
    /// May be null.
    pub license_file: Option<String>,
    /// String of the URL to the website for the source repository of this package.
    /// May be null.
    pub repository: Option<String>,
    /// Optional object of "status" badges. Each value is an object of
    /// arbitrary string to string mappings.
    /// crates.io has special interpretation of the format of the badges.
    pub badges: BTreeMap<String, BTreeMap<String, String>>,
    /// The `links` string value from the package's manifest, or null if not
    /// specified. This field is optional and defaults to null.
    pub links: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct IndexCrate {
    /// The name of the package.
    /// This must only contain alphanumeric, `-`, or `_` characters.
    pub name: String,
    /// The version of the package this row is describing.
    /// This must be a valid version number according to the Semantic
    /// Versioning 2.0.0 spec at https://semver.org/.
    pub vers: Version,
    /// Array of direct dependencies of the package.
    pub deps: Vec<IndexDependency>,
    /// A SHA256 checksum of the `.crate` file.
    pub cksum: String,
    /// Set of features defined for the package.
    /// Each feature maps to an array of features or dependencies it enables.
    pub features: BTreeMap<String, Vec<String>>,
    /// Boolean of whether or not this version has been yanked.
    pub yanked: bool,
    /// The `links` string value from the package's manifest, or null if not
    /// specified. This field is optional and defaults to null.
    pub links: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SearchResult {
    pub name: String,
    pub max_version: Version,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Warnings {
    pub invalid_categories: Vec<String>,
    pub invalid_badges: Vec<String>,
    pub other: Vec<String>,
}

#[async_trait]
pub trait CrateFetcher: Send + Sync {
    async fn fetch(&self, registry_crate: &RegistryCrate) -> Result<Bytes>;
}

#[async_trait]
impl<T: Into<Bytes> + Clone + Send + Sync> CrateFetcher for T {

    async fn fetch(&self, _registry_crate: &RegistryCrate) -> Result<Bytes> {
        Ok(self.clone().into())
    }
}

// config level crate
#[derive(Clone)]
pub struct RegistryCrate {
    pub api_crate: ApiCrate,
    pub yanked: bool,
    pub cksum: String,
    pub owners: Vec<String>,
    pub fetcher: Arc<dyn CrateFetcher>,
}

impl RegistryCrate {
    pub fn make_index(&self) -> IndexCrate {
        IndexCrate {
            name: self.api_crate.name.clone(),
            vers: self.api_crate.vers.clone(),
            deps: self.api_crate.deps.clone().into_iter().map(|x| x.into()).collect::<Vec<IndexDependency>>(),
            cksum: self.cksum.clone(),
            features: self.api_crate.features.clone(),
            yanked: self.yanked,
            links: self.api_crate.links.clone(),
        }
    }
}

/// authenticates users. authorization is checking the authenticated username vs crate owners. control authorization via `RegistryIndex.owners`.
#[async_trait]
pub trait UserProvider: Send + Sync + 'static {
    /// check a token for validity
    async fn authenticate_user(&self, username: &str, token: &str) -> Result<bool>;
}

#[async_trait]
pub trait CrateProvider: Send + Sync + 'static {

    /// used to serve git endpoint for crate index, internal caller or unauthenticated
    async fn index(&self) -> Result<Vec<IndexCrate>>;

    /// used to check if a name is available or a new or existing crate. use this to check for partial conflicts. authenticated.
    async fn check_name_availability(&self, name: &str) -> Result<bool>;

    /// general purpose crate information source, unauthenticated. If `version` is `None`, then fetch latest version.
    async fn get(&self, name: &str, version: Option<&Version>) -> Result<Option<RegistryCrate>>;

    /// publish a new crate version, authenticated for new crates, authorized for existing crates
    async fn publish(&self, ccrate: RegistryCrate) -> Result<Warnings>;

    /// yank a crate version, authorized
    async fn yank(&self, name: &str, version: &Version) -> Result<()>;

    /// unyank a crate version, authorized
    async fn unyank(&self, name: &str, version: &Version) -> Result<()>;

    /// update owners on a crate, authorized
    async fn update_owners(&self, name: &str, version: &Version, owners: Vec<String>) -> Result<()>;

    /// search for crates, unauthenticated
    async fn search(&self, query: &str, count: u32) -> Result<Vec<SearchResult>>;
}

pub trait LogIngestor: Send + Sync + 'static {
    fn error(&self, message: String);
}

impl LogIngestor for () {
    fn error(&self, message: String) {
        error!("{}", message);
    }
}
