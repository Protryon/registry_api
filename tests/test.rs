use registry_api::*;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CrateStore {
    pub crates: BTreeMap<String, BTreeMap<Version, RegistryCrate>>,
}

struct MockProvider {
    pub crate_store: RwLock<CrateStore>,
}

#[async_trait]
impl CrateProvider for MockProvider {
    async fn index(&self) -> Result<Vec<IndexCrate>> {
        let crates = self.crate_store.read().await;

        Ok(crates
            .crates
            .iter()
            .map(|(_, x)| x.iter().map(|(_, x)| x))
            .flatten()
            .map(RegistryCrate::make_index)
            .collect())
    }

    async fn check_name_availability(&self, _name: &str) -> Result<bool> {
        Ok(true)
    }

    async fn get(&self, name: &str, version: Option<&Version>) -> Result<Option<RegistryCrate>> {
        let crates = self.crate_store.read().await;

        let namespace = match crates.crates.get(name) {
            Some(x) => x,
            None => return Ok(None),
        };
        Ok(match version {
            Some(version) => namespace.get(version).cloned(),
            None => namespace.iter().last().map(|x| x.1.clone()),
        })
    }

    async fn publish(&self, ccrate: RegistryCrate) -> Result<Warnings> {
        let mut crates = self.crate_store.write().await;

        if !crates.crates.contains_key(&ccrate.api_crate.name) {
            crates
                .crates
                .insert(ccrate.api_crate.name.clone(), BTreeMap::new());
        }

        let namespace = crates.crates.get_mut(&ccrate.api_crate.name).unwrap();

        namespace.insert(ccrate.api_crate.vers.clone(), ccrate);

        Ok(Default::default())
    }

    async fn yank(&self, name: &str, version: &Version) -> Result<()> {
        let mut crates = self.crate_store.write().await;

        let namespace = crates.crates.get_mut(name).unwrap();
        let ccrate = namespace.get_mut(version).unwrap();
        ccrate.yanked = true;

        Ok(())
    }

    async fn unyank(&self, name: &str, version: &Version) -> Result<()> {
        let mut crates = self.crate_store.write().await;

        let namespace = crates.crates.get_mut(name).unwrap();
        let ccrate = namespace.get_mut(version).unwrap();
        ccrate.yanked = false;

        Ok(())
    }

    async fn update_owners(
        &self,
        name: &str,
        version: &Version,
        owners: Vec<String>,
    ) -> Result<()> {
        let mut crates = self.crate_store.write().await;

        let namespace = crates.crates.get_mut(name).unwrap();
        let ccrate = namespace.get_mut(version).unwrap();
        ccrate.owners = owners;

        Ok(())
    }

    async fn search(&self, query: &str, _count: u32) -> Result<Vec<SearchResult>> {
        let exact_match = self.get(query, None).await?;
        println!("query = {} found = {}", query, exact_match.is_some());
        match exact_match {
            None => Ok(vec![]),
            Some(ccrate) => Ok(vec![SearchResult {
                name: ccrate.api_crate.name,
                max_version: ccrate.api_crate.vers,
                description: ccrate.api_crate.description,
            }]),
        }
    }
}

#[async_trait]
impl UserProvider for MockProvider {
    async fn authenticate_user(&self, _username: &str, _token: &str) -> Result<bool> {
        Ok(true)
    }
}

#[actix_rt::test]
pub async fn host() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    let provider = Arc::new(MockProvider {
        crate_store: RwLock::new(CrateStore {
            crates: BTreeMap::new(),
        }),
    });
    spawn_within_actix(
        Config::new(
            "0.0.0.0:8080",
            "./index",
            "http://127.0.0.1:8080/".parse().unwrap(),
            provider.clone(),
            provider,
            None,
        )
        .unwrap(),
    )
    .await;
}
