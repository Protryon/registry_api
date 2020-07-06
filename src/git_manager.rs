use crate::config::*;
use crate::result::*;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::prelude::*;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::{delay_for, Duration};
use url::Url;

pub struct Git {
    directory: PathBuf,
    config: ConfigFile,
    update_lock: RwLock<()>,
}

#[derive(Deserialize, Serialize)]
pub struct ConfigFile {
    pub dl: String,
    pub api: String,
}

impl Git {
    pub async fn reset_git_worker(self: Arc<Self>, config: Arc<Config>) {
        loop {
            match config.crate_provider.index().await {
                Ok(crates) => match self.reset_git(crates).await {
                    Ok(()) => (),
                    Err(e) => {
                        config
                            .log_ingestor
                            .error(format!("failed to update index crates: {:?}", e));
                    }
                },
                Err(e) => {
                    config
                        .log_ingestor
                        .error(format!("failed to fetch index crates: {:?}", e));
                }
            }
            delay_for(Duration::from_secs(60)).await;
        }
    }

    pub fn new(index_dir: PathBuf, mut exposed_url: Url) -> Result<Git> {
        let path = exposed_url.path().to_string();
        if path.ends_with("/") {
            if path.ends_with("/") {
                exposed_url.set_path(&*format!("{}{}", path, "registry"));
            } else {
                exposed_url.set_path(&*format!("{}{}", path, "/registry"));
            }
        }

        Ok(Git {
            directory: index_dir,
            config: ConfigFile {
                api: exposed_url.to_string(),
                dl: {
                    let mut new_url = exposed_url.clone();
                    let path = new_url.path().to_string();
                    new_url.set_path(&*format!("{}{}", path, "/api/v1/crates"));
                    new_url.to_string()
                },
            },
            update_lock: tokio::sync::RwLock::new(()),
        })
    }

    async fn init_git(&self) -> Result<()> {
        fs::create_dir_all(&self.directory).await?;
        if Command::new("git")
            .arg("init")
            .current_dir(&self.directory)
            .status()
            .await?
            .code()
            != Some(0)
        {
            return Err(registry_err!("failed to run git init"));
        }
        self.write_config().await?;
        Ok(())
    }

    async fn write_config(&self) -> Result<()> {
        let mut config_path = self.directory.clone();
        config_path.push("config.json");
        fs::write(&config_path, serde_json::to_string(&self.config)?).await?;
        Ok(())
    }

    #[async_recursion::async_recursion]
    async fn recur_crates(
        path: &PathBuf,
        results: &mut HashMap<(String, Version), IndexCrate>,
    ) -> Result<()> {
        let mut dir = fs::read_dir(path).await?;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name();
            if name == "config.json" || name == ".git" {
                continue;
            }
            match entry.file_type().await? {
                x if x.is_dir() => {
                    Git::recur_crates(&entry.path(), results).await?;
                }
                x if x.is_file() => {
                    let crates = String::from_utf8_lossy(&fs::read(&entry.path()).await?[..])
                        .split('\n')
                        .filter(|x| x.trim().len() > 0)
                        .map(|x| serde_json::from_str(x).map_err(|x| x.into()))
                        .collect::<Result<Vec<IndexCrate>>>()?;
                    for ccrate in crates.into_iter() {
                        results.insert((ccrate.name.clone(), ccrate.vers.clone()), ccrate);
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }

    async fn existing_crates(&self) -> Result<HashMap<(String, Version), IndexCrate>> {
        let mut crates = HashMap::new();
        Git::recur_crates(&self.directory, &mut crates).await?;
        Ok(crates)
    }

    fn crate_path(&self, name: &str) -> Result<PathBuf> {
        let name = name.to_ascii_lowercase();
        if !crate::registry_api::CRATE_NAME_REGEX.is_match(&name) {
            return Err(registry_err!("invalid name"));
        }
        let mut path = self.directory.clone();
        if name.len() == 1 {
            path.push(format!("1/{}", name));
        } else if name.len() == 2 {
            path.push(format!("2/{}", name));
        } else if name.len() == 3 {
            path.push(format!("3/{}/{}", &name[0..1], name));
        } else {
            path.push(format!("{}/{}/{}", &name[0..2], &name[2..4], name));
        }
        Ok(path)
    }

    async fn write_crate(&self, ccrate: &IndexCrate) -> Result<()> {
        let crate_path = self.crate_path(&ccrate.name)?;
        fs::create_dir_all(crate_path.parent().unwrap()).await?;
        let mut f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&crate_path)
            .await?;
        f.write_all(format!("{}\n", serde_json::to_string(&ccrate)?).as_bytes())
            .await?;
        f.flush().await?;
        Ok(())
    }

    async fn delete_crate(&self, name: &str, version: &Version) -> Result<()> {
        let crate_path = self.crate_path(&name)?;
        let crates = String::from_utf8_lossy(&fs::read(&crate_path).await?[..])
            .split("\n")
            .filter(|x| x.trim().len() > 0)
            .map(|x| serde_json::from_str(x).map_err(|x| x.into()))
            .collect::<Result<Vec<IndexCrate>>>()?
            .into_iter()
            .filter(|x| &x.vers != version)
            .map(|x| serde_json::to_string(&x).map_err(|x| x.into()))
            .collect::<Result<Vec<String>>>()?
            .join("\n")
            + "\n";

        fs::write(&crate_path, crates.as_bytes()).await?;
        Ok(())
    }

    async fn commit(&self, message: &str) -> Result<()> {
        if Command::new("git")
            .arg("add")
            .arg("-A")
            .current_dir(&self.directory)
            .status()
            .await?
            .code()
            != Some(0)
        {
            return Err(registry_err!("failed to run git add"));
        }
        if Command::new("git")
            .arg("commit")
            .arg("-am")
            .arg(message)
            .current_dir(&self.directory)
            .status()
            .await?
            .code()
            != Some(0)
        {
            return Err(registry_err!("failed to run git commit"));
        }
        Ok(())
    }

    //TODO: make commits work with distributed nodes better here
    pub async fn reset_git(&self, crates: Vec<IndexCrate>) -> Result<()> {
        let _lock = self.update_lock.write().await;
        let mut mutated = false;
        if !fs::metadata(&self.directory).await.is_ok() {
            self.init_git().await?;
            mutated = true;
        } else {
            // a config change on it's own wont be updated, but that isnt supported in the exposed api
            self.write_config().await?;
        }
        let existing_crates = self.existing_crates().await?;
        for ccrate in crates.iter() {
            let existing_crate = existing_crates.get(&(ccrate.name.clone(), ccrate.vers.clone()));
            match existing_crate {
                Some(existing_crate) if existing_crate != ccrate => {
                    mutated = true;
                    self.delete_crate(&existing_crate.name, &existing_crate.vers)
                        .await?;
                    self.write_crate(&ccrate).await?;
                }
                None => {
                    mutated = true;
                    self.write_crate(&ccrate).await?;
                }
                _ => (),
            }
        }
        let crates = crates.into_iter().collect::<HashSet<IndexCrate>>();
        for (_, ccrate) in existing_crates.iter() {
            if !crates.contains(ccrate) {
                mutated = true;
                self.delete_crate(&ccrate.name, &ccrate.vers).await?;
            }
        }
        if mutated {
            self.commit(&*format!(
                "automatic update {}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis()
            ))
            .await?;
        }
        Ok(())
    }
}
