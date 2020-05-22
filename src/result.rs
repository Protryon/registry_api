use std::fmt;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub type StdResult<T, E> = std::result::Result<T, E>;
pub type Result<T> = StdResult<T, Error>;
#[derive(Debug)]
pub struct RegistryError {
    message: String,
}

impl RegistryError {
    pub fn new(message: String) -> RegistryError {
        RegistryError { message }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegistryError {{ {} }}", self.message)
    }
}

impl std::error::Error for RegistryError {}

#[macro_export]
macro_rules! registry_err {
    ($($arg:tt)*) => { Box::new(RegistryError::new(format!($($arg)*))) }
}
