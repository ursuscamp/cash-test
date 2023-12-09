use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Token V3 format")]
    TokenV3(Option<Box<dyn std::error::Error>>),
}

impl Error {
    pub(crate) fn map_tokenv3(err: impl std::error::Error + 'static) -> Error {
        Error::TokenV3(Some(Box::new(err)))
    }
}
