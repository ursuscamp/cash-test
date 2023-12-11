use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Token V3 format")]
    TokenV3(Option<Box<dyn std::error::Error>>),

    #[error("ECC arithmetic error: {0}")]
    EccArithmetic(#[from] k256::elliptic_curve::Error),

    #[error("Hex conversion")]
    HexConversion(#[from] hex::FromHexError),
}

impl Error {
    pub(crate) fn map_tokenv3(err: impl std::error::Error + 'static) -> Error {
        Error::TokenV3(Some(Box::new(err)))
    }
}
