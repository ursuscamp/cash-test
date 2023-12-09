use std::str::from_utf8;

use base64::{engine::general_purpose::URL_SAFE, Engine};
use derive_more::*;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlindedMessage {
    amount: u64,

    #[serde(rename = "B_", with = "hex::serde")]
    blinded_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlindedSignature {
    id: Option<String>,

    amount: u64,

    #[serde(rename = "C_", with = "hex::serde")]
    blinded_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof {
    id: Option<String>,

    amount: u64,

    secret: String,

    #[serde(rename = "C", with = "hex::serde")]
    unblinded_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, AsRef, Into, From, PartialEq, Eq)]
pub struct Proofs(Vec<Proof>);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MintToken {
    mint: Url,
    proofs: Proofs,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Token {
    token: Vec<MintToken>,
    memo: Option<String>,
}

impl Token {
    pub fn serialize(&self) -> Result<String, crate::error::Error> {
        let token = serde_json::to_string(self).map_err(crate::error::Error::map_tokenv3)?;
        let mut token = URL_SAFE.encode(&token);
        token.insert_str(0, "cashuA");
        Ok(token)
    }

    pub fn deserialize(token: &str) -> Result<Token, crate::Error> {
        let token = token
            .strip_prefix("cashuA")
            .ok_or(crate::Error::TokenV3(None))?;
        let token = URL_SAFE
            .decode(token)
            .map_err(|e| crate::Error::TokenV3(Some(Box::new(e))))?;
        let token = from_utf8(&token).map_err(crate::Error::map_tokenv3)?;
        let token: Token = serde_json::from_str(token).map_err(crate::Error::map_tokenv3)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_v3_serialization() {
        let token = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJpZCI6IkRTQWw5bnZ2eWZ2YSIsImFtb3VudCI6Miwic2VjcmV0IjoiRWhwZW5uQzlxQjNpRmxXOEZaX3BadyIsIkMiOiIwMmMwMjAwNjdkYjcyN2Q1ODZiYzMxODNhZWNmOTdmY2I4MDBjM2Y0Y2M0NzU5ZjY5YzYyNmM5ZGI1ZDhmNWI1ZDQifSx7ImlkIjoiRFNBbDludnZ5ZnZhIiwiYW1vdW50Ijo4LCJzZWNyZXQiOiJUbVM2Q3YwWVQ1UFVfNUFUVktudWt3IiwiQyI6IjAyYWM5MTBiZWYyOGNiZTVkNzMyNTQxNWQ1YzI2MzAyNmYxNWY5Yjk2N2EwNzljYTk3NzlhYjZlNWMyZGIxMzNhNyJ9XX1dLCJtZW1vIjoiVGhhbmsgeW91LiJ9";

        let token = Token::deserialize(token).unwrap();
        dbg!(&token);
        assert_eq!(
            token.token[0].mint,
            "https://8333.space:3338".parse().unwrap()
        );
        let proofs = token.token[0].proofs.as_ref();
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0].amount, 2);
        assert_eq!(proofs[1].amount, 8);
    }

    #[test]
    fn test_blind_message_serialization() {
        let bm = BlindedMessage {
            amount: 10,
            blinded_message: hex::decode("abcd").unwrap(),
        };
        let bmser = serde_json::to_string(&bm).unwrap();
        assert_eq!(bmser, r#"{"amount":10,"B_":"abcd"}"#);

        let bm2 = serde_json::from_str(&bmser).unwrap();
        assert_eq!(bm, bm2);
    }

    #[test]
    fn test_blinded_signature_serialization() {
        let bs = BlindedSignature {
            id: Some("abcd".into()),
            amount: 5,
            blinded_key: hex::decode("abcd").unwrap(),
        };
        let bsser = serde_json::to_string(&bs).unwrap();
        assert_eq!(bsser, r#"{"id":"abcd","amount":5,"C_":"abcd"}"#);

        let bs2 = serde_json::from_str(&bsser).unwrap();
        assert_eq!(bs, bs2);
    }

    #[test]
    fn test_proof_serialization() {
        let proof = Proof {
            id: Some("abcd".into()),
            amount: 5,
            secret: "abcd".to_string(),
            unblinded_key: hex::decode("abcd").unwrap(),
        };
        let pser = serde_json::to_string(&proof).unwrap();
        assert_eq!(
            pser,
            r#"{"id":"abcd","amount":5,"secret":"abcd","C":"abcd"}"#
        );

        let proof2 = serde_json::from_str(&pser).unwrap();
        assert_eq!(proof, proof2);
    }
}
