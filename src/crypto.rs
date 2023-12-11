use derive_more::{AsRef, From, Into};
use k256::{ProjectivePoint, PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq, AsRef, Into, From)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn random() -> Secret {
        let c: [u8; 20] = rand::random();
        Secret(c.to_vec())
    }

    pub fn from_hex(data: &str) -> Result<Secret, crate::Error> {
        Ok(Secret(hex::decode(data)?))
    }

    pub fn hash_to_curve(&self) -> PublicKey {
        let mut s = Sha256::digest(&self.0);
        let mut v = Vec::new();
        loop {
            v.clear();
            v.extend(b"\x02");
            v.extend(&s);
            if let Ok(pk) = k256::PublicKey::from_sec1_bytes(&v) {
                return pk;
            }
            s = Sha256::digest(&s);
        }
    }

    pub fn blinded_message(
        &self,
        blinding_factor: &k256::SecretKey,
    ) -> Result<BlindedMessage, crate::Error> {
        // Convert myself into a point
        let secret_key = self.hash_to_curve();
        let secret_point: ProjectivePoint = secret_key.into();

        // Convert blinding factor into a point
        let bf_key = blinding_factor.public_key();
        let blind_point: ProjectivePoint = bf_key.into();

        let new_point = secret_point + blind_point;

        Ok(BlindedMessage(new_point.try_into()?))
    }
}

#[derive(Debug, PartialEq, Eq, AsRef, Into, From)]
pub struct BlindedMessage(PublicKey);

impl BlindedMessage {
    pub fn blinded_key(&self, sk: SecretKey) -> Result<BlindedKey, crate::Error> {
        let pk = self.0;
        let point = pk.to_projective();
        let scalar = sk.as_scalar_primitive();
        let scalar: Scalar = scalar.into();
        let new_point = point * scalar;
        let new_pk: PublicKey = new_point.try_into()?;
        Ok(BlindedKey(new_pk))
    }

    pub fn from_hex(data: &str) -> Result<BlindedMessage, crate::Error> {
        let data = hex::decode(data)?;
        let key = PublicKey::from_sec1_bytes(&data)?;
        Ok(BlindedMessage(key))
    }
}

#[derive(Debug, PartialEq, Eq, AsRef, Into, From)]
pub struct BlindedKey(PublicKey);

impl BlindedKey {
    pub fn from_hex(data: &str) -> Result<BlindedKey, crate::Error> {
        let data = hex::decode(data)?;
        let key = PublicKey::from_sec1_bytes(&data)?;
        Ok(BlindedKey(key))
    }
}

#[cfg(test)]
mod tests {
    use k256::SecretKey;

    use super::*;

    #[test]
    fn test_secret_random() {
        let secret = Secret::random();
        assert_eq!(secret.as_ref().len(), 20);
    }

    // Hash to curve vectors: https://github.com/cashubtc/nuts/blob/main/test-vectors/00-tests.md
    #[test]
    fn test_hash_to_curve() {
        let vectors = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0266687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "02ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "02076c988b353fcbb748178ecb286bc9d0b4acf474d4ba31ba62334e46c97c416a",
            ),
        ];
        for (message, point) in vectors {
            let message = hex::decode(message).unwrap();
            let secret = Secret::from(message);
            let pk = PublicKey::from_sec1_bytes(&hex::decode(point).unwrap()).unwrap();
            assert_eq!(secret.hash_to_curve(), pk);
        }
    }

    #[test]
    fn test_blinding_message() {
        let vectors = [
            (
                "test_message",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            ),
            (
                "hello",
                "6d7e0abffc83267de28ed8ecc8760f17697e51252e13333ba69b4ddad1f95d05",
                "0249eb5dbb4fac2750991cf18083388c6ef76cde9537a6ac6f3e6679d35cdf4b0c",
            ),
        ];

        for (message, blinding_factor, point) in vectors {
            let secret = Secret::from(message.bytes().collect::<Vec<_>>());
            let sk = SecretKey::from_slice(&hex::decode(blinding_factor).unwrap()).unwrap();
            let result = secret.blinded_message(&sk);
            let expected: BlindedMessage = PublicKey::from_sec1_bytes(&hex::decode(point).unwrap())
                .unwrap()
                .into();
            assert_eq!(expected, result.unwrap());
        }
    }

    #[test]
    fn test_blinding_key() {
        // Test 1: https://github.com/cashubtc/nuts/blob/main/test-vectors/00-tests.md
        let bm = BlindedMessage::from_hex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
        )
        .unwrap();
        let keydata =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let sk = SecretKey::from_slice(&keydata).unwrap();
        let bk = bm.blinded_key(sk).unwrap();
        let expected = BlindedKey::from_hex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
        )
        .unwrap();

        assert_eq!(bk, expected);

        // Test 2: https://github.com/cashubtc/nuts/blob/main/test-vectors/00-tests.md
        let bm = BlindedMessage::from_hex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
        )
        .unwrap();
        let keydata =
            hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
                .unwrap();
        let sk = SecretKey::from_slice(&keydata).unwrap();
        let bk = bm.blinded_key(sk).unwrap();
        let expected = BlindedKey::from_hex(
            "0398bc70ce8184d27ba89834d19f5199c84443c31131e48d3c1214db24247d005d",
        )
        .unwrap();

        assert_eq!(bk, expected);
    }
}
