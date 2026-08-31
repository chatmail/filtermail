use crate::smtp_responses::{LOCAL_ERROR_451, MALFORMED_DATA_554, NON_UTF8_554};
use std::str::FromStr;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use viadkim::Signer;
use viadkim::message_hash::BodyHasherStance;

/// DKIM selector used for signatures.
///
/// It's `opendkim` for backward compatibility - we are no longer depending on OpenDKIM.
const SELECTOR: &str = "opendkim";

/// Path to the DKIM private key.
const PRIVATE_KEY_PATH: &str = "/etc/dkimkeys/opendkim.private";

pub struct DkimSigner {
    domain: viadkim::DomainName,
    selector: viadkim::Selector,
    signing_key: String,
}

impl DkimSigner {
    /// Creates a new [`DkimSigner`] using the provided domain.
    pub async fn new(domain: &str) -> Result<Self, crate::error::Error> {
        let domain = viadkim::DomainName::new(domain)
            .inspect_err(|e| log::error!("Can't sign message, failed to parse headers: {e}"))?;

        let selector = viadkim::Selector::new(SELECTOR).inspect_err(|e| {
            log::error!("Can't sign message, failed to parse DKIM selector ({SELECTOR}): {e}");
        })?;

        let mut signing_key = String::new();
        File::open(PRIVATE_KEY_PATH)
            .await
            .inspect_err(|e| {
                log::error!("Error opening DKIM private key file ({PRIVATE_KEY_PATH}): {e}");
            })?
            .read_to_string(&mut signing_key)
            .await
            .inspect_err(|e| {
                log::error!("Error reading DKIM private key ({PRIVATE_KEY_PATH}): {e}");
            })?;

        Ok(Self {
            domain,
            selector,
            signing_key,
        })
    }

    /// DKIM-signs the message and returns message bytes including the signature.
    pub async fn sign(&self, raw_mail: &[u8]) -> Result<Vec<u8>, String> {
        let mail_data = str::from_utf8(raw_mail).or(Err(NON_UTF8_554))?;
        let (header, body) = mail_data.split_once("\r\n\r\n").ok_or(MALFORMED_DATA_554)?;
        let header_fields = viadkim::HeaderFields::from_str(header).map_err(|e| {
            log::error!("Can't sign message, failed to parse headers: {e}");
            MALFORMED_DATA_554
        })?;

        let signing_key = viadkim::SigningKey::from_pkcs8_pem(&self.signing_key).map_err(|e| {
            log::error!("Invalid DKIM signing key format ({PRIVATE_KEY_PATH}): {e}");
            LOCAL_ERROR_451
        })?;

        let algorithm = viadkim::SigningAlgorithm::from_parts(
            signing_key.key_type(),
            viadkim::crypto::HashAlgorithm::Sha256,
        )
        .unwrap_or(
            // in practice, this is unreachable
            viadkim::SigningAlgorithm::RsaSha256,
        );

        let request = viadkim::SignRequest::new(
            self.domain.clone(),
            self.selector.clone(),
            algorithm,
            signing_key,
        );

        let mut signer = Signer::prepare_signing(header_fields, [request]).map_err(|e| {
            log::error!("Failed to prepare DKIM signer: {e}");
            LOCAL_ERROR_451
        })?;

        'hasher: for chunk in body.as_bytes().chunks(8192) {
            if signer.process_body_chunk(chunk) == BodyHasherStance::Done {
                break 'hasher;
            }
        }

        let signature = match signer.sign().await.into_iter().next() {
            Some(Ok(output)) => output.format_header().to_string(),
            None => {
                // unreachable
                log::error!("DKIM signing failed.");
                return Err(LOCAL_ERROR_451.to_string());
            }
            Some(Err(err)) => {
                log::error!("DKIM signing failed: {err}");
                return Err(LOCAL_ERROR_451.to_string());
            }
        };

        let mut mail_signed = signature.as_bytes().to_vec();
        mail_signed.append(&mut b"\r\n".to_vec());
        mail_signed.append(&mut raw_mail.to_vec());
        Ok(mail_signed)
    }
}
