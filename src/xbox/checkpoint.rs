//! Explicit restart ownership for an account's refresh credential and proof key.

use super::{Account, Config, Device};
use crate::{Error, http::Http, oauth::Credentials};
use p256::ecdsa::SigningKey;
use zeroize::Zeroizing;

const PREFIX: &[u8] = b"BSAC\x01";
const PROOF_BYTES: usize = 32;

/// Ordered authentication-policy fields in the version-one format.
type PolicyFields<'a> = [&'a str; 5];

/// Maximum encoded account checkpoint size. Bound secure-store reads by this value.
pub const MAX_CHECKPOINT_BYTES: usize = 64 * 1024;

/// Sensitive restart state, with no Debug or implicit serialization implementation.
///
/// The owned bytes are zeroized when dropped. This format supplies neither encryption
/// nor integrity protection. The caller must protect storage and bind it to the
/// current account generation; restoring an older checkpoint can undo refresh rotation.
pub struct Checkpoint {
    bytes: Zeroizing<Vec<u8>>,
}

impl Checkpoint {
    /// Takes ownership of bounded, versioned bytes read from the caller's secure store.
    ///
    /// This checks framing. Policy and proof-key validity are checked when the
    /// checkpoint moves into [`crate::oauth::MicrosoftAuth::restore_account`].
    ///
    /// # Errors
    /// Returns a redacted error for oversized, unsupported or malformed bytes.
    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, Error> {
        Contents::parse(&bytes)?;
        Ok(Self { bytes })
    }

    /// Explicitly exposes secret bytes for the caller's protected persistence layer.
    /// Do not log these bytes or place them in ordinary application configuration.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Account {
    /// Captures the current refresh credential and its account-owned P-256 proof key.
    ///
    /// This performs no I/O. Persist each returned checkpoint under the same account
    /// generation and serialization boundary as refresh and sign-out. Access, device,
    /// SISU and XSTS tokens are omitted: their response-clock anchors cannot survive
    /// restart. The restored owner reacquires them using this same proof key.
    ///
    /// # Errors
    /// Returns [`Error::SignInRequired`] without a refresh token, or a redacted error
    /// when the policy and credential exceed [`MAX_CHECKPOINT_BYTES`].
    pub fn checkpoint(&self) -> Result<Checkpoint, Error> {
        let refresh = self.credentials.refresh_token();
        if refresh.is_empty() {
            return Err(Error::SignInRequired);
        }
        let policy = policy_fields(&self.config);
        let mut length = PREFIX.len() + 1 + PROOF_BYTES;
        for field in policy.into_iter().chain([refresh]) {
            length = length
                .checked_add(4)
                .and_then(|length| length.checked_add(field.len()))
                .filter(|length| *length <= MAX_CHECKPOINT_BYTES)
                .ok_or(Error::Invalid("account checkpoint size"))?;
        }
        // Allocate once before exporting the scalar so secret bytes never move on growth.
        let mut bytes = Zeroizing::new(Vec::with_capacity(length));
        bytes.extend_from_slice(PREFIX);
        bytes.push(device_tag(self.config.device));
        for field in policy {
            append_field(&mut bytes, field)?;
        }
        let proof = Zeroizing::new(self.key.to_bytes());
        bytes.extend_from_slice(proof.as_slice());
        append_field(&mut bytes, refresh)?;
        Ok(Checkpoint { bytes })
    }

    /// Restores only state whose account and policy binding remains meaningful at restart.
    pub(crate) fn restore(
        http: Http,
        config: Config,
        checkpoint: Checkpoint,
    ) -> Result<Self, Error> {
        let contents = Contents::parse(checkpoint.as_bytes())?;
        if contents.device != device_tag(config.device) || contents.policy != policy_fields(&config)
        {
            return Err(Error::Invalid("account checkpoint policy"));
        }
        let key = SigningKey::from_slice(contents.proof)
            .map_err(|_| Error::Invalid("account checkpoint proof key"))?;
        let credentials = Credentials::from_tokens(
            config.client_id.clone(),
            String::new(),
            contents.refresh.to_owned(),
            std::time::UNIX_EPOCH,
        )?;
        Ok(Self::with_key(http, config, credentials, key))
    }
}

/// Lists all policy strings that must match before a saved proof can be adopted.
fn policy_fields(config: &Config) -> PolicyFields<'_> {
    // Exhaustive destructuring makes newly added policy fields require a format decision.
    let Config {
        client_id,
        user_agent,
        device: _,
        device_version,
        sandbox,
    } = config;
    [
        client_id,
        user_agent,
        device_version,
        sandbox,
        crate::oauth::SCOPE,
    ]
}

/// Assigns a versioned wire identity to every supported device policy.
fn device_tag(device: Device) -> u8 {
    match device {
        Device::Android => 0,
        Device::Ios => 1,
        Device::Nintendo => 2,
        Device::PlayStation => 3,
        Device::Win32 => 4,
        Device::Xbox => 5,
    }
}

/// Appends a checked UTF-8 field to an already bounded checkpoint allocation.
fn append_field(bytes: &mut Vec<u8>, value: &str) -> Result<(), Error> {
    let length =
        u32::try_from(value.len()).map_err(|_| Error::Invalid("account checkpoint size"))?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Contents<'a> {
    device: u8,
    policy: PolicyFields<'a>,
    proof: &'a [u8],
    refresh: &'a str,
}

impl<'a> Contents<'a> {
    /// Decodes borrowed fields without allocating credential copies or accepting trailing data.
    fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Invalid("account checkpoint size"));
        }
        let mut reader = Reader(bytes);
        if reader.take(PREFIX.len())? != PREFIX {
            return Err(Error::Invalid("account checkpoint version"));
        }
        let device = reader.take(1)?[0];
        let mut policy = PolicyFields::default();
        for field in &mut policy {
            *field = reader.field()?;
        }
        let proof = reader.take(PROOF_BYTES)?;
        let refresh = reader.field()?;
        if refresh.is_empty() || !reader.0.is_empty() {
            return Err(Error::Invalid("account checkpoint framing"));
        }
        Ok(Self {
            device,
            policy,
            proof,
            refresh,
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// Advances over a checked portion of the checkpoint, including zero-length fields.
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let (value, remainder) = self
            .0
            .split_at_checked(length)
            .ok_or(Error::Invalid("account checkpoint framing"))?;
        self.0 = remainder;
        Ok(value)
    }

    /// Reads one length-prefixed UTF-8 value without trusting its declared size.
    fn field(&mut self) -> Result<&'a str, Error> {
        let length = u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| Error::Invalid("account checkpoint framing"))?,
        );
        let length =
            usize::try_from(length).map_err(|_| Error::Invalid("account checkpoint size"))?;
        std::str::from_utf8(self.take(length)?)
            .map_err(|_| Error::Invalid("account checkpoint encoding"))
    }
}

#[cfg(test)]
mod tests;
