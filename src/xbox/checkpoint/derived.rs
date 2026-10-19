//! Dormant Xbox cache state with original expiries and no serialized clock anchors.

use super::{Reader, TIME_BYTES, append_field, encode_time};
use crate::{
    Error,
    xbox::{
        Account, Authorization, MAX_RELYING_PARTIES, MAX_RELYING_PARTY_BYTES, Session, Token, User,
    },
};
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use zeroize::Zeroizing;

pub(in crate::xbox) struct Derived {
    observed: SystemTime,
    device: Option<Token>,
    device_id: Option<String>,
    session: Option<Session>,
    authorizations: HashMap<String, Arc<Authorization>>,
}

pub(super) struct View<'a> {
    observed: SystemTime,
    device: Option<TokenView<'a>>,
    device_id: Option<&'a str>,
    session: Option<[TokenView<'a>; 2]>,
    authorizations: Vec<AuthorizationView<'a>>,
}

#[derive(Clone, Copy)]
struct TokenView<'a> {
    value: &'a str,
    expires: SystemTime,
}

struct AuthorizationView<'a> {
    party: &'a str,
    token: TokenView<'a>,
    hash: &'a str,
    xuid: &'a str,
    gamertag: &'a str,
}

impl Derived {
    /// Activates eligible entries only against the restored owner's fresh service UTC.
    pub(in crate::xbox) fn install(mut self, account: &mut Account) {
        if account
            .http
            .response_time()
            .is_none_or(|sample| sample < self.observed)
        {
            return;
        }
        let now = account.http.now();
        account.credentials.admit_access();
        account.device = self.device.filter(|token| token.valid(now));
        account.device_id = account.device.as_ref().and(self.device_id);
        account.legacy_device = account.device.is_some() && account.device_id.is_none();
        account.session = self
            .session
            .filter(|session| session.title.valid(now) && session.user.valid(now));
        self.authorizations
            .retain(|_, token| token.token.valid(now));
        account.authorizations = self.authorizations;
    }
}

impl<'a> View<'a> {
    /// Borrows dormant or calibrated live state without copying secret strings.
    pub(super) fn of(account: &'a Account) -> Option<Self> {
        let (observed, device, device_id, session, authorizations) =
            if let Some(cache) = &account.restored {
                (
                    cache.observed,
                    &cache.device,
                    cache.device_id.as_deref(),
                    &cache.session,
                    &cache.authorizations,
                )
            } else {
                if account.device.is_none()
                    && account.session.is_none()
                    && account.authorizations.is_empty()
                {
                    return None;
                }
                // Keep the original Date sample; its process-local monotonic anchor cannot be restored.
                let observed = account.http.response_time()?;
                (
                    observed,
                    &account.device,
                    account.device_id.as_deref(),
                    &account.session,
                    &account.authorizations,
                )
            };
        let mut authorizations = authorizations
            .values()
            .map(|authorization| AuthorizationView {
                party: &authorization.relying_party,
                token: TokenView::of(&authorization.token),
                hash: &authorization.user.hash,
                xuid: &authorization.user.xuid,
                gamertag: &authorization.user.gamertag,
            })
            .collect::<Vec<_>>();
        authorizations.sort_unstable_by_key(|authorization| authorization.party);
        Some(Self {
            observed,
            device: device.as_ref().map(TokenView::of),
            device_id: device.as_ref().and(device_id),
            session: session
                .as_ref()
                .map(|session| [TokenView::of(&session.title), TokenView::of(&session.user)]),
            authorizations,
        })
    }

    /// Selects the cache extension only when its original device token has issued metadata.
    pub(super) fn has_device_identity(&self) -> bool {
        self.device_id.is_some()
    }

    /// Measures all optional bytes before the single bounded secret allocation.
    pub(super) fn encoded_len(&self) -> Option<usize> {
        encode_time(self.observed).ok()?;
        let mut length = TIME_BYTES + 3;
        for token in self.device.iter().chain(self.session.iter().flatten()) {
            length = length.checked_add(token.encoded_len()?)?;
        }
        for authorization in &self.authorizations {
            length = length.checked_add(authorization.token.encoded_len()?)?;
            for field in [
                authorization.party,
                authorization.hash,
                authorization.xuid,
                authorization.gamertag,
            ] {
                length = length.checked_add(4)?.checked_add(field.len())?;
            }
        }
        if let Some(device_id) = self.device_id {
            length = length.checked_add(4)?.checked_add(device_id.len())?;
        }
        (self.authorizations.len() <= MAX_RELYING_PARTIES).then_some(length)
    }

    /// Writes the measured format, retaining every original absolute expiry.
    pub(super) fn write(self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        bytes.extend_from_slice(&encode_time(self.observed)?);
        bytes.push(u8::from(self.device.is_some()));
        if let Some(device) = self.device {
            device.write(bytes)?;
        }
        bytes.push(u8::from(self.session.is_some()));
        if let Some(session) = self.session {
            for token in session {
                token.write(bytes)?;
            }
        }
        bytes.push(
            u8::try_from(self.authorizations.len())
                .map_err(|_| Error::Invalid("account checkpoint cache"))?,
        );
        for authorization in self.authorizations {
            append_field(bytes, authorization.party)?;
            authorization.token.write(bytes)?;
            for field in [
                authorization.hash,
                authorization.xuid,
                authorization.gamertag,
            ] {
                append_field(bytes, field)?;
            }
        }
        if let Some(device_id) = self.device_id {
            append_field(bytes, device_id)?;
        }
        Ok(())
    }

    /// Validates bounded borrowed cache framing before creating any owned credential copies.
    pub(super) fn parse(bytes: &'a [u8], device_identity: bool) -> Result<Self, Error> {
        let mut reader = Reader(bytes);
        let observed = reader.time()?;
        let device = if present(&mut reader)? {
            Some(TokenView::parse(&mut reader)?)
        } else {
            None
        };
        let session = if present(&mut reader)? {
            Some([
                TokenView::parse(&mut reader)?,
                TokenView::parse(&mut reader)?,
            ])
        } else {
            None
        };
        let count = usize::from(reader.take(1)?[0]);
        if count > MAX_RELYING_PARTIES {
            return Err(Error::Invalid("account checkpoint cache"));
        }
        let mut authorizations = Vec::with_capacity(count);
        for _ in 0..count {
            let party = reader.field()?;
            let token = TokenView::parse(&mut reader)?;
            let hash = reader.field()?;
            let xuid = reader.field()?;
            let gamertag = reader.field()?;
            if party.is_empty()
                || party.len() > MAX_RELYING_PARTY_BYTES
                || hash.is_empty()
                || authorizations
                    .iter()
                    .any(|authorization: &AuthorizationView<'_>| authorization.party == party)
            {
                return Err(Error::Invalid("account checkpoint cache"));
            }
            authorizations.push(AuthorizationView {
                party,
                token,
                hash,
                xuid,
                gamertag,
            });
        }
        let device_id = if device_identity {
            let id = reader.field()?;
            if device.is_none() || id.is_empty() {
                return Err(Error::Invalid("account checkpoint device identity"));
            }
            Some(id)
        } else {
            None
        };
        if !reader.0.is_empty() {
            return Err(Error::Invalid("account checkpoint cache"));
        }
        Ok(Self {
            observed,
            device,
            device_id,
            session,
            authorizations,
        })
    }

    /// Moves a validated protected snapshot into dormant proof-bound account state.
    pub(super) fn into_owned(self) -> Derived {
        Derived {
            observed: self.observed,
            device: self.device.map(TokenView::into_owned),
            device_id: self.device_id.map(str::to_owned),
            session: self.session.map(|[title, user]| Session {
                title: title.into_owned(),
                user: user.into_owned(),
            }),
            authorizations: self
                .authorizations
                .into_iter()
                .map(|authorization| {
                    let party = authorization.party.to_owned();
                    let token = Arc::new(Authorization {
                        relying_party: party.clone(),
                        token: authorization.token.into_owned(),
                        user: User {
                            hash: authorization.hash.to_owned(),
                            xuid: authorization.xuid.to_owned(),
                            gamertag: authorization.gamertag.to_owned(),
                        },
                    });
                    (party, token)
                })
                .collect(),
        }
    }
}

impl<'a> TokenView<'a> {
    /// Borrows the issued value and its absolute deadline together.
    fn of(token: &'a Token) -> Self {
        Self {
            value: &token.value,
            expires: token.expires,
        }
    }

    /// Includes the absolute deadline and length prefix in the optional cache budget.
    fn encoded_len(self) -> Option<usize> {
        encode_time(self.expires).ok()?;
        (4 + TIME_BYTES).checked_add(self.value.len())
    }

    /// Encodes a live or dormant issued value without resetting its deadline.
    fn write(self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        append_field(bytes, self.value)?;
        bytes.extend_from_slice(&encode_time(self.expires)?);
        Ok(())
    }

    /// Reads one nonempty issued token and its original deadline.
    fn parse(reader: &mut Reader<'a>) -> Result<Self, Error> {
        let value = reader.field()?;
        let expires = reader.time()?;
        if value.is_empty() {
            return Err(Error::Invalid("account checkpoint cache"));
        }
        Ok(Self { value, expires })
    }

    /// Copies one validated secret only into its zeroizing runtime owner.
    fn into_owned(self) -> Token {
        Token {
            value: Zeroizing::new(self.value.to_owned()),
            expires: self.expires,
        }
    }
}

/// Accepts only the format's two explicit optional-field tags.
fn present(reader: &mut Reader<'_>) -> Result<bool, Error> {
    match reader.take(1)?[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Invalid("account checkpoint cache")),
    }
}
