//! axum `FromRequestParts` extractors for peer-credential and session binding.

use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};

use crate::peer_cred::PeerCredentials;
use crate::problem::{Problem, ProblemType};

/// axum extractor that injects verified `PeerCredentials` into handler arguments.
///
/// The credentials are inserted into request extensions by the
/// `peer_cred_check` middleware ([`crate::router`]). If the middleware was
/// bypassed or the extension is absent the extractor returns a 403.
#[derive(Debug, Clone)]
pub struct ExtractedPeerCred(pub PeerCredentials);

impl<S> FromRequestParts<S> for ExtractedPeerCred
where
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<PeerCredentials>()
            .cloned()
            .map(ExtractedPeerCred)
            .ok_or_else(|| Problem {
                kind: ProblemType::RevealDenied,
                title: "Peer credential missing".into(),
                status: 403,
                detail: "Peer credential check was not executed for this request.".into(),
                instance: None,
                hint: None,
                fields: vec![],
            })
    }
}
