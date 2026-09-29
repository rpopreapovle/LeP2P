//! TLS 1.3 integration binding a quinn/rustls connection to a node's ed25519 identity.
//!
//! Every node has a self-signed certificate whose key IS the node's ed25519 key.
//! A peer validates a connection by extracting the ed25519 public key from the
//! presented certificate, recomputing `NodeId = SHA-256(pubkey)` and comparing it
//! to the expected `NodeId` (which, via the overlay address, is also the network
//! address of the peer). This delivers **address == identity** with standard TLS.

use crate::{Identity, NodeId};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use x509_parser::prelude::*;

/// Everything needed to run as a TLS server: the self-signed cert chain + private key.
pub struct ServerTls {
    pub cert: CertificateDer<'static>,
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// Build a self-signed certificate whose key is the node's ed25519 key.
pub fn build_server_tls(identity: &Identity) -> Result<ServerTls, rcgen::Error> {
    // Serialize the ed25519 signing key as PKCS#8 and load it via rcgen.
    let pkcs8 = identity
        .signing_key()
        .to_pkcs8_der()
        .expect("ed25519 key -> pkcs8")
        .as_bytes()
        .to_vec();
    let keypair = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8),
        &rcgen::PKCS_ED25519,
    )?;

    // SANs document the identity; real verification uses the embedded ed25519 pubkey.
    let params = CertificateParams::new(vec![
        identity.overlay_ipv6().to_string(),
        identity.node_id().to_base32(),
    ])?;
    let cert = params.self_signed(&keypair)?;

    Ok(ServerTls {
        cert: CertificateDer::from(cert.der().to_vec()),
        chain: vec![],
        key: PrivateKeyDer::try_from(keypair.serialize_der()).expect("valid private key der"),
    })
}

/// Extract the node's ed25519 public key bytes from a presented certificate.
pub fn extract_pubkey(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let (_, cert) = X509Certificate::from_der(cert.as_ref()).ok()?;
    let raw = cert.public_key().raw;
    if raw.len() >= 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw[raw.len() - 32..]);
        Some(out)
    } else {
        None
    }
}

/// NodeId that a certificate encodes (SHA-256 of its embedded ed25519 pubkey).
pub fn cert_node_id(cert: &CertificateDer<'_>) -> Option<NodeId> {
    let pubkey = extract_pubkey(cert)?;
    Some(NodeId(sha256(&pubkey)))
}

/// Trusts a single peer by expected NodeId (peer pins its identity into its cert).
#[derive(Debug)]
struct NodeIdVerifier {
    expected: NodeId,
    allow_any: bool,
}

impl ServerCertVerifier for NodeIdVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.allow_any {
            return Ok(ServerCertVerified::assertion());
        }
        match cert_node_id(end_entity) {
            Some(id) if id == self.expected => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::General(
                "certificate does not match expected node identity".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for NodeIdVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.allow_any {
            return Ok(ClientCertVerified::assertion());
        }
        match cert_node_id(end_entity) {
            Some(id) if id == self.expected => Ok(ClientCertVerified::assertion()),
            _ => Err(rustls::Error::General(
                "client certificate does not match expected node identity".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Server rustls config with our self-signed cert. Identity of the server is
/// carried in the certificate (ed25519 key); clients verify it via `client_config`.
pub fn server_config(tls: &ServerTls) -> Result<rustls::ServerConfig, rustls::Error> {
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![tls.cert.clone()], tls.key.clone_key())
}

/// Client rustls config authenticating a specific peer by NodeId (address == identity).
pub fn client_config(expected: NodeId) -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NodeIdVerifier {
            expected,
            allow_any: false,
        }))
        .with_no_client_auth()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(data);
    d.into()
}
