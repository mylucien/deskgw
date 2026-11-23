//! 浏览器侧的 TLS 客户端：在 WebSocket 字节流之上完成 RDP 的 TLS 层。
//!
//! 与上游的 RDCleanPath 模式不同，这里由浏览器自己与 Windows 主机协商 TLS，
//! 网关只转发字节，看不到 RDP 明文，也无法接触 NLA 凭据。
//!
//! RDP 主机普遍使用自签证书，因此不做 CA 链校验，改为记录证书指纹供
//! 前端做 TOFU（首次信任）比对；指纹变化时由调用方阻断连接。

use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use futures_rustls::client::TlsStream;
use futures_rustls::TlsConnector;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as rustls_ring;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use futures_util::io::{AsyncRead, AsyncWrite};
use ring::digest;
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// TlsInfo 是握手后拿到的服务器证书信息。
pub(crate) struct TlsInfo {
    pub cert_der: Vec<u8>,
    /// SHA-256 指纹，小写十六进制，无分隔符。
    pub fingerprint: String,
}

/// upgrade 在给定字节流上发起 TLS 握手。host 仅用于 SNI 与证书名称，
/// 不做链校验。
pub(crate) async fn upgrade<S>(stream: S, host: &str) -> anyhow::Result<(TlsStream<S>, TlsInfo)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    let provider = rustls_ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("TLS 配置失败: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert {
            captured: Arc::clone(&captured),
        }))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|e| anyhow!("服务器名称不合法: {e}"))?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| anyhow!("TLS 握手失败: {e}"))?;

    let cert_der = captured
        .lock()
        .map_err(|_| anyhow!("证书捕获锁 poisoned"))?
        .take()
        .ok_or_else(|| anyhow!("服务器未提供证书"))?;

    let fingerprint = sha256_hex(&cert_der);
    Ok((
        tls,
        TlsInfo {
            cert_der,
            fingerprint,
        },
    ))
}

/// subject_public_key 从 DER 证书中提取 SubjectPublicKeyInfo 的 BIT STRING，
/// 供 CredSSP 绑定 TLS 通道使用。
pub(crate) fn subject_public_key(cert_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    use x509_cert::der::Decode as _;

    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("解析服务器证书失败: {e}"))?;
    let bits = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("证书公钥 BIT STRING 未对齐"))?;
    Ok(bits.to_vec())
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, data);
    let mut out = String::with_capacity(64);
    for b in digest.as_ref() {
        use core::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[derive(Debug)]
struct AcceptAnyCert {
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(end_entity.as_ref().to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls_ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
