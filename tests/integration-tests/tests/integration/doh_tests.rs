use std::{env, path::Path, sync::Arc, time::Duration};

use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use http::{Method, Request, Response, StatusCode, header};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{PrivateKeyDer, pem::PemObject},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
use tokio::time::timeout;

use hickory_net::{http::fetch_body, tls::default_provider};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, rdata::A},
};
use hickory_server::{Server, zone_handler::Catalog};

use super::server_future_tests::{new_catalog, read_certs};

const DNS_QUERY: &str = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB";
const ENDPOINT: &str = "https://ns.example.com/custom-dns";

#[cfg(feature = "__https")]
#[tokio::test]
async fn test_https_get_and_post() {
    use rustls::pki_types::ServerName;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    timeout(Duration::from_secs(15), async {
        let (mut server, certificate, crypto) = server_and_tls(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        server
            .register_https_listener(
                listener,
                Duration::from_secs(5),
                certificate,
                Some("ns.example.com".into()),
                "/custom-dns".into(),
            )
            .unwrap();

        let tcp = TcpStream::connect(address).await.unwrap();
        let tls = TlsConnector::from(Arc::new(crypto))
            .connect(ServerName::try_from("ns.example.com").unwrap(), tcp)
            .await
            .unwrap();
        let (mut client, driver) = h2::client::handshake(tls).await.unwrap();
        let driver = tokio::spawn(driver);
        let mut responses = Vec::new();
        for method in [Method::GET, Method::POST] {
            let (request, body) = doh_request(method);
            client = client.ready().await.unwrap();
            let (response, mut stream) = client.send_request(request, body.is_none()).unwrap();
            if let Some(body) = body {
                stream.send_data(body, true).unwrap();
            }
            let mut response = response.await.unwrap();
            let bytes = fetch_body(response.body_mut(), None).await.unwrap();
            responses.push(assert_response(&response, &bytes));
        }
        assert_eq!(responses[0], responses[1]);
        driver.abort();
        server.shutdown_gracefully().await.unwrap();
    })
    .await
    .expect("HTTP/2 exchange timed out");
}

#[cfg(feature = "__h3")]
#[tokio::test]
async fn test_h3_get_and_post() {
    use h3_quinn::quinn::{ClientConfig as QuicConfig, Endpoint, crypto::rustls::QuicClientConfig};
    use hickory_net::h3::BodyStream;
    use std::{future::poll_fn, task::Context};
    use tokio::net::UdpSocket;

    timeout(Duration::from_secs(15), async {
        let (mut server, certificate, crypto) = server_and_tls(b"h3");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        server
            .register_h3_listener(
                socket,
                Duration::from_secs(5),
                certificate,
                Some("ns.example.com".into()),
                "/custom-dns".into(),
            )
            .unwrap();

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(QuicConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).unwrap(),
        )));
        let connection = endpoint
            .connect(address, "ns.example.com")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut client) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let driver = tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });

        let mut responses = Vec::new();
        for method in [Method::GET, Method::POST] {
            let (request, body) = doh_request(method);
            let mut stream = client.send_request(request).await.unwrap();
            if let Some(body) = body {
                stream.send_data(body).await.unwrap();
            }
            stream.finish().await.unwrap();
            let response = stream.recv_response().await.unwrap();
            let bytes = fetch_body(
                BodyStream::from(|cx: &mut Context<'_>| stream.poll_recv_data(cx)),
                None,
            )
            .await
            .unwrap();
            responses.push(assert_response(&response, &bytes));
        }
        assert_eq!(responses[0], responses[1]);
        connection.close(0u32.into(), b"test complete");
        driver.abort();
        server.shutdown_gracefully().await.unwrap();
    })
    .await
    .expect("HTTP/3 exchange timed out");
}

fn server_and_tls(alpn: &[u8]) -> (Server<Catalog>, Arc<dyn ResolvesServerCert>, ClientConfig) {
    test_support::subscribe();
    let root = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
    let directory = Path::new(&root).join("tests").join("test-data");
    let ca = read_certs(directory.join("ca.pem")).unwrap();
    let chain = read_certs(directory.join("cert.pem")).unwrap();
    let key = PrivateKeyDer::from_pem_file(directory.join("cert.key")).unwrap();
    let certificate = Arc::new(SingleCertAndKey::from(
        CertifiedKey::from_der(chain, key, &default_provider()).unwrap(),
    ));
    let mut roots = RootCertStore::empty();
    for certificate in ca {
        roots.add(certificate).unwrap();
    }
    let mut crypto = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.to_vec()];
    (Server::new(new_catalog()), certificate, crypto)
}

fn doh_request(method: Method) -> (Request<()>, Option<Bytes>) {
    let mut request = Request::builder()
        .method(method.clone())
        .header(header::ACCEPT, "application/dns-message");
    let body = if method == Method::GET {
        request = request.uri(format!("{ENDPOINT}?dns={DNS_QUERY}"));
        None
    } else {
        let bytes = Bytes::from(BASE64URL_NOPAD.decode(DNS_QUERY.as_bytes()).unwrap());
        request = request
            .uri(ENDPOINT)
            .header(header::CONTENT_TYPE, "application/dns-message")
            .header(header::CONTENT_LENGTH, bytes.len());
        Some(bytes)
    };
    (request.body(()).unwrap(), body)
}

fn assert_response<T>(response: &Response<T>, bytes: &[u8]) -> Message {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/dns-message"
    );
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        bytes.len().to_string()
    );
    let message = Message::from_vec(bytes).unwrap();
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.metadata.authoritative);
    assert_eq!(message.queries[0].name.to_string(), "www.example.com.");
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].data, RData::A(A::new(93, 184, 215, 14)));
    assert_eq!(message.answers[0].ttl, 86400);
    message
}
