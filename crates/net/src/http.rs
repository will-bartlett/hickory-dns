// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTP protocol related components for DNS over HTTP/2 (DoH) and HTTP/3 (DoH3)

use core::str::FromStr;
use std::sync::Arc;

use bytes::{Buf, BufMut, BytesMut};
use futures_util::{Stream, StreamExt};
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, header, uri};
use tracing::debug;

use crate::error::NetError;

pub(crate) struct RequestContext {
    pub(crate) version: Version,
    pub(crate) server_name: Arc<str>,
    pub(crate) query_path: Arc<str>,
    pub(crate) set_headers: Option<Arc<dyn SetHeaders>>,
}

impl RequestContext {
    /// Create a new Request for an http dns-message request
    ///
    /// ```text
    /// RFC 8484              DNS Queries over HTTPS (DoH)          October 2018
    ///
    /// The URI Template defined in this document is processed without any
    /// variables when the HTTP method is POST.  When the HTTP method is GET,
    /// the single variable "dns" is defined as the content of the DNS
    /// request (as described in Section 6), encoded with base64url
    /// [RFC4648].
    /// ```
    pub(crate) fn build(&self, message_len: usize) -> Result<Request<()>, NetError> {
        let mut parts = uri::Parts::default();
        parts.path_and_query = Some(
            uri::PathAndQuery::try_from(&*self.query_path)
                .map_err(|e| NetError::from(format!("invalid DoH path: {e}")))?,
        );
        parts.scheme = Some(uri::Scheme::HTTPS);
        parts.authority = Some(
            uri::Authority::from_str(&self.server_name)
                .map_err(|e| NetError::from(format!("invalid authority: {e}")))?,
        );

        let url =
            Uri::from_parts(parts).map_err(|e| NetError::from(format!("uri parse error: {e}")))?;

        // TODO: add user agent to TypedHeaders
        let mut request = Request::builder()
            .method("POST")
            .uri(url)
            .version(self.version.to_http())
            .header(CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(ACCEPT, MIME_APPLICATION_DNS)
            .header(CONTENT_LENGTH, message_len);

        if let Some(headers) = &self.set_headers {
            if let Some(map) = request.headers_mut() {
                headers.set_headers(map)?;
            }
        }

        request
            .body(())
            .map_err(|e| NetError::from(format!("http stream errored: {e}")))
    }
}

/// Verifies the request is well-formed for the name-server and supported protocols
fn verify<T>(
    version: Version,
    name_server: Option<&str>,
    query_path: &str,
    request: &Request<T>,
) -> Result<(), NetError> {
    // Verify all HTTP parameters
    let uri = request.uri();

    // validate path
    if uri.path() != query_path {
        return Err(format!("bad path: {}, expected: {}", uri.path(), query_path).into());
    }

    // we only accept HTTPS
    if Some(&uri::Scheme::HTTPS) != uri.scheme() {
        return Err("must be HTTPS scheme".into());
    }

    // the authority must match our nameserver name
    if let Some(name_server) = name_server {
        if let Some(authority) = uri.authority() {
            if authority.host() != name_server {
                return Err("incorrect authority".into());
            }
        } else {
            return Err("no authority in HTTPS request".into());
        }
    }

    // GET carries the DNS message in the URI, not a typed request body.
    if request.method() != Method::GET {
        match request.headers().get(CONTENT_TYPE).map(|v| v.to_str()) {
            Some(Ok(ctype)) if ctype == MIME_APPLICATION_DNS => {}
            _ => return Err("unsupported content type".into()),
        }
    }

    // TODO: switch to mime::APPLICATION_DNS when that stabilizes
    match request.headers().get(ACCEPT).map(|v| v.to_str()) {
        Some(Ok(ctype)) => {
            let mut found = false;
            for mime_and_quality in ctype.split(',') {
                let mut parts = mime_and_quality.splitn(2, ';');
                match parts.next() {
                    Some(mime) if mime.trim() == MIME_APPLICATION_DNS => {
                        found = true;
                        break;
                    }
                    Some(mime) if mime.trim() == "application/*" => {
                        found = true;
                        break;
                    }
                    _ => continue,
                }
            }

            if !found {
                return Err("does not accept content type".into());
            }
        }
        Some(Err(e)) => return Err(e.into()),
        None => return Err("Accept is unspecified".into()),
    };

    if request.version() != version.to_http() {
        let message = match version {
            #[cfg(feature = "__https")]
            Version::Http2 => "only HTTP/2 supported",
            #[cfg(feature = "__h3")]
            Version::Http3 => "only HTTP/3 supported",
        };
        return Err(message.into());
    }

    debug!(
        "verified request from: {}",
        request
            .headers()
            .get(header::USER_AGENT)
            .map(|h| h.to_str().unwrap_or("bad user agent"))
            .unwrap_or("unknown user agent")
    );

    Ok(())
}

/// Validate an HTTP request and collect its DNS message bytes.
pub async fn message_from<E: Into<NetError>>(
    version: Version,
    name_server: Option<&str>,
    query_path: &str,
    request: Request<impl Stream<Item = Result<impl Buf, E>> + Unpin>,
) -> Result<BytesMut, NetError> {
    verify(version, name_server, query_path, &request)?;

    let mut content_length = None;
    if let Some(length) = request.headers().get(CONTENT_LENGTH) {
        let length = usize::from_str(length.to_str()?)?;
        debug!("got message length: {}", length);
        content_length = Some(length);
    }

    match *request.method() {
        Method::GET => {
            if content_length.is_some_and(|length| length != 0) {
                return Err("GET body must be empty".into());
            }
            let message = message_from_query(request.uri().query())?;
            let mut body = request.into_body();
            while let Some(chunk) = body.next().await {
                if chunk.map_err(Into::into)?.has_remaining() {
                    return Err("GET body must be empty".into());
                }
            }
            Ok(message)
        }
        Method::POST => fetch_body(request.into_body(), content_length).await,
        _ => Err(format!("bad method: {}", request.method()).into()),
    }
}

fn message_from_query(query: Option<&str>) -> Result<BytesMut, NetError> {
    use data_encoding::BASE64URL_NOPAD;

    let query = query.ok_or("missing dns parameter")?;
    let mut dns = None;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if name != "dns" {
            continue;
        }
        if dns.is_some() {
            return Err("duplicate dns parameter".into());
        }
        dns = Some(value);
    }
    let dns = dns
        .filter(|value| !value.is_empty())
        .ok_or("missing or empty dns parameter")?;
    let invalid_encoding = || NetError::from("invalid unpadded base64url DNS message");
    let len = BASE64URL_NOPAD
        .decode_len(dns.len())
        .map_err(|_| invalid_encoding())?;
    if len > MAX_REQUEST_SIZE {
        return Err(NetError::RequestTooLarge);
    }
    let mut bytes = BytesMut::zeroed(len);
    BASE64URL_NOPAD
        .decode_mut(dns.as_bytes(), &mut bytes)
        .map_err(|_| invalid_encoding())?;
    Ok(bytes)
}

/// Fetch the body of the request from the stream
pub async fn fetch_body<E: Into<NetError>>(
    mut stream: impl Stream<Item = Result<impl Buf, E>> + Unpin,
    length: Option<usize>,
) -> Result<BytesMut, NetError> {
    let mut bytes = BytesMut::with_capacity(512);
    loop {
        match stream.next().await {
            Some(Ok(frame)) => match bytes.len() + frame.remaining() > MAX_REQUEST_SIZE {
                true => return Err(NetError::RequestTooLarge),
                false => bytes.put(frame),
            },
            Some(Err(err)) => return Err(err.into()),
            None => match length {
                Some(length) if bytes.len() == length => return Ok(bytes),
                Some(_) => return Err("body size does not match expected content-length".into()),
                None => return Ok(bytes),
            },
        };
    }
}

const MAX_REQUEST_SIZE: usize = u16::MAX as usize;

/// Create a new Response for an http dns-message request
///
/// ```text
/// RFC 8484              DNS Queries over HTTPS (DoH)          October 2018
///
///  4.2.1.  Handling DNS and HTTP Errors
///
/// DNS response codes indicate either success or failure for the DNS
/// query.  A successful HTTP response with a 2xx status code (see
/// Section 6.3 of [RFC7231]) is used for any valid DNS response,
/// regardless of the DNS response code.  For example, a successful 2xx
/// HTTP status code is used even with a DNS message whose DNS response
/// code indicates failure, such as SERVFAIL or NXDOMAIN.
///
/// HTTP responses with non-successful HTTP status codes do not contain
/// replies to the original DNS question in the HTTP request.  DoH
/// clients need to use the same semantic processing of non-successful
/// HTTP status codes as other HTTP clients.  This might mean that the
/// DoH client retries the query with the same DoH server, such as if
/// there are authorization failures (HTTP status code 401; see
/// Section 3.1 of [RFC7235]).  It could also mean that the DoH client
/// retries with a different DoH server, such as for unsupported media
/// types (HTTP status code 415; see Section 6.5.13 of [RFC7231]), or
/// where the server cannot generate a representation suitable for the
/// client (HTTP status code 406; see Section 6.5.6 of [RFC7231]), and so
/// on.
/// ```
pub fn response(version: Version, message_len: usize) -> Result<Response<()>, NetError> {
    Response::builder()
        .status(StatusCode::OK)
        .version(version.to_http())
        .header(CONTENT_TYPE, MIME_APPLICATION_DNS)
        .header(CONTENT_LENGTH, message_len)
        .body(())
        .map_err(|e| NetError::from(format!("invalid response: {e}")))
}

/// Represents a version of the HTTP spec.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    /// HTTP/2 for DoH.
    #[cfg(feature = "__https")]
    Http2,
    /// HTTP/3 for DoH3.
    #[cfg(feature = "__h3")]
    Http3,
}

impl Version {
    fn to_http(self) -> http::Version {
        match self {
            #[cfg(feature = "__https")]
            Self::Http2 => http::Version::HTTP_2,
            #[cfg(feature = "__h3")]
            Self::Http3 => http::Version::HTTP_3,
        }
    }
}

/// Helper trait to update HTTP headers on requests
///
/// For instance a DoH server may require authentication based
/// on per-request HTTP headers and this trait allows their addition.
pub trait SetHeaders: Send + Sync + 'static {
    /// Get a set of headers to add to the query
    fn set_headers(&self, headers: &mut HeaderMap<HeaderValue>) -> Result<(), NetError>;
}

pub(crate) const MIME_APPLICATION_DNS: &str = "application/dns-message";

/// The default query path for DNS-over-HTTPS if none was given.
pub const DEFAULT_DNS_QUERY_PATH: &str = "/dns-query";

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::stream;
    use http::{
        HeaderMap,
        header::{HeaderName, HeaderValue},
    };

    use super::*;
    use crate::proto::{
        op::Message,
        rr::{Name, RecordType},
    };

    #[test]
    fn test_from_get() {
        // RFC 8484 section 4.1.1 includes both a simple query and one requiring
        // the URL-safe alphabet and omission of padding.
        for (encoded, name) in [
            (
                "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
                "www.example.com.",
            ),
            (
                concat!(
                    "AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJl",
                    "bC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1z",
                    "dGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ"
                ),
                "a.62characterlabel-makes-base64url-distinct-from-standard-base64.example.com.",
            ),
        ] {
            let bytes = message_from_query(Some(&format!("dns={encoded}"))).unwrap();
            let message = Message::from_vec(&bytes).unwrap();
            assert_eq!(message.queries[0].name, Name::from_str(name).unwrap());
            assert_eq!(message.queries[0].query_type, RecordType::A);
        }
    }

    #[tokio::test]
    #[cfg(feature = "__https")]
    async fn test_get_large_message() {
        use data_encoding::BASE64URL_NOPAD;

        let message = vec![255; 47 * 1024];
        let query = format!("dns={}", BASE64URL_NOPAD.encode(&message));
        assert_eq!(read_get(&query).await.as_ref(), message);
    }

    #[cfg(feature = "__https")]
    async fn read_get(query: &str) -> BytesMut {
        let request = Request::get(format!("https://ns.example.com/dns-query?{query}"))
            .version(Version::Http2.to_http())
            .header(ACCEPT, MIME_APPLICATION_DNS)
            .body(stream::empty::<Result<Bytes, NetError>>())
            .unwrap();
        message_from(
            Version::Http2,
            Some("ns.example.com"),
            "/dns-query",
            request,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    #[cfg(feature = "__https")]
    async fn test_from_post() {
        test_support::subscribe();
        let message = Message::query();
        let msg_bytes = message.to_vec().unwrap();
        let len = msg_bytes.len();
        let stream = stream::iter([Ok::<_, NetError>(Bytes::from(msg_bytes))]);
        let cx = RequestContext {
            version: Version::Http2,
            server_name: Arc::from("ns.example.com"),
            query_path: Arc::from("/dns-query"),
            set_headers: None,
        };
        let request = cx.build(len).unwrap().map(|()| stream);
        let bytes = message_from(
            Version::Http2,
            Some("ns.example.com"),
            "/dns-query",
            request,
        )
        .await
        .unwrap();
        let msg_from_post = Message::from_vec(bytes.as_ref()).expect("bytes failed");
        assert_eq!(message, msg_from_post);
    }

    #[test]
    fn test_get_query_parameters() {
        for query in ["dns=AA", "ignored=value&dns=AA&other=value", "%64ns=%41%41"] {
            assert_eq!(message_from_query(Some(query)).unwrap().as_ref(), &[0]);
        }
        for query in [
            None,
            Some(""),
            Some("other=AA"),
            Some("DNS=AA"),
            Some("dns"),
            Some("dns="),
            Some("dns=AA&dns=AA"),
            Some("dns=AA&%64ns=AA"),
            Some("dns=AA&dns"),
            Some("dns=A"),
            Some("dns=AB"), // Nonzero trailing bits are not canonical base64url.
            Some("dns=AA=="),
            Some("dns=AA%3D%3D"),
            Some("dns=+w"),
            Some("dns=/w"),
            Some("dns=%2Bw"),
            Some("dns=%"),
            Some("dns=%GG"),
            Some("dns=AA%00"),
        ] {
            assert!(message_from_query(query).is_err(), "{query:?}");
        }
    }

    #[test]
    #[cfg(feature = "__https")]
    fn test_new_verify_h2() {
        let cx = RequestContext {
            version: Version::Http2,
            server_name: Arc::from("ns.example.com"),
            query_path: Arc::from("/dns-query"),
            set_headers: None,
        };

        let request = cx.build(512).expect("error converting to http");
        assert!(
            verify(
                Version::Http2,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );
    }

    #[tokio::test]
    #[cfg(feature = "__https")]
    async fn test_content_type_required_only_for_post() {
        for (method, valid) in [(Method::GET, true), (Method::POST, false)] {
            let request = Request::builder()
                .method(method)
                .version(Version::Http2.to_http())
                .uri("https://ns.example.com/dns-query?dns=AA")
                .header(ACCEPT, MIME_APPLICATION_DNS)
                .body(stream::empty::<Result<Bytes, NetError>>())
                .unwrap();
            assert_eq!(
                message_from(Version::Http2, None, "/dns-query", request)
                    .await
                    .is_ok(),
                valid,
            );
        }
    }

    #[tokio::test]
    #[cfg(feature = "__https")]
    async fn test_get_body_validation() {
        for (length, body, valid) in [
            (None, Bytes::from_static(b"x"), false),
            (Some(1), Bytes::new(), false),
            (Some(0), Bytes::new(), true),
        ] {
            let mut request = Request::builder()
                .method(Method::GET)
                .version(Version::Http2.to_http())
                .uri("https://ns.example.com/dns-query?dns=AA")
                .header(ACCEPT, MIME_APPLICATION_DNS);
            if let Some(length) = length {
                request = request.header(CONTENT_LENGTH, length);
            }
            let request = request
                .body(stream::iter([Ok::<_, NetError>(body)]))
                .unwrap();
            assert_eq!(
                message_from(Version::Http2, None, "/dns-query", request)
                    .await
                    .is_ok(),
                valid,
            );
        }
    }

    #[test]
    #[cfg(feature = "__https")]
    fn test_additional_headers() {
        let cx = RequestContext {
            version: Version::Http2,
            server_name: Arc::from("ns.example.com"),
            query_path: Arc::from("/dns-query"),
            set_headers: Some(Arc::new(vec![(
                HeaderName::from_static("test-header"),
                HeaderValue::from_static("test-header-value"),
            )]) as Arc<dyn SetHeaders>),
        };

        let request = cx.build(512).expect("error converting to http");
        assert!(
            verify(
                Version::Http2,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );

        assert_eq!(
            request
                .headers()
                .get(HeaderName::from_static("test-header"))
                .expect("header to be set"),
            HeaderValue::from_static("test-header-value")
        )
    }

    #[test]
    #[cfg(feature = "__h3")]
    fn test_new_verify_h3() {
        let cx = RequestContext {
            version: Version::Http3,
            server_name: Arc::from("ns.example.com"),
            query_path: Arc::from("/dns-query"),
            set_headers: None,
        };

        let request = cx.build(512).expect("error converting to http");
        assert!(
            verify(
                Version::Http3,
                Some("ns.example.com"),
                "/dns-query",
                &request
            )
            .is_ok()
        );
    }

    impl SetHeaders for Vec<(HeaderName, HeaderValue)> {
        fn set_headers(&self, map: &mut HeaderMap<HeaderValue>) -> Result<(), NetError> {
            for (name, value) in self.iter() {
                map.insert(name.clone(), value.clone());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn fetch_body_accumulates_chunks() {
        let mut body = chunks(&[512, 512, 200]);
        let bytes = fetch_body(&mut body, None).await.unwrap();
        assert_eq!(bytes.len(), 1224);
    }

    #[tokio::test]
    async fn fetch_body_stops_at_content_length() {
        let mut body = chunks(&[512, 512]);
        assert!(fetch_body(&mut body, Some(512)).await.is_err());
    }

    #[tokio::test]
    async fn fetch_body_short_body_errors() {
        let mut body = chunks(&[512]);
        assert!(fetch_body(&mut body, Some(1024)).await.is_err());
    }

    #[tokio::test]
    async fn fetch_body_single_oversized_chunk() {
        // a single chunk exceeding the limit is rejected without being buffered
        let mut body = chunks(&[MAX_REQUEST_SIZE + 1]);
        assert!(matches!(
            fetch_body(&mut body, None).await,
            Err(NetError::RequestTooLarge)
        ));
    }

    #[tokio::test]
    async fn fetch_body_accumulated_oversize_rejected() {
        // no single chunk is too large, but together they exceed the limit
        let half = MAX_REQUEST_SIZE / 2 + 1;
        let mut body = chunks(&[half, half]);
        assert!(matches!(
            fetch_body(&mut body, None).await,
            Err(NetError::RequestTooLarge)
        ));
    }

    #[tokio::test]
    async fn fetch_body_at_limit_ok() {
        // a body exactly at the limit is still accepted
        let mut body = chunks(&[MAX_REQUEST_SIZE]);
        let bytes = fetch_body(&mut body, None).await.unwrap();
        assert_eq!(bytes.len(), MAX_REQUEST_SIZE);
    }

    fn chunks(lengths: &[usize]) -> impl Stream<Item = Result<Bytes, NetError>> + Unpin {
        stream::iter(
            lengths
                .iter()
                .map(|&len| Ok(Bytes::from(vec![0u8; len])))
                .collect::<Vec<_>>(),
        )
    }
}
