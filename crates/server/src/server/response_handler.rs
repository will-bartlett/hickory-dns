// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;

use crate::{
    net::{BufDnsStreamHandle, DnsStreamHandle, NetError, xfer::Protocol},
    proto::{op::SerialMessage, rr::Record},
    server::ResponseInfo,
    zone_handler::MessageResponse,
};

#[cfg(any(feature = "__https", feature = "__h3"))]
pub(super) fn http_response(
    version: crate::net::http::Version,
    message_len: usize,
    ttl: Option<u32>,
) -> Result<http::Response<()>, NetError> {
    use http::{HeaderValue, header};

    let mut response = crate::net::http::response(version, message_len)?;
    let cache_control = match ttl {
        // Request handlers may return different answers to different clients.
        Some(ttl) => format!("private, max-age={ttl}")
            .parse()
            .expect("a numeric TTL produces a valid HTTP header"),
        None => HeaderValue::from_static("no-store"),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, cache_control);
    Ok(response)
}

/// A handler for send a response to a client
#[async_trait::async_trait]
pub trait ResponseHandler: Send + Sync + Unpin + 'static {
    // TODO: add associated error type
    //type Error;

    /// Serializes and sends a message to the wrapped handle
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError>;
}

/// A handler for wrapping a [`BufDnsStreamHandle`], which will properly serialize the message and add the
///  associated destination.
#[derive(Clone)]
pub struct ResponseHandle {
    dst: SocketAddr,
    stream_handle: BufDnsStreamHandle,
    protocol: Protocol,
}

impl ResponseHandle {
    /// Returns a new `ResponseHandle` for sending a response message
    pub fn new(dst: SocketAddr, stream_handle: BufDnsStreamHandle, protocol: Protocol) -> Self {
        Self {
            dst,
            stream_handle,
            protocol,
        }
    }
}

#[async_trait::async_trait]
impl ResponseHandler for ResponseHandle {
    /// Serializes and sends a message to the wrapped handle
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let (info, buffer, _) = response.encode(self.protocol)?;
        self.stream_handle
            .send(SerialMessage::new(buffer, self.dst))?;

        Ok(info)
    }
}

#[cfg(all(test, any(feature = "__https", feature = "__h3")))]
mod tests {
    use super::*;
    use crate::net::http::Version;

    #[test]
    fn http_cache_headers_match_across_versions() {
        for version in [
            #[cfg(feature = "__https")]
            Version::Http2,
            #[cfg(feature = "__h3")]
            Version::Http3,
        ] {
            for (ttl, expected) in [
                (Some(60), "private, max-age=60"),
                (Some(0), "private, max-age=0"),
                (None, "no-store"),
            ] {
                let response = http_response(version, 12, ttl).unwrap();
                assert_eq!(response.headers()[http::header::CACHE_CONTROL], expected);
            }
        }
    }
}
