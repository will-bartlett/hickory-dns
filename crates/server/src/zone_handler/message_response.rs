// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use tracing::{debug, error};

use crate::{
    net::xfer::Protocol,
    proto::{
        ProtoError,
        op::{
            Edns, Header, HeaderCounts, MessageRequest, MessageType, Metadata, OpCode, Queries,
            QueriesEmitAndCount, ResponseCode, emit_message_parts,
        },
        rr::{Record, rdata::TSIG},
        serialize::binary::{BinEncodable, BinEncoder},
    },
    server::ResponseInfo,
};

/// A [`crate::proto::serialize::binary::BinEncodable`] message with borrowed data for
/// Responses in the Server
///
/// This can be constructed via [`MessageResponseBuilder`].
#[derive(Debug)]
pub struct MessageResponse<'q, 'a, Answers, Authorities, Soa, Additionals>
where
    Answers: Iterator<Item = &'a Record> + Send + 'a,
    Authorities: Iterator<Item = &'a Record> + Send + 'a,
    Soa: Iterator<Item = &'a Record> + Send + 'a,
    Additionals: Iterator<Item = &'a Record> + Send + 'a,
{
    metadata: Metadata,
    queries: Option<&'q Queries>,
    answers: Answers,
    authorities: Authorities,
    soa: Soa,
    additionals: Additionals,
    signature: Option<Box<Record<TSIG>>>,
    edns: Option<&'q Edns>,
}

impl<'q, 'a, A, N, S, D> MessageResponse<'q, 'a, A, N, S, D>
where
    A: Iterator<Item = &'a Record> + Send + 'a,
    N: Iterator<Item = &'a Record> + Send + 'a,
    S: Iterator<Item = &'a Record> + Send + 'a,
    D: Iterator<Item = &'a Record> + Send + 'a,
{
    /// Returns the header of the message
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get a mutable reference to the header
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    /// Set the EDNS options for the Response
    pub fn set_edns(&mut self, edns: &'q Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Gets a reference to the EDNS options for the Response.
    pub fn edns(&self) -> Option<&'q Edns> {
        self.edns
    }

    /// Set the message signature
    pub fn set_signature(&mut self, signature: Box<Record<TSIG>>) {
        self.signature = Some(signature);
    }

    pub(crate) fn encode(
        mut self,
        protocol: Protocol,
    ) -> Result<(ResponseInfo, Vec<u8>, Option<u32>), ProtoError> {
        use crate::proto::rr::RData;

        fn record_ttl(record: &Record) -> u32 {
            // RFC 2181 section 8 treats TTLs with the high bit set as zero.
            if record.ttl > i32::MAX as u32 {
                0
            } else {
                record.ttl
            }
        }

        let id = self.metadata.id;
        debug!(
            id,
            response_code = %self.metadata.response_code,
            "encoding response"
        );

        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(match protocol {
            Protocol::Udp => match &self.edns {
                Some(edns) => edns.max_payload(),
                // No EDNS, so the requestor advertised no buffer and RFC 1035 section 4.2.1
                // restricts the message to 512 bytes
                None => 512,
            },
            _ => u16::MAX,
        });

        let cacheable = self.signature.is_none() && self.metadata.op_code == OpCode::Query;
        let mut answer_ttl: Option<u32> = None;
        let mut negative_ttl: Option<u32> = None;
        let result = emit_message_parts(
            &self.metadata,
            &mut match self.queries {
                Some(queries) => queries.as_emit_and_count(),
                None => QueriesEmitAndCount::None,
            },
            &mut self.answers.inspect(|record| {
                let ttl = record_ttl(record);
                answer_ttl = Some(answer_ttl.map_or(ttl, |previous| previous.min(ttl)));
            }),
            &mut self.authorities.chain(self.soa).inspect(|record| {
                if let RData::SOA(soa) = &record.data {
                    let ttl = record_ttl(record).min(soa.minimum);
                    negative_ttl = Some(negative_ttl.map_or(ttl, |previous| previous.min(ttl)));
                }
            }),
            &mut self.additionals,
            self.edns,
            self.signature.as_deref(),
            &mut encoder,
        )
        .map(ResponseInfo::from);

        let error = match result {
            Ok(info) => {
                // Inspect can observe a record that does not fit; truncated
                // responses must not get freshness derived from those records.
                let ttl = if !cacheable || info.truncation {
                    None
                } else {
                    match (info.response_code, answer_ttl, negative_ttl) {
                        (
                            ResponseCode::NoError | ResponseCode::NXDomain,
                            Some(answer),
                            Some(soa),
                        ) => Some(answer.min(soa)),
                        (ResponseCode::NoError, Some(answer), None) => Some(answer),
                        (ResponseCode::NoError | ResponseCode::NXDomain, None, Some(soa)) => {
                            Some(soa)
                        }
                        _ => None,
                    }
                };
                return Ok((info, bytes, ttl));
            }
            Err(error) => error,
        };

        error!(%error, "error encoding message");
        bytes.clear();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(512);

        let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
        metadata.response_code = ResponseCode::ServFail;
        let header = Header {
            metadata,
            counts: HeaderCounts::default(),
        };

        header.emit(&mut encoder)?;
        Ok((ResponseInfo::from(header), bytes, None))
    }

    /// Consumes self, and emits to the encoder.
    pub fn destructive_emit(
        mut self,
        encoder: &mut BinEncoder<'_>,
    ) -> Result<ResponseInfo, ProtoError> {
        // soa records are part of the authority section
        let mut authorities = self.authorities.chain(self.soa);

        let header = emit_message_parts(
            &self.metadata,
            &mut match self.queries {
                Some(queries) => queries.as_emit_and_count(),
                None => QueriesEmitAndCount::None,
            },
            &mut self.answers,
            &mut authorities,
            &mut self.additionals,
            self.edns,
            self.signature.as_deref(),
            encoder,
        )?;

        Ok(ResponseInfo::from(header))
    }
}

/// A builder for MessageResponses
pub struct MessageResponseBuilder<'q> {
    queries: Option<&'q Queries>,
    signature: Option<Box<Record<TSIG>>>,
    edns: Option<&'q Edns>,
}

impl<'q> MessageResponseBuilder<'q> {
    /// Constructs a new response builder
    ///
    /// # Arguments
    ///
    /// * `message` - original request message to associate with the response
    ///
    /// # Example
    ///
    /// ```rust
    /// use hickory_proto::{op::ResponseCode, rr::Record};
    /// use hickory_server::{
    ///     server::Request,
    ///     zone_handler::{MessageResponse, MessageResponseBuilder},
    /// };
    ///
    /// fn handle_request<'q>(request: &'q Request) -> MessageResponse<
    ///     'q,
    ///     'static,
    ///     impl Iterator<Item = &'static Record> + Send + 'static,
    ///     impl Iterator<Item = &'static Record> + Send + 'static,
    ///     impl Iterator<Item = &'static Record> + Send + 'static,
    ///     impl Iterator<Item = &'static Record> + Send + 'static,
    /// > {
    ///     MessageResponseBuilder::from_message_request(request)
    ///         .error_msg(&request.metadata, ResponseCode::ServFail)
    /// }
    /// ```
    pub fn from_message_request(message: &'q MessageRequest) -> Self {
        Self::new(&message.queries, None)
    }

    /// Constructs a new response builder
    ///
    /// # Arguments
    ///
    /// * `queries` - queries (from the Request) to associate with the Response
    /// * `edns` - Optional Edns data to associate with the Response
    pub fn new(queries: &'q Queries, edns: Option<&'q Edns>) -> Self {
        MessageResponseBuilder {
            queries: Some(queries),
            signature: None,
            edns,
        }
    }

    /// Constructs a new response builder for a request with no queries
    ///
    /// # Arguments
    ///
    /// * `edns` - Optional Edns data to associate with the Response
    pub fn no_queries(edns: Option<&'q Edns>) -> Self {
        MessageResponseBuilder {
            queries: None,
            signature: None,
            edns,
        }
    }

    /// Associate EDNS with the Response
    pub fn edns(&mut self, edns: &'q Edns) -> &mut Self {
        self.edns = Some(edns);
        self
    }

    /// Constructs the new MessageResponse with associated data
    pub fn build<'a, A, N, S, D>(
        self,
        metadata: Metadata,
        answers: A,
        authorities: N,
        soa: S,
        additionals: D,
    ) -> MessageResponse<'q, 'a, A::IntoIter, N::IntoIter, S::IntoIter, D::IntoIter>
    where
        A: IntoIterator<Item = &'a Record> + Send + 'a,
        A::IntoIter: Send,
        N: IntoIterator<Item = &'a Record> + Send + 'a,
        N::IntoIter: Send,
        S: IntoIterator<Item = &'a Record> + Send + 'a,
        S::IntoIter: Send,
        D: IntoIterator<Item = &'a Record> + Send + 'a,
        D::IntoIter: Send,
    {
        MessageResponse {
            metadata,
            queries: self.queries,
            answers: answers.into_iter(),
            authorities: authorities.into_iter(),
            soa: soa.into_iter(),
            additionals: additionals.into_iter(),
            signature: self.signature,
            edns: self.edns,
        }
    }

    /// Construct a Response with no associated records
    pub fn build_no_records<'a>(
        self,
        metadata: Metadata,
    ) -> MessageResponse<
        'q,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    > {
        MessageResponse {
            metadata,
            queries: self.queries,
            answers: Box::new(None.into_iter()),
            authorities: Box::new(None.into_iter()),
            soa: Box::new(None.into_iter()),
            additionals: Box::new(None.into_iter()),
            signature: self.signature,
            edns: self.edns,
        }
    }

    /// Constructs a new error MessageResponse with associated header and response code
    pub fn error_msg<'a>(
        self,
        request_meta: &Metadata,
        response_code: ResponseCode,
    ) -> MessageResponse<
        'q,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    > {
        let mut metadata = Metadata::response_from_request(request_meta);
        metadata.response_code = response_code;

        MessageResponse {
            metadata,
            queries: self.queries,
            answers: Box::new(None.into_iter()),
            authorities: Box::new(None.into_iter()),
            soa: Box::new(None.into_iter()),
            additionals: Box::new(None.into_iter()),
            signature: self.signature,
            edns: self.edns,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use crate::proto::op::{Header, Message, MessageType, Metadata, OpCode, Query};
    use crate::proto::rr::{DNSClass, Name, RData, Record};
    use crate::proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};

    use super::*;

    #[test]
    fn test_udp_response_cache_ttl() {
        let answer = Record::from_rdata(Name::root(), 60, RData::A(Ipv4Addr::LOCALHOST.into()));
        let (_, _, ttl) = MessageResponseBuilder::no_queries(None)
            .build(
                Metadata::new(0, MessageType::Response, OpCode::Query),
                [&answer],
                [],
                [],
                [],
            )
            .encode(Protocol::Udp)
            .unwrap();
        assert_eq!(ttl, Some(60));
    }

    mod cache_ttl {
        use super::*;
        use crate::proto::rr::rdata::{
            CNAME, SOA, TXT,
            tsig::{TsigAlgorithm, make_tsig_record},
        };

        fn answer(ttl: u32) -> Record {
            Record::from_rdata(
                Name::from_ascii("www.example.com.").unwrap(),
                ttl,
                RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
            )
        }

        fn soa(ttl: u32, minimum: u32) -> Record {
            Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                ttl,
                RData::SOA(SOA::new(
                    Name::from_ascii("ns.example.com.").unwrap(),
                    Name::from_ascii("hostmaster.example.com.").unwrap(),
                    1,
                    3600,
                    600,
                    86400,
                    minimum,
                )),
            )
        }

        fn encode(
            answers: &[Record],
            authorities: &[Record],
            soa: &[Record],
            response_code: ResponseCode,
        ) -> (ResponseInfo, Vec<u8>, Option<u32>) {
            let mut metadata = Metadata::new(0, MessageType::Response, OpCode::Query);
            metadata.response_code = response_code;
            MessageResponseBuilder::no_queries(None)
                .build(metadata, answers, authorities, soa, [])
                .encode(Protocol::Tcp)
                .unwrap()
        }

        #[test]
        fn minimum_remaining_answer_ttl() {
            let mut answers = [answer(300), answer(60), answer(120)];
            assert_eq!(
                encode(&answers, &[], &[], ResponseCode::NoError).2,
                Some(60)
            );
            for record in &mut answers {
                record.decrement_ttl(20);
            }
            let (_, bytes, ttl) = encode(&answers, &[], &[], ResponseCode::NoError);
            assert_eq!(ttl, Some(40));
            assert_eq!(Message::from_vec(&bytes).unwrap().answers, answers);
            for answers in [vec![answer(0)], vec![answer(60), answer(1 << 31)]] {
                assert_eq!(encode(&answers, &[], &[], ResponseCode::NoError).2, Some(0));
            }
        }

        #[test]
        fn negative_ttl_from_either_authority_iterator() {
            for code in [ResponseCode::NoError, ResponseCode::NXDomain] {
                for (ttl, minimum, expected) in [
                    (300, 60, 60),
                    (30, 60, 30),
                    (0, 60, 0),
                    (60, 0, 0),
                    (1 << 31, 60, 0),
                ] {
                    let soa = [soa(ttl, minimum)];
                    assert_eq!(encode(&[], &soa, &[], code).2, Some(expected));
                    assert_eq!(encode(&[], &[], &soa, code).2, Some(expected));
                }
            }
        }

        #[test]
        fn negative_answer_also_bounds_alias_ttl() {
            let cname = Record::from_rdata(
                Name::from_ascii("www.example.com.").unwrap(),
                300,
                RData::CNAME(CNAME(Name::from_ascii("missing.example.com.").unwrap())),
            );
            for code in [ResponseCode::NoError, ResponseCode::NXDomain] {
                assert_eq!(
                    encode(std::slice::from_ref(&cname), &[], &[soa(60, 30)], code).2,
                    Some(30)
                );
            }
        }

        #[test]
        fn missing_ttl_and_errors_are_not_cacheable() {
            for code in [
                ResponseCode::NoError,
                ResponseCode::NXDomain,
                ResponseCode::Refused,
                ResponseCode::ServFail,
            ] {
                assert_eq!(encode(&[], &[], &[], code).2, None);
            }
            for code in [
                ResponseCode::NXDomain,
                ResponseCode::Refused,
                ResponseCode::ServFail,
            ] {
                assert_eq!(encode(&[answer(60)], &[], &[], code).2, None);
            }
        }

        #[test]
        fn signed_response_is_not_cacheable() {
            let answers = [answer(60)];
            let mut response = MessageResponseBuilder::no_queries(None).build(
                Metadata::new(0, MessageType::Response, OpCode::Query),
                &answers,
                [],
                [],
                [],
            );
            response.set_signature(Box::new(make_tsig_record(
                Name::root(),
                TSIG::new(TsigAlgorithm::HmacSha256, 0, 300, vec![], 0, None, vec![]),
            )));
            let (info, _, ttl) = response.encode(Protocol::Tcp).unwrap();
            assert_eq!(info.response_code, ResponseCode::NoError);
            assert_eq!(info.counts().additionals, 1);
            assert_eq!(ttl, None);
        }

        #[test]
        fn non_query_response_is_not_cacheable() {
            let answers = [answer(60)];
            let (info, _, ttl) = MessageResponseBuilder::no_queries(None)
                .build(
                    Metadata::new(0, MessageType::Response, OpCode::Update),
                    &answers,
                    [],
                    [],
                    [],
                )
                .encode(Protocol::Tcp)
                .unwrap();
            assert_eq!(info.response_code, ResponseCode::NoError);
            assert_eq!(info.counts().answers, 1);
            assert_eq!(ttl, None);
        }

        #[test]
        fn truncation_is_not_cacheable() {
            let answer = answer(60);
            let metadata = Metadata::new(0, MessageType::Response, OpCode::Query);
            let (info, _, ttl) = MessageResponseBuilder::no_queries(None)
                .build(metadata, iter::repeat(&answer), [], [], [])
                .encode(Protocol::Tcp)
                .unwrap();
            assert!(info.truncation);
            assert_eq!(ttl, None);
        }

        #[test]
        fn encoding_fallback_is_not_cacheable() {
            let invalid = Record::from_rdata(
                Name::root(),
                60,
                RData::TXT(TXT::new(vec!["x".repeat(256)])),
            );
            let (info, bytes, ttl) =
                encode(&[answer(60), invalid], &[], &[], ResponseCode::NoError);
            assert_eq!(info.response_code, ResponseCode::ServFail);
            assert_eq!(
                Message::from_vec(&bytes).unwrap().metadata.response_code,
                ResponseCode::ServFail
            );
            assert_eq!(ttl, None);
        }
    }

    #[test]
    fn test_truncation_ridiculous_number_answers() {
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(512);

            let mut answer = Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                0,
                RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
            );
            answer.dns_class = DNSClass::NONE;

            let request = MessageRequest::mock(
                Metadata::new(10, MessageType::Query, OpCode::Query),
                Query::root(),
            );

            let response = MessageResponseBuilder::from_message_request(&request).build(
                Metadata::new(10, MessageType::Response, OpCode::Query),
                iter::repeat(&answer),
                iter::repeat(&answer),
                iter::repeat(&answer),
                iter::repeat(&answer),
            );

            response
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.metadata.truncation);
        assert!(response.answers.len() > 1);
        // should never have written the authority section...
        assert_eq!(response.authorities.len(), 0);
    }

    #[test]
    fn test_truncation_ridiculous_number_nameservers() {
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(512);

            let mut answer = Record::from_rdata(
                Name::from_str("www.example.com.").unwrap(),
                0,
                RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
            );
            answer.dns_class = DNSClass::NONE;

            let request = MessageRequest::mock(
                Metadata::new(10, MessageType::Query, OpCode::Query),
                Query::root(),
            );

            let response = MessageResponseBuilder::from_message_request(&request).build(
                Metadata::new(10, MessageType::Response, OpCode::Query),
                [],
                iter::repeat(&answer),
                iter::repeat(&answer),
                iter::repeat(&answer),
            );

            response
                .destructive_emit(&mut encoder)
                .expect("failed to encode");
        }

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.metadata.truncation);
        assert_eq!(response.answers.len(), 0);
        assert!(response.authorities.len() > 1);
    }

    /// A response with no OPT record answers a request that had none, so RFC 1035 section 4.2.1
    /// applies and the message may not exceed 512 bytes.
    #[test]
    fn test_non_edns_udp_response_is_bounded_at_512() {
        let answer = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            0,
            RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
        );

        let request = MessageRequest::mock(
            Metadata::new(10, MessageType::Query, OpCode::Query),
            Query::root(),
        );
        assert_eq!(request.max_payload(), 512);

        let response = MessageResponseBuilder::from_message_request(&request).build(
            Metadata::new(10, MessageType::Response, OpCode::Query),
            iter::repeat(&answer),
            [],
            [],
            [],
        );

        let (_info, buf, _) = response.encode(Protocol::Udp).expect("failed to encode");
        assert!(buf.len() <= 512, "response was {} bytes", buf.len());

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.metadata.truncation);
        assert!(response.answers.len() > 1);
    }

    /// RFC 6891 section 7 requires the OPT record to be present even when the response is
    /// truncated, so answers have to give way to it rather than the other way around.
    #[test]
    fn test_opt_record_is_kept_when_truncating() {
        let answer = Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            0,
            RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
        );

        let mut edns = Edns::new();
        edns.set_max_payload(512);

        let request = MessageRequest::mock(
            Metadata::new(10, MessageType::Query, OpCode::Query),
            Query::root(),
        );
        let mut response = MessageResponseBuilder::from_message_request(&request).build(
            Metadata::new(10, MessageType::Response, OpCode::Query),
            iter::repeat(&answer),
            [],
            [],
            [],
        );
        response.set_edns(&edns);

        let (_info, buf, _) = response.encode(Protocol::Udp).expect("failed to encode");
        assert!(buf.len() <= 512, "response was {} bytes", buf.len());

        let response = Message::from_vec(&buf).expect("failed to decode");
        assert!(response.metadata.truncation);
        assert!(response.answers.len() > 1);
        assert!(response.edns.is_some(), "OPT record was dropped");
    }

    // https://github.com/hickory-dns/hickory-dns/issues/2210
    // If a client sends this DNS request to the hickory 0.24.0 DNS server:
    //
    // 08 00 00 00 00 01 00 00 00 00 00 00 c0 00 00 00 00 00 00 00 00 00 00
    // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    // 00 00
    //
    // i.e.:
    // 08 00 ID
    // 00 00 flags
    // 00 01 QDCOUNT
    // 00 00 ANCOUNT
    // 00 00 NSCOUNT
    // 00 00 ARCOUNT
    // c0 00 QNAME
    // 00 00 QTYPE
    // 00 00 QCLASS
    //
    // hickory-dns fails the 2nd assert here while building the reply message
    // (really while remembering names for pointers):
    //
    // pub fn slice_of(&self, start: usize, end: usize) -> &[u8] {
    //     assert!(start < self.offset);
    //     assert!(end <= self.buffer.len());
    //     &self.buffer.buffer()[start..end]
    // }
    // The name is eight bytes long, but the current message size (after the
    // current offset of 12) is only six, because QueriesEmitAndCount::emit()
    // stored just the six bytes of the original encoded query:
    //
    //     encoder.emit_vec(self.cached_serialized)?;
    #[test]
    fn bad_length_of_named_pointers() {
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);

        let data: &[u8] = &[
            0x08u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut decoder = BinDecoder::new(data);
        let header = Header::read(&mut decoder).unwrap();
        let msg = MessageRequest::read(&mut decoder, header).unwrap();

        eprintln!("query: {:?}", *msg.queries);

        MessageResponseBuilder::new(&msg.queries, None)
            .build_no_records(Metadata::response_from_request(&msg.metadata))
            .destructive_emit(&mut encoder)
            .unwrap();
    }
}
