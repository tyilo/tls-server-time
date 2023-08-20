use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
};

use clap::Parser;
use rustls::{
    client::InvalidDnsNameError,
    internal::msgs::{
        alert::AlertMessagePayload,
        base::Payload,
        codec::{Codec, Reader},
        enums::{Compression, ECPointFormat},
        handshake::{
            ClientExtension, ClientHelloPayload, ClientSessionTicket, HandshakeMessagePayload,
            HandshakePayload, Random, ServerHelloPayload, SessionId,
        },
        message::{MessageError, MessagePayload, OpaqueMessage},
    },
    ContentType, HandshakeType, NamedGroup, ProtocolVersion, ServerName, SignatureScheme,
    DEFAULT_CIPHER_SUITES,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

fn parse_server_name(s: &str) -> Result<ServerName, InvalidDnsNameError> {
    ServerName::try_from(s)
}

#[derive(Parser)]
struct Args {
    #[arg(value_parser = parse_server_name)]
    hostname: ServerName,

    #[arg(short, long, default_value = "443")]
    port: u16,
}

fn main() {
    let args = Args::parse();
    let client_hello = create_client_hello(&args.hostname);

    eprintln!("Sending client hello: {:02x?}", client_hello);

    let tcp_stream = tcp_connect(&args.hostname, args.port);
    let server_hello = retrieve_server_hello(tcp_stream, &client_hello);
    let server_hello = parse_server_hello(&server_hello);

    let server_hello_random = server_hello.random.0;
    let timestamp = u32::from_be_bytes(server_hello_random[..4].try_into().unwrap());

    let date_time = OffsetDateTime::from_unix_timestamp(timestamp.into()).unwrap();
    eprintln!();
    println!("{}", date_time.format(&Rfc3339).unwrap());
}

fn tcp_connect(server_name: &ServerName, port: u16) -> TcpStream {
    let stream = match server_name {
        ServerName::DnsName(dns_name) => TcpStream::connect((dns_name.as_ref(), port)),
        ServerName::IpAddress(ip_address) => TcpStream::connect(SocketAddr::new(*ip_address, port)),
        _ => panic!("unknown ServerName variant encountered"),
    };
    stream.unwrap()
}

fn create_client_hello(server_name: &ServerName) -> Vec<u8> {
    let mut extensions = vec![
        ClientExtension::ECPointFormats(vec![
            ECPointFormat::Uncompressed,
            ECPointFormat::ANSIX962CompressedPrime,
            ECPointFormat::ANSIX962CompressedChar2,
        ]),
        ClientExtension::NamedGroups(vec![
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
            NamedGroup::secp521r1,
            NamedGroup::X25519,
            NamedGroup::X448,
            NamedGroup::FFDHE2048,
            NamedGroup::FFDHE3072,
            NamedGroup::FFDHE4096,
            NamedGroup::FFDHE6144,
            NamedGroup::FFDHE8192,
        ]),
        ClientExtension::SessionTicket(ClientSessionTicket::Request),
        ClientExtension::ExtendedMasterSecretRequest,
        ClientExtension::SignatureAlgorithms(vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]),
    ];

    match server_name {
        ServerName::DnsName(dns_name) => {
            extensions.push(ClientExtension::make_sni(dns_name.borrow()));
        }
        ServerName::IpAddress(_) => {}
        _ => panic!("unknown ServerName variant encountered"),
    };

    let client_hello_payload = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::new().unwrap(),
        session_id: SessionId::random().unwrap(),
        cipher_suites: DEFAULT_CIPHER_SUITES.iter().map(|s| s.suite()).collect(),
        compression_methods: vec![Compression::Null],
        extensions,
    };

    let handshake_message_payload = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(client_hello_payload),
    };

    let message_payload = MessagePayload::handshake(handshake_message_payload);
    let mut message_payload_bytes = vec![];
    message_payload.encode(&mut message_payload_bytes);

    let message = OpaqueMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_0,
        payload: Payload::new(message_payload_bytes),
    };

    message.encode()
}

fn retrieve_server_hello<S: Read + Write>(mut stream: S, client_hello: &[u8]) -> OpaqueMessage {
    stream.write_all(client_hello).unwrap();

    let mut buffer = vec![];
    loop {
        let len = buffer.len();
        buffer.resize(len + 1024, 0);
        let n = stream.read(&mut buffer[len..]).unwrap();
        buffer.resize(len + n, 0);
        if n == 0 {
            panic!("EOF before ServerHello done");
        }
        eprintln!("Received {} (+{n}) bytes", buffer.len());

        let mut reader = Reader::init(&buffer);
        match OpaqueMessage::read(&mut reader) {
            Ok(opaque_message) => return opaque_message,
            Err(MessageError::TooShortForHeader) => {}
            Err(MessageError::TooShortForLength) => {}
            Err(e) => {
                Err::<(), _>(e).unwrap();
            }
        }
    }
}

fn parse_server_hello(opaque_message: &OpaqueMessage) -> ServerHelloPayload {
    match opaque_message.typ {
        ContentType::Handshake => {}
        ContentType::Alert => {
            let payload = AlertMessagePayload::read_bytes(&opaque_message.payload.0).unwrap();
            panic!("Expected handshake message, got alert: {:?}", payload);
        }
        _ => panic!("Expected handshake message, got: {:?}", opaque_message),
    }

    assert_eq!(
        opaque_message.typ,
        ContentType::Handshake,
        "{:?}",
        opaque_message
    );
    let mut reader = Reader::init(&opaque_message.payload.0);
    let handshake_message_payload =
        HandshakeMessagePayload::read_version(&mut reader, opaque_message.version).unwrap();
    let HandshakePayload::ServerHello(server_hello_payload) = handshake_message_payload.payload
    else {
        panic!("Expected ServerHello, got: {:?}", handshake_message_payload);
    };
    server_hello_payload
}
