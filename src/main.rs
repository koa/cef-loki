use crate::{config::CONFIG, error::Error};
use base64::{Engine, prelude::BASE64_STANDARD};
use env_logger::Env;
use log::{Level, error, info};
use prost::Message;
use tracing_loki_fmt::proto::logproto::{
    EntryAdapter, LabelPairAdapter, PushRequest, StreamAdapter,
};

use reqwest::{
    Client,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue},
};
use std::{
    borrow::Cow,
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::from_utf8,
    time::{Duration, SystemTime},
};
use tokio::{
    net::UdpSocket,
    pin,
    signal::unix::{SignalKind, signal},
    spawn,
    sync::mpsc,
};
use tokio_stream::{
    StreamExt,
    wrappers::{ReceiverStream, SignalStream},
};

mod config;
mod error;

const DEFAULT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1514);
enum Event {
    Interrupt,
    Message(Box<[LogMessage]>),
}
#[derive(Debug)]
struct LogMessage {
    timestamp: SystemTime,
    source: IpAddr,
    hostname: Option<Box<str>>,
    device_vendor: Box<str>,
    device_product: Box<str>,
    device_version: Box<str>,
    device_event_class_id: Box<str>,
    name: Box<str>,
    severity: Box<str>,
    fields: Box<[(Box<str>, Box<str>)]>,
}
const CEF_MARKER: &[u8] = b"CEF:0";

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(Env::default().filter_or("LOG_LEVEL", "info"));
    let bind_addr = CONFIG.bind.as_ref().unwrap_or(&DEFAULT_ADDR);
    let socket = UdpSocket::bind(&bind_addr)
        .await
        .map_err(Error::CannotBindSocket)?;
    let (sender, receiver) = mpsc::channel::<LogMessage>(1000);
    spawn(async move {
        let mut buf = [0u8; 1024 * 8];
        loop {
            #[allow(clippy::collapsible_if)]
            if let Some(data) = match socket.recv_from(&mut buf).await {
                Ok((byte_count, address)) => {
                    let timestamp = SystemTime::now();
                    let source = address.ip();
                    let data = &buf[..byte_count];
                    let option = data
                        .windows(CEF_MARKER.len())
                        .enumerate()
                        .find_map(|(i, window)| if window == CEF_MARKER { Some(i) } else { None });
                    if let Some(start_idx) = option {
                        let end_of_prefix = if start_idx > 0 && data[start_idx - 1] == b' ' {
                            start_idx - 1
                        } else {
                            start_idx
                        };
                        let prefix = &data[..end_of_prefix];
                        let hostname = prefix
                            .iter()
                            .enumerate()
                            .rev()
                            .find_map(|(i, byte)| if *byte == b' ' { Some(i) } else { None })
                            .map(|i| &prefix[i + 1..])
                            .map(|s| str::from_utf8(s))
                            .and_then(Result::ok)
                            .map(|s| s.to_string().into_boxed_str());

                        match split_fields(&data[start_idx..], hostname, source, timestamp) {
                            Ok(msg) => Some(msg),
                            Err(e) => {
                                error!("Cannot parse message: {e}");
                                None
                            }
                        }
                    } else {
                        None
                    }
                }
                Err(e) => {
                    error!("Cannot receive packet: {e}");
                    None
                }
            } {
                if let Err(error) = sender.send(data).await {
                    error!("Cannot process received packet: {error}");
                    return;
                }
            }
        }
    });
    let stream = StreamExt::merge(
        ReceiverStream::new(receiver)
            .chunks_timeout(1000, Duration::from_secs(1))
            .map(|chunk| chunk.into_boxed_slice())
            .map(Event::Message),
        SignalStream::new(signal(SignalKind::interrupt()).map_err(Error::CannotListenSignals)?)
            .map(|_| Event::Interrupt),
    );

    let mut headers = HeaderMap::<HeaderValue>::default();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-snappy"),
    );
    if let Some(credentials) = &CONFIG.credentials {
        headers.insert(
            AUTHORIZATION,
            format!(
                "Basic {}",
                BASE64_STANDARD
                    .encode(format!("{}:{}", credentials.username, credentials.password))
            )
            .try_into()
            .expect("Cannot encode credentials"),
        );
    }
    if let Some(org_id) = &CONFIG.org_id {
        headers.insert(
            "X-Scope-OrgID",
            org_id.try_into().expect("Cannot encode org_id"),
        );
    }
    let client = Client::builder()
        .default_headers(headers)
        .build()
        .expect("Cannot create client");

    pin!(stream);
    while let Some(event) = stream.next().await {
        match event {
            Event::Interrupt => break,
            Event::Message(messages) => {
                let mut messages_by_labels = HashMap::new();
                for message in messages {
                    //info!("Received message: {:?}", message);

                    let mut level = Level::Info;
                    let mut labels = HashMap::<Cow<str>, Cow<str>>::new();
                    let mut entry = None;

                    //let mut logrecord = logger.create_log_record();
                    //logrecord.set_timestamp(message.timestamp);
                    //logrecord.set_observed_timestamp(message.timestamp);
                    match message.severity.as_ref() {
                        "Low" | "0" | "1" | "2" | "3" => {
                            level = Level::Debug;
                        }
                        "Medium" | "4" | "5" | "6" => {
                            level = Level::Info;
                        }
                        "High" | "7" | "8" => {
                            level = Level::Warn;
                        }
                        "Very-High" | "9" | "10" => {
                            level = Level::Error;
                        }
                        _ => {}
                    };
                    labels.insert("severity".into(), message.severity.into_string().into());
                    labels.insert(
                        "device_vendor".into(),
                        message.device_vendor.into_string().into(),
                    );
                    labels.insert(
                        "device_product".into(),
                        message.device_product.into_string().into(),
                    );
                    labels.insert(
                        "device_version".into(),
                        message.device_version.into_string().into(),
                    );
                    labels.insert(
                        "device_event_class_id".into(),
                        message.device_event_class_id.into_string().into(),
                    );
                    labels.insert("source_ip".into(), message.source.to_string().into());
                    if let Some(hostname) = message.hostname {
                        labels.insert("hostname".into(), hostname.into_string().into());
                    }

                    let mut name_components = message.name.split(',');
                    if let Some(mut current_component) = name_components.next() {
                        if current_component.len() < message.name.len() {
                            let mut has_packet = false;
                            let mut has_raw_packet = false;
                            let mut is_system = false;
                            loop {
                                match current_component {
                                    "debug" => level = Level::Debug,
                                    "info" => level = Level::Info,
                                    "warn" => level = Level::Warn,
                                    "error" => level = Level::Error,
                                    "critical" => level = Level::Error,
                                    "packet" => has_packet = true,
                                    "raw" => has_raw_packet = true,
                                    "system" => is_system = true,
                                    facility => {
                                        labels.insert("facility".into(), facility.into());
                                    }
                                }
                                if let Some(next_component) = name_components.next() {
                                    current_component = next_component;
                                    continue;
                                } else {
                                    break;
                                }
                            }
                            labels.insert("has_packet".into(), bool2label(has_packet));
                            labels.insert("has_raw_packet".into(), bool2label(has_raw_packet));
                            labels.insert("is_system".into(), bool2label(is_system));
                        }
                        labels.insert("name".into(), current_component.into());
                    }

                    labels.insert("name".into(), message.name.to_string().into());
                    let mut structured_metadata = Vec::with_capacity(message.fields.len());

                    for (key, value) in message.fields {
                        if key.as_ref() == "msg" {
                            entry = Some(value);
                        } else {
                            structured_metadata.push(LabelPairAdapter {
                                name: key.into_string(),
                                value: value.into_string(),
                            });
                        }
                    }
                    if entry.is_some() || !structured_metadata.is_empty() {
                        messages_by_labels
                            .entry(format_labels(labels, level))
                            .or_insert(Vec::new())
                            .push(EntryAdapter {
                                timestamp: Some(message.timestamp.into()),
                                line: entry.unwrap_or_default().into_string(),
                                structured_metadata,
                                parsed: vec![],
                            });
                    }
                }
                let streams = messages_by_labels
                    .into_iter()
                    .map(|(labels, entries)| StreamAdapter {
                        labels,
                        entries,
                        hash: 0,
                    })
                    .collect();

                let request = PushRequest { streams };
                let request_data =
                    match snap::raw::Encoder::new().compress_vec(&request.encode_to_vec()) {
                        Ok(data) => data,
                        Err(error) => {
                            error!("Cannot compress request: {error}");
                            continue;
                        }
                    };
                let result = match client
                    .post(&CONFIG.loki_url)
                    .body(request_data)
                    .send()
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        error!("Cannot send request: {e}");
                        continue;
                    }
                };
                let code = result.status();
                if !code.is_success() {
                    error!("Error from loki: {code}");
                }
            }
        }
    }
    Ok(())
}

fn bool2label(value: bool) -> Cow<'static, str> {
    if value { "true".into() } else { "false".into() }
}

fn split_fields(
    log_message: &[u8],
    hostname: Option<Box<str>>,
    source: IpAddr,
    timestamp: SystemTime,
) -> Result<LogMessage, Error> {
    let log_message = match from_utf8(log_message) {
        Ok(msg) => msg,
        Err(e) => {
            return Err(Error::CannotDecodeUtfString(e));
        }
    };
    let mut current_field_value = String::new();
    let mut last_was_escape = false;
    let mut found_header_fields = [const { None }; 6];
    let mut next_field_idx = 0;
    let mut chars = log_message.chars();
    while next_field_idx <= found_header_fields.len()
        && let Some(char) = chars.next()
    {
        if last_was_escape {
            last_was_escape = false;
            match char {
                'n' | 'r' => {
                    if !current_field_value.ends_with('\n') {
                        current_field_value.push('\n')
                    }
                }
                other => current_field_value.push(other),
            }
        } else {
            match char {
                '\\' => last_was_escape = true,
                '|' => {
                    if next_field_idx > 0 {
                        found_header_fields[next_field_idx - 1] =
                            Some(current_field_value.into_boxed_str());
                    }
                    next_field_idx += 1;
                    current_field_value = String::new();
                }
                other => current_field_value.push(other),
            }
        }
    }
    if !current_field_value.is_empty() && next_field_idx <= found_header_fields.len() {
        found_header_fields[next_field_idx - 1] = Some(current_field_value.into_boxed_str());
    }
    let mut current_chunk = String::new();
    let mut last_chunk: Option<String> = None;
    let mut current_key_name = Option::<Box<str>>::default();
    let mut values: Vec<(Box<str>, Box<str>)> = Vec::new();

    for char in chars {
        if last_was_escape {
            match char {
                'n' | 'r' => {
                    if !current_chunk.ends_with('\n') {
                        current_chunk.push('\n')
                    }
                }
                other => current_chunk.push(other),
            }
        } else {
            match char {
                '\\' => last_was_escape = true,
                ' ' => {
                    if let Some(chunk) = last_chunk.as_mut() {
                        chunk.push(' ');
                        chunk.push_str(&current_chunk);
                    } else {
                        last_chunk = Some(current_chunk);
                    }
                    current_chunk = String::new();
                }
                '=' => {
                    if let Some(key_name) = current_key_name
                        && let Some(value) = last_chunk
                    {
                        values.push((key_name, value.into_boxed_str()));
                    }
                    last_chunk = None;
                    current_key_name = Some(current_chunk.into_boxed_str());
                    current_chunk = String::new();
                }
                other => current_chunk.push(other),
            }
        }
    }
    if let Some(key_name) = current_key_name
        && let Some(value) = last_chunk
    {
        values.push((key_name, value.into_boxed_str()));
    }
    if let [
        Some(device_vendor),
        Some(device_product),
        Some(device_version),
        Some(device_event_class_id),
        Some(name),
        Some(severity),
    ] = found_header_fields
    {
        Ok(LogMessage {
            timestamp,
            source,
            hostname,
            device_vendor,
            device_product,
            device_version,
            device_event_class_id,
            name,
            severity,
            fields: values.into_boxed_slice(),
        })
    } else {
        Err(Error::InvalidHeaderField(
            log_message.to_string().into_boxed_str(),
        ))
    }
}
fn format_labels(mut labels: HashMap<Cow<str>, Cow<str>>, level: Level) -> String {
    let level = match level {
        Level::Trace => "trace",
        Level::Debug => "debug",
        Level::Info => "info",
        Level::Warn => "warn",
        Level::Error => "error",
    };

    labels.insert("level".into(), level.into());

    let labels = labels
        .into_iter()
        .map(|(k, v)| format!("{}={:?}", k, v))
        .collect::<Vec<_>>()
        .join(",");

    format!("{{{labels}}}")
}
