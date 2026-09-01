use std::env;
use std::fmt::{self, Formatter};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;

use clap::Parser;
use oab_cli::args::Cli;
use oab_domain::{SnapshotEnvelopeV1, SurfaceSnapshotEnvelope};
use oab_ipc::codec::{JsonLineDecoder, encode_json_line};
use oab_ipc::permissions::effective_uid;
use oab_ipc::protocol::{
    BackendStreamId, Capability, CapabilitySet, ClientMessage, MIN_SUPPORTED_PROTOCOL_MAJOR,
    PROTOCOL_V1_MAJOR, ProtocolVersion, RequestId, Sequence, ServerMessage,
};
use oab_ipc::socket::verify_peer_uid;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Number, Value};

mod codex_accounts;
mod credentials;
mod daemon;
mod hyprland_events;
mod provider_bootstrap;
mod provider_config;
pub mod provider_refresh;
mod server;
mod single_instance;
mod wiring;

const IO_CHUNK_BYTES: usize = 8 * 1024;
const BRIDGE_FAILURE_MESSAGE: &str = "omarchy-ai-bar: UI bridge failed";

fn main() -> ExitCode {
    wiring::run(Cli::parse()).into()
}

#[derive(Debug)]
enum BridgeError {
    InvalidRuntimeDirectory,
    Connect,
    Authenticate,
    CloneStream,
    SpawnInputForwarder,
    Input,
    Output,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum OwnedServerFrame {
    Hello {
        protocol: ProtocolVersion,
        stream_id: BackendStreamId,
        capabilities: CapabilitySet,
    },
    Snapshot {
        sequence: Sequence,
        snapshot: StrictJsonValue,
    },
    ActionProgress {
        request_id: RequestId,
        state: OwnedActionProgressState,
    },
    CompatibilityError {
        code: OwnedCompatibilityErrorCode,
        supported: ProtocolVersion,
    },
    Pong {
        request_id: RequestId,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnedActionProgressState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnedCompatibilityErrorCode {
    UnsupportedProtocolMajor,
    HelloRequired,
    ProtocolViolation,
}

enum ServerFrameState {
    AwaitingHello,
    Ready(CapabilitySet),
    Terminal,
}

struct ServerFrameGuard {
    state: ServerFrameState,
}

struct StrictJsonValue(Value);

impl Serialize for StrictJsonValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonValueVisitor)
    }
}

struct StrictJsonValueVisitor;

impl<'de> Visitor<'de> for StrictJsonValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| de::Error::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.into())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = serde_json::Map::new();
        while let Some(name) = object.next_key::<String>()? {
            if fields.contains_key(&name) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let StrictJsonValue(value) = object.next_value()?;
            fields.insert(name, value);
        }
        Ok(StrictJsonValue(Value::Object(fields)))
    }
}

impl ServerFrameGuard {
    const fn new() -> Self {
        Self {
            state: ServerFrameState::AwaitingHello,
        }
    }

    fn accept(&mut self, frame: &OwnedServerFrame) -> Result<(), BridgeError> {
        match (&self.state, frame) {
            (
                ServerFrameState::AwaitingHello,
                OwnedServerFrame::Hello {
                    protocol,
                    capabilities,
                    ..
                },
            ) if (MIN_SUPPORTED_PROTOCOL_MAJOR..=PROTOCOL_V1_MAJOR).contains(&protocol.major()) => {
                self.state = ServerFrameState::Ready(capabilities.clone());
                Ok(())
            }
            (
                ServerFrameState::AwaitingHello | ServerFrameState::Ready(_),
                OwnedServerFrame::CompatibilityError { .. },
            ) => {
                self.state = ServerFrameState::Terminal;
                Ok(())
            }
            (ServerFrameState::Ready(capabilities), OwnedServerFrame::Snapshot { .. })
                if capabilities.contains(Capability::DisplaySnapshots) =>
            {
                Ok(())
            }
            (ServerFrameState::Ready(capabilities), OwnedServerFrame::ActionProgress { .. })
                if capabilities.contains(Capability::ActionProgress) =>
            {
                Ok(())
            }
            (ServerFrameState::Ready(_), OwnedServerFrame::Pong { .. }) => Ok(()),
            _ => Err(BridgeError::Output),
        }
    }
}

fn run_stdio_bridge(socket_override: Option<PathBuf>) -> Result<(), BridgeError> {
    let socket_path = display_socket_path(socket_override)?;
    let stream = UnixStream::connect(socket_path).map_err(|_source| BridgeError::Connect)?;
    verify_peer_uid(&stream, effective_uid()).map_err(|_source| BridgeError::Authenticate)?;

    let mut input_stream = stream
        .try_clone()
        .map_err(|_source| BridgeError::CloneStream)?;
    let (input_result_sender, input_result_receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("oab-ui-stdin".into())
        .spawn(move || {
            let result = forward_child_input(&mut input_stream);
            let _ = input_result_sender.send(result);
            // EOF means the stdio owner has gone away. A full shutdown makes
            // clean EOF and poisoned input terminate without waiting for the
            // backend to independently close its half of the stream.
            let _ = input_stream.shutdown(Shutdown::Both);
        })
        .map_err(|_source| BridgeError::SpawnInputForwarder)?;

    let output_result = forward_server_output(stream);
    match input_result_receiver.try_recv() {
        Ok(Err(error)) => Err(error),
        Ok(Ok(())) | Err(mpsc::TryRecvError::Empty) => output_result,
        Err(mpsc::TryRecvError::Disconnected) => Err(BridgeError::Input),
    }
}

fn display_socket_path(socket_override: Option<PathBuf>) -> Result<PathBuf, BridgeError> {
    if let Some(path) = socket_override {
        return path
            .is_absolute()
            .then_some(path)
            .ok_or(BridgeError::InvalidRuntimeDirectory);
    }

    let runtime_directory = env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(BridgeError::InvalidRuntimeDirectory)?;
    Ok(runtime_directory
        .join("omarchy-ai-bar")
        .join("display.sock"))
}

fn forward_child_input(stream: &mut UnixStream) -> Result<(), BridgeError> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut decoder = JsonLineDecoder::<ClientMessage>::new();
    let mut chunk = [0_u8; IO_CHUNK_BYTES];

    loop {
        let bytes_read =
            read_retry_interrupted(&mut input, &mut chunk).map_err(|_| BridgeError::Input)?;
        if bytes_read == 0 {
            decoder.finish().map_err(|_| BridgeError::Input)?;
            return Ok(());
        }

        let messages = decoder
            .feed(&chunk[..bytes_read])
            .map_err(|_| BridgeError::Input)?;
        for message in messages {
            let encoded = encode_json_line(&message).map_err(|_| BridgeError::Input)?;
            stream.write_all(&encoded).map_err(|_| BridgeError::Input)?;
        }
    }
}

fn forward_server_output(mut stream: UnixStream) -> Result<(), BridgeError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut decoder = JsonLineDecoder::<OwnedServerFrame>::new();
    let mut guard = ServerFrameGuard::new();
    let mut chunk = [0_u8; IO_CHUNK_BYTES];

    loop {
        let bytes_read =
            read_retry_interrupted(&mut stream, &mut chunk).map_err(|_| BridgeError::Output)?;
        if bytes_read == 0 {
            decoder.finish().map_err(|_| BridgeError::Output)?;
            output.flush().map_err(|_| BridgeError::Output)?;
            return Ok(());
        }

        let messages = decoder
            .feed(&chunk[..bytes_read])
            .map_err(|_| BridgeError::Output)?;
        for message in messages {
            guard.accept(&message)?;
            validate_server_frame(&message)?;
            let encoded = encode_json_line(&message).map_err(|_| BridgeError::Output)?;
            output
                .write_all(&encoded)
                .map_err(|_| BridgeError::Output)?;
            output.flush().map_err(|_| BridgeError::Output)?;
        }
    }
}

fn validate_server_frame(frame: &OwnedServerFrame) -> Result<(), BridgeError> {
    if let OwnedServerFrame::Snapshot { sequence, snapshot } = frame {
        validate_snapshot(*sequence, snapshot)?;
    }
    Ok(())
}

fn validate_snapshot(sequence: Sequence, snapshot: &StrictJsonValue) -> Result<(), BridgeError> {
    let original = snapshot.0.clone();
    let mut converted = snapshot.0.clone();
    let root = converted.as_object_mut().ok_or(BridgeError::Output)?;
    let redacted = match root.remove("privacy") {
        None => false,
        Some(Value::String(value)) if value == "redacted" => true,
        Some(_) => return Err(BridgeError::Output),
    };

    convert_snapshot_u64_fields(&mut converted)?;
    let envelope: SnapshotEnvelopeV1 =
        serde_json::from_value(converted).map_err(|_| BridgeError::Output)?;
    let surface = SurfaceSnapshotEnvelope::Trusted(envelope.private_view());
    let canonical_frame = serde_json::to_value(ServerMessage::Snapshot {
        sequence,
        snapshot: surface,
    })
    .map_err(|_| BridgeError::Output)?;
    let mut canonical = canonical_frame
        .as_object()
        .and_then(|frame| frame.get("snapshot"))
        .cloned()
        .ok_or(BridgeError::Output)?;
    if redacted {
        canonical
            .as_object_mut()
            .ok_or(BridgeError::Output)?
            .insert("privacy".into(), Value::String("redacted".into()));
    }

    if canonical == original {
        Ok(())
    } else {
        Err(BridgeError::Output)
    }
}

fn convert_snapshot_u64_fields(value: &mut Value) -> Result<(), BridgeError> {
    match value {
        Value::Array(values) => {
            for value in values {
                convert_snapshot_u64_fields(value)?;
            }
        }
        Value::Object(fields) => {
            for (name, value) in fields {
                if is_snapshot_u64_field(name) {
                    if value.is_null() {
                        continue;
                    }
                    let Value::String(text) = value else {
                        return Err(BridgeError::Output);
                    };
                    let parsed = parse_canonical_u64(text).ok_or(BridgeError::Output)?;
                    *value = Value::Number(Number::from(parsed));
                } else {
                    convert_snapshot_u64_fields(value)?;
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn is_snapshot_u64_field(name: &str) -> bool {
    matches!(
        name,
        "duration_seconds"
            | "retry_after"
            | "input_tokens"
            | "output_tokens"
            | "cache_read_tokens"
            | "cache_creation_tokens"
            | "reasoning_tokens"
            | "priced"
            | "unpriced"
            | "unmetered"
            | "estimated"
            | "total_tokens"
            | "request_count"
            | "standard_tokens"
            | "priority_tokens"
    )
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn read_retry_interrupted(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}
