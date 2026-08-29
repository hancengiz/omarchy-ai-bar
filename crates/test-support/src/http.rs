//! Bounded loopback HTTP fixture server for provider transport tests.

use std::collections::VecDeque;
use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// One deterministic response emitted for one accepted request.
#[derive(Clone)]
pub struct FakeHttpResponse {
    behavior: ResponseBehavior,
}

#[derive(Clone)]
enum ResponseBehavior {
    Complete {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        declared_length: Option<usize>,
    },
    Stall,
}

impl FakeHttpResponse {
    /// Creates a complete response whose declared length matches `body`.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            behavior: ResponseBehavior::Complete {
                status,
                headers: Vec::new(),
                body,
                declared_length: None,
            },
        }
    }

    /// Adds one response header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        if let ResponseBehavior::Complete { headers, .. } = &mut self.behavior {
            headers.push((name.into(), value.into()));
        }
        self
    }

    /// Creates a response that declares more bytes than it sends.
    #[must_use]
    pub fn truncated(status: u16, declared_length: usize, body: Vec<u8>) -> Self {
        Self {
            behavior: ResponseBehavior::Complete {
                status,
                headers: Vec::new(),
                body,
                declared_length: Some(declared_length),
            },
        }
    }

    /// Accepts a request and holds the connection without sending response bytes.
    #[must_use]
    pub fn stall() -> Self {
        Self {
            behavior: ResponseBehavior::Stall,
        }
    }
}

impl Debug for FakeHttpResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeHttpResponse")
            .field("behavior", &"<fixture response>")
            .finish()
    }
}

/// Parsed request metadata. Its debug view redacts all header values.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedHttpRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CapturedHttpRequest {
    /// Returns a captured header value using an ASCII-case-insensitive name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns the request target exactly as received.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the captured request method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the bounded captured request body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Debug for CapturedHttpRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedHttpRequest")
            .field("method", &self.method)
            .field("target", &"<redacted-target>")
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Loopback server with a shared FIFO response script and request capture.
pub struct FakeHttpServer {
    origin: String,
    state: Arc<Mutex<ServerState>>,
    requests_changed: Arc<Notify>,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

struct ServerState {
    responses: VecDeque<FakeHttpResponse>,
    requests: Vec<CapturedHttpRequest>,
}

impl FakeHttpServer {
    /// Binds an ephemeral IPv4 loopback port and starts serving `responses`.
    ///
    /// # Panics
    ///
    /// Panics only when the test host cannot bind or inspect a loopback socket.
    pub async fn start(responses: impl IntoIterator<Item = FakeHttpResponse>) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fake HTTP server binds loopback");
        let address = listener
            .local_addr()
            .expect("fake HTTP server has a local address");
        let state = Arc::new(Mutex::new(ServerState {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }));
        let cancellation = CancellationToken::new();
        let requests_changed = Arc::new(Notify::new());
        let task_state = Arc::clone(&state);
        let task_cancellation = cancellation.clone();
        let task_requests_changed = Arc::clone(&requests_changed);
        let task = tokio::spawn(async move {
            serve(
                listener,
                task_state,
                task_requests_changed,
                task_cancellation,
            )
            .await;
        });
        Self {
            origin: format!("http://{address}"),
            state,
            requests_changed,
            cancellation,
            task,
        }
    }

    /// Returns the exact approved origin for endpoint-policy construction.
    #[must_use]
    pub fn origin(&self) -> String {
        self.origin.clone()
    }

    /// Resolves a root-relative path against this server.
    ///
    /// # Panics
    ///
    /// Panics when `path` cannot be joined as a URL in a test fixture.
    #[must_use]
    pub fn url(&self, path: &str) -> url::Url {
        url::Url::parse(&self.origin)
            .expect("fake origin is a URL")
            .join(path)
            .expect("test path joins fake origin")
    }

    /// Returns captured requests in arrival order.
    #[must_use]
    pub fn requests(&self) -> Vec<CapturedHttpRequest> {
        self.lock_state().requests.clone()
    }

    /// Waits until at least `count` requests have been captured.
    pub async fn wait_for_request_count(&self, count: usize) {
        loop {
            let notified = self.requests_changed.notified();
            if self.lock_state().requests.len() >= count {
                return;
            }
            notified.await;
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, ServerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for FakeHttpServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.task.abort();
    }
}

async fn serve(
    listener: TcpListener,
    state: Arc<Mutex<ServerState>>,
    requests_changed: Arc<Notify>,
    cancellation: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            () = cancellation.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _peer)) = accepted else {
            break;
        };
        let connection_state = Arc::clone(&state);
        let connection_requests_changed = Arc::clone(&requests_changed);
        let connection_cancellation = cancellation.clone();
        tokio::spawn(async move {
            handle_connection(
                stream,
                connection_state,
                connection_requests_changed,
                connection_cancellation,
            )
            .await;
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<ServerState>>,
    requests_changed: Arc<Notify>,
    cancellation: CancellationToken,
) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    let response = {
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        state.requests.push(request);
        state
            .responses
            .pop_front()
            .unwrap_or_else(|| FakeHttpResponse::new(500, Vec::new()))
    };
    requests_changed.notify_waiters();

    match response.behavior {
        ResponseBehavior::Stall => {
            cancellation.cancelled().await;
        }
        ResponseBehavior::Complete {
            status,
            headers,
            body,
            declared_length,
        } => {
            let reason = reason_phrase(status);
            let length = declared_length.unwrap_or(body.len());
            let mut head = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {length}\r\n");
            for (name, value) in headers {
                head.push_str(&name);
                head.push_str(": ");
                head.push_str(&value);
                head.push_str("\r\n");
            }
            head.push_str("Connection: close\r\n\r\n");
            if stream.write_all(head.as_bytes()).await.is_ok() {
                let _ignored = stream.write_all(&body).await;
                let _ignored = stream.shutdown().await;
            }
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<CapturedHttpRequest> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while bytes.len() <= MAX_REQUEST_HEAD_BYTES {
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    if bytes.len() > MAX_REQUEST_HEAD_BYTES {
        return None;
    }
    let head_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let head = std::str::from_utf8(&bytes[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_ascii_whitespace();
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let _version = request_line.next()?;
    if request_line.next().is_some() {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map_or(Some(0), |(_, value)| value.parse::<usize>().ok())?;
    if content_length > MAX_REQUEST_BODY_BYTES {
        return None;
    }
    let mut body = bytes[head_end..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    } else if body.len() < content_length {
        let missing = content_length - body.len();
        let mut remaining = vec![0_u8; missing];
        stream.read_exact(&mut remaining).await.ok()?;
        body.extend_from_slice(&remaining);
    }
    Some(CapturedHttpRequest {
        method,
        target,
        headers,
        body,
    })
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Response",
    }
}
