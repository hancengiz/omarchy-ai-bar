//! Bounded loopback-only HTTP projection of the private daemon state.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use oab_cli::args::ServeArgs;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::timeout;

use crate::single_instance::{ControlAction, ControlStatus, ForwardOutcome, forward};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Local-server lifecycle failure with no request or credential contents.
#[derive(Debug, Error)]
pub(crate) enum ServerError {
    #[error("could not initialize the local server runtime")]
    Runtime(#[source] io::Error),
    #[error("could not listen on the requested loopback address")]
    Listen(#[source] io::Error),
    #[error("could not install the local server shutdown handler")]
    Signal(#[source] io::Error),
}

pub(crate) fn run(arguments: &ServeArgs, daemon_socket: PathBuf) -> Result<(), ServerError> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ServerError::Runtime)?;
    runtime.block_on(run_loop(arguments, daemon_socket))
}

async fn run_loop(arguments: &ServeArgs, daemon_socket: PathBuf) -> Result<(), ServerError> {
    let listener = TcpListener::bind(arguments.listen)
        .await
        .map_err(ServerError::Listen)?;
    let address = listener.local_addr().map_err(ServerError::Listen)?;
    println!("Omarchy AI Bar API listening on http://{address}");

    let mut terminate = signal(SignalKind::terminate()).map_err(ServerError::Signal)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(ServerError::Signal)?;
    let mut served = 0_u64;
    loop {
        tokio::select! {
            _ = terminate.recv() => return Ok(()),
            _ = interrupt.recv() => return Ok(()),
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    continue;
                };
                if peer.ip().is_loopback() {
                    let _result = serve_connection(stream, &daemon_socket).await;
                }
                served = served.saturating_add(1);
                if arguments.max_requests > 0 && served >= arguments.max_requests {
                    return Ok(());
                }
            }
        }
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    daemon_socket: &std::path::Path,
) -> io::Result<()> {
    let request = match timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(_error)) => {
            return write_response(
                &mut stream,
                400,
                "Bad Request",
                &json!({"error":"bad_request"}),
            )
            .await;
        }
        Err(_) => {
            return write_response(
                &mut stream,
                408,
                "Request Timeout",
                &json!({"error":"request_timeout"}),
            )
            .await;
        }
    };
    let response = route(&request, daemon_socket);
    write_response(
        &mut stream,
        response.status,
        response.reason,
        &response.body,
    )
    .await
}

async fn read_request(stream: &mut TcpStream) -> io::Result<HttpRequest> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request ended",
            ));
        }
        if bytes.len().saturating_add(read) > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request encoding"))?;
    let line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request line"))?;
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || method.is_empty()
        || path.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request line"));
    }
    Ok(HttpRequest {
        method: method.to_owned(),
        path: path.to_owned(),
    })
}

struct HttpRequest {
    method: String,
    path: String,
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    body: Value,
}

fn route(request: &HttpRequest, daemon_socket: &std::path::Path) -> HttpResponse {
    if request.method != "GET" {
        return response(
            405,
            "Method Not Allowed",
            json!({"error":"method_not_allowed"}),
        );
    }
    let action = match request.path.as_str() {
        "/health" | "/v1/diagnose" => ControlAction::Diagnose,
        "/v1/usage" => ControlAction::Usage,
        "/v1/cards" => ControlAction::Cards,
        "/v1/cost" => ControlAction::Cost,
        "/v1/sessions" => ControlAction::Sessions,
        _ => return response(404, "Not Found", json!({"error":"not_found"})),
    };
    match forward(daemon_socket, action) {
        Ok(ForwardOutcome::Response(reply)) if reply.status() == ControlStatus::Accepted => {
            let mut payload = reply.payload().cloned().unwrap_or(Value::Null);
            if action == ControlAction::Cards {
                payload = cards_payload(&payload);
            }
            if request.path == "/health" {
                payload = json!({"status":"ok","daemon":"running"});
            }
            response(200, "OK", payload)
        }
        Ok(ForwardOutcome::Response(_) | ForwardOutcome::NoDaemon) => response(
            503,
            "Service Unavailable",
            json!({"error":"daemon_unavailable"}),
        ),
        Err(_error) => response(
            502,
            "Bad Gateway",
            json!({"error":"daemon_exchange_failed"}),
        ),
    }
}

fn cards_payload(payload: &Value) -> Value {
    Value::Array(
        payload
            .get("snapshots")
            .and_then(Value::as_array)
            .map(|snapshots| {
                snapshots
                    .iter()
                    .map(|snapshot| {
                        let sample = snapshot.get("last_known_good");
                        json!({
                            "provider": sample.and_then(|value| value.pointer("/scope/provider"))
                                .or_else(|| snapshot.pointer("/scope/provider"))
                                .and_then(Value::as_str)
                                .unwrap_or("unknown"),
                            "state": snapshot.get("state").and_then(Value::as_str).unwrap_or("unknown"),
                            "used_percent": sample.and_then(|value| value.pointer("/primary/usage/used_percent")).and_then(Value::as_f64),
                            "reset_description": sample.and_then(|value| value.pointer("/primary/reset_description")).and_then(Value::as_str),
                            "error_kind": snapshot.pointer("/error/kind").and_then(Value::as_str),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    )
}

const fn response(status: u16, reason: &'static str, body: Value) -> HttpResponse {
    HttpResponse {
        status,
        reason,
        body,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &Value,
) -> io::Result<()> {
    let body = serde_json::to_vec(body).map_err(io::Error::other)?;
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_non_get_routes_fail_without_daemon_access() {
        let socket = std::path::Path::new("/unreachable");
        let missing = route(
            &HttpRequest {
                method: "GET".into(),
                path: "/unknown".into(),
            },
            socket,
        );
        assert_eq!(missing.status, 404);
        let method = route(
            &HttpRequest {
                method: "POST".into(),
                path: "/v1/usage".into(),
            },
            socket,
        );
        assert_eq!(method.status, 405);
    }
}
