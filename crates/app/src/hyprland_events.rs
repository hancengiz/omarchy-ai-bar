use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use nix::sys::resource::{Resource, setrlimit};
use nix::sys::{prctl, signal::Signal};
use nix::unistd::{close, getppid};
use oab_ipc::permissions::effective_uid;
use oab_ipc::socket::verify_peer_uid;

pub(crate) const FAILURE_MESSAGE: &str = "omarchy-ai-bar: Hyprland event witness failed";

const READ_CHUNK_BYTES: usize = 8 * 1024;
const MAX_EVENT_LINE_BYTES: usize = 64 * 1024;
const MAX_MONITOR_NAME_BYTES: usize = 4 * 1024;
const MONITOR_ADDED_PREFIX: &[u8] = b"monitoradded>>";
const MONITOR_REMOVED_PREFIX: &[u8] = b"monitorremoved>>";

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum EventWitnessError {
    InvalidSocketPath,
    InvalidMonitorName,
    ParentLifecycle,
    ProcessPrivacy,
    Authorization,
    Connect,
    Authenticate,
    Input,
    Output,
    LineTooLong,
    PartialLine,
    Poisoned,
}

pub(crate) fn run(
    socket_path: PathBuf,
    monitor_name_base64: &str,
    expected_parent_pid: u32,
    ready_fd: i32,
    authorization_fd: i32,
) -> Result<(), EventWitnessError> {
    arm_parent_death_signal(expected_parent_pid)?;
    disable_core_dumps()?;
    if !socket_path.is_absolute() {
        return Err(EventWitnessError::InvalidSocketPath);
    }

    let monitor_name = decode_monitor_name(monitor_name_base64)?;
    let stream = UnixStream::connect(socket_path).map_err(|_| EventWitnessError::Connect)?;
    verify_peer_uid(&stream, effective_uid()).map_err(|_| EventWitnessError::Authenticate)?;
    authorize_event_reads(ready_fd, authorization_fd)?;

    let stdout = io::stdout();
    let mut output = stdout.lock();
    forward_events(stream, &mut output, monitor_name)
}

fn arm_parent_death_signal(expected_parent_pid: u32) -> Result<(), EventWitnessError> {
    let expected_parent_pid = i32::try_from(expected_parent_pid)
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or(EventWitnessError::ParentLifecycle)?;
    let parent = getppid();
    if parent.as_raw() != expected_parent_pid {
        return Err(EventWitnessError::ParentLifecycle);
    }
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|_| EventWitnessError::ParentLifecycle)?;
    if getppid() != parent {
        return Err(EventWitnessError::ParentLifecycle);
    }
    Ok(())
}

fn disable_core_dumps() -> Result<(), EventWitnessError> {
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|_| EventWitnessError::ProcessPrivacy)
}

fn authorize_event_reads(ready_fd: i32, authorization_fd: i32) -> Result<(), EventWitnessError> {
    if ready_fd <= 2 || authorization_fd <= 2 || ready_fd == authorization_fd {
        return Err(EventWitnessError::Authorization);
    }

    let mut ready = open_inherited_pipe(ready_fd, false, true)?;
    let mut authorization = open_inherited_pipe(authorization_fd, true, false)?;
    let ready_metadata = ready
        .metadata()
        .map_err(|_| EventWitnessError::Authorization)?;
    let authorization_metadata = authorization
        .metadata()
        .map_err(|_| EventWitnessError::Authorization)?;
    if (ready_metadata.dev(), ready_metadata.ino())
        == (authorization_metadata.dev(), authorization_metadata.ino())
    {
        return Err(EventWitnessError::Authorization);
    }

    close(ready_fd).map_err(|_| EventWitnessError::Authorization)?;
    close(authorization_fd).map_err(|_| EventWitnessError::Authorization)?;
    ready
        .write_all(b"R")
        .and_then(|()| ready.flush())
        .map_err(|_| EventWitnessError::Authorization)?;
    let mut authorization_byte = [0_u8; 1];
    authorization
        .read_exact(&mut authorization_byte)
        .map_err(|_| EventWitnessError::Authorization)?;
    if authorization_byte != *b"A" {
        return Err(EventWitnessError::Authorization);
    }
    let mut trailing_authorization = [0_u8; 1];
    if authorization
        .read(&mut trailing_authorization)
        .map_err(|_| EventWitnessError::Authorization)?
        != 0
    {
        return Err(EventWitnessError::Authorization);
    }

    prctl::set_dumpable(false).map_err(|_| EventWitnessError::ProcessPrivacy)?;
    if prctl::get_dumpable().map_err(|_| EventWitnessError::ProcessPrivacy)? {
        return Err(EventWitnessError::ProcessPrivacy);
    }
    ready
        .write_all(b"D")
        .and_then(|()| ready.flush())
        .map_err(|_| EventWitnessError::Authorization)
}

fn open_inherited_pipe(
    descriptor: i32,
    read: bool,
    write: bool,
) -> Result<File, EventWitnessError> {
    let path = format!("/proc/self/fd/{descriptor}");
    let file = OpenOptions::new()
        .read(read)
        .write(write)
        .open(path)
        .map_err(|_| EventWitnessError::Authorization)?;
    let metadata = file
        .metadata()
        .map_err(|_| EventWitnessError::Authorization)?;
    if !metadata.file_type().is_fifo()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(EventWitnessError::Authorization);
    }
    Ok(file)
}

fn forward_events(
    mut stream: UnixStream,
    output: &mut impl Write,
    monitor_name: Vec<u8>,
) -> Result<(), EventWitnessError> {
    let mut decoder = EventLineDecoder::new(monitor_name);
    let mut chunk = [0_u8; READ_CHUNK_BYTES];

    loop {
        let bytes_read = read_retry_interrupted(&mut stream, &mut chunk)
            .map_err(|_| EventWitnessError::Input)?;
        if bytes_read == 0 {
            return decoder.finish();
        }

        let result = decoder.feed(&chunk[..bytes_read], output);
        chunk[..bytes_read].fill(0);
        result?;
    }
}

struct EventLineDecoder {
    monitor_added: Vec<u8>,
    monitor_removed: Vec<u8>,
    line: Vec<u8>,
    poisoned: bool,
}

impl EventLineDecoder {
    fn new(mut monitor_name: Vec<u8>) -> Self {
        let mut monitor_added = Vec::with_capacity(MONITOR_ADDED_PREFIX.len() + monitor_name.len());
        monitor_added.extend_from_slice(MONITOR_ADDED_PREFIX);
        monitor_added.extend_from_slice(&monitor_name);

        let mut monitor_removed =
            Vec::with_capacity(MONITOR_REMOVED_PREFIX.len() + monitor_name.len());
        monitor_removed.extend_from_slice(MONITOR_REMOVED_PREFIX);
        monitor_removed.extend_from_slice(&monitor_name);
        monitor_name.fill(0);

        Self {
            monitor_added,
            monitor_removed,
            line: Vec::with_capacity(READ_CHUNK_BYTES),
            poisoned: false,
        }
    }

    fn feed(&mut self, mut input: &[u8], output: &mut impl Write) -> Result<(), EventWitnessError> {
        if self.poisoned {
            return Err(EventWitnessError::Poisoned);
        }

        while !input.is_empty() {
            let newline = input.iter().position(|byte| *byte == b'\n');
            let segment = newline.map_or(input, |position| &input[..position]);
            let line_length = self
                .line
                .len()
                .checked_add(segment.len())
                .filter(|length| *length <= MAX_EVENT_LINE_BYTES);
            if line_length.is_none() {
                self.poison();
                return Err(EventWitnessError::LineTooLong);
            }
            self.line.extend_from_slice(segment);

            let Some(position) = newline else {
                return Ok(());
            };

            if let Err(error) = self.emit_line(output) {
                self.poison();
                return Err(error);
            }
            self.clear_line();
            input = &input[position + 1..];
        }

        Ok(())
    }

    fn finish(&mut self) -> Result<(), EventWitnessError> {
        if self.poisoned {
            return Err(EventWitnessError::Poisoned);
        }
        if self.line.is_empty() {
            Ok(())
        } else {
            self.poison();
            Err(EventWitnessError::PartialLine)
        }
    }

    fn emit_line(&self, output: &mut impl Write) -> Result<(), EventWitnessError> {
        let evidence = if self.line == self.monitor_added {
            Some(self.monitor_added.as_slice())
        } else if self.line == self.monitor_removed {
            Some(self.monitor_removed.as_slice())
        } else {
            None
        };

        if let Some(evidence) = evidence {
            output
                .write_all(evidence)
                .and_then(|()| output.write_all(b"\n"))
                .and_then(|()| output.flush())
                .map_err(|_| EventWitnessError::Output)?;
        }
        Ok(())
    }

    fn clear_line(&mut self) {
        self.line.fill(0);
        self.line.clear();
    }

    fn poison(&mut self) {
        self.clear_line();
        self.poisoned = true;
    }
}

impl Drop for EventLineDecoder {
    fn drop(&mut self) {
        self.monitor_added.fill(0);
        self.monitor_removed.fill(0);
        self.line.fill(0);
    }
}

fn decode_monitor_name(encoded: &str) -> Result<Vec<u8>, EventWitnessError> {
    let input = encoded.as_bytes();
    let maximum_encoded_length = MAX_MONITOR_NAME_BYTES.div_ceil(3) * 4;
    if input.is_empty() || input.len() > maximum_encoded_length || !input.len().is_multiple_of(4) {
        return Err(EventWitnessError::InvalidMonitorName);
    }

    let padding = match input {
        [.., b'=', b'='] => 2,
        [.., b'='] => 1,
        _ => 0,
    };
    let decoded_length = input.len() / 4 * 3 - padding;
    if decoded_length == 0 || decoded_length > MAX_MONITOR_NAME_BYTES {
        return Err(EventWitnessError::InvalidMonitorName);
    }

    let mut decoded = Vec::with_capacity(decoded_length);
    let (groups, remainder) = input.as_chunks::<4>();
    debug_assert!(remainder.is_empty());
    for (index, group) in groups.iter().enumerate() {
        let last_group = index + 1 == groups.len();
        let first = decode_base64_digit(group[0]).ok_or(EventWitnessError::InvalidMonitorName)?;
        let second = decode_base64_digit(group[1]).ok_or(EventWitnessError::InvalidMonitorName)?;

        match (group[2], group[3]) {
            (b'=', b'=') if last_group && second.trailing_zeros() >= 4 => {
                decoded.push(first << 2 | second >> 4);
            }
            (third, b'=') if last_group => {
                let third =
                    decode_base64_digit(third).ok_or(EventWitnessError::InvalidMonitorName)?;
                if third.trailing_zeros() < 2 {
                    decoded.fill(0);
                    return Err(EventWitnessError::InvalidMonitorName);
                }
                decoded.push(first << 2 | second >> 4);
                decoded.push(second << 4 | third >> 2);
            }
            (third, fourth) if third != b'=' && fourth != b'=' => {
                let third =
                    decode_base64_digit(third).ok_or(EventWitnessError::InvalidMonitorName)?;
                let fourth =
                    decode_base64_digit(fourth).ok_or(EventWitnessError::InvalidMonitorName)?;
                decoded.push(first << 2 | second >> 4);
                decoded.push(second << 4 | third >> 2);
                decoded.push(third << 6 | fourth);
            }
            _ => {
                decoded.fill(0);
                return Err(EventWitnessError::InvalidMonitorName);
            }
        }
    }

    if decoded.len() != decoded_length
        || decoded
            .iter()
            .any(|byte| matches!(*byte, b'\0' | b'\n' | b'\r'))
    {
        decoded.fill(0);
        return Err(EventWitnessError::InvalidMonitorName);
    }
    Ok(decoded)
}

const fn decode_base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn read_retry_interrupted(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &[u8] = "fallback\u{00a0}\u{1680}".as_bytes();

    #[test]
    fn canonical_base64_decodes_monitor_name() {
        assert_eq!(
            decode_monitor_name("ZmFsbGJhY2vCoOGagA=="),
            Ok(TARGET.to_vec())
        );
        assert_eq!(decode_monitor_name("Zg=="), Ok(b"f".to_vec()));
        assert_eq!(decode_monitor_name("Zm8="), Ok(b"fo".to_vec()));
        assert_eq!(decode_monitor_name("Zm9v"), Ok(b"foo".to_vec()));
    }

    #[test]
    fn malformed_or_noncanonical_base64_is_rejected() {
        for encoded in [
            "", "Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "=m9v", "Zm=v", "Zm9v====", "Zm 9v",
            "Zm9v\n", "!!!!",
        ] {
            assert_eq!(
                decode_monitor_name(encoded),
                Err(EventWitnessError::InvalidMonitorName),
                "unexpectedly accepted {encoded:?}"
            );
        }
    }

    #[test]
    fn event_delimiters_cannot_be_injected_through_monitor_name() {
        for encoded in ["AA==", "Cg==", "DQ=="] {
            assert_eq!(
                decode_monitor_name(encoded),
                Err(EventWitnessError::InvalidMonitorName)
            );
        }
    }

    #[test]
    fn only_exact_monitor_events_are_emitted() {
        let mut decoder = EventLineDecoder::new(TARGET.to_vec());
        let mut evidence = Vec::new();
        let mut events = Vec::new();
        events.extend_from_slice(b"monitoradded>>fallback\n");
        events.extend_from_slice(b"monitoraddedv2>>7,");
        events.extend_from_slice(TARGET);
        events.extend_from_slice(b",description\n");
        events.extend_from_slice(b"monitoradded>>");
        events.extend_from_slice(TARGET);
        events.extend_from_slice(b"-suffix\n");
        events.extend_from_slice(b"monitoradded>>");
        events.extend_from_slice(TARGET);
        events.extend_from_slice(b"\n");
        events.extend_from_slice(b"monitorremoved>>");
        events.extend_from_slice(TARGET);
        events.extend_from_slice(b"\n");

        decoder.feed(&events, &mut evidence).expect("decode events");
        decoder.finish().expect("finish complete stream");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"monitoradded>>");
        expected.extend_from_slice(TARGET);
        expected.extend_from_slice(b"\nmonitorremoved>>");
        expected.extend_from_slice(TARGET);
        expected.push(b'\n');
        assert_eq!(evidence, expected);
    }

    #[test]
    fn fragmented_exact_event_is_emitted_once() {
        let mut decoder = EventLineDecoder::new(TARGET.to_vec());
        let mut evidence = Vec::new();

        for fragment in [
            b"monitor".as_slice(),
            b"added>>fall".as_slice(),
            &TARGET[4..10],
            &TARGET[10..],
            b"\n".as_slice(),
        ] {
            decoder
                .feed(fragment, &mut evidence)
                .expect("decode fragment");
        }

        let mut expected = b"monitoradded>>".to_vec();
        expected.extend_from_slice(TARGET);
        expected.push(b'\n');
        assert_eq!(evidence, expected);
    }

    #[test]
    fn unrelated_window_titles_never_reach_evidence() {
        let secret = b"private repository title and prompt contents";
        let mut decoder = EventLineDecoder::new(TARGET.to_vec());
        let mut evidence = Vec::new();
        let mut events = b"activewindow>>kitty,".to_vec();
        events.extend_from_slice(secret);
        events.extend_from_slice(b"\nwindowtitlev2>>deadbeef,");
        events.extend_from_slice(secret);
        events.extend_from_slice(b"\n");

        decoder.feed(&events, &mut evidence).expect("decode titles");
        decoder.finish().expect("finish complete stream");

        assert!(evidence.is_empty());
        assert!(
            !evidence
                .windows(secret.len())
                .any(|window| window == secret)
        );
    }

    #[test]
    fn oversized_line_poisons_decoder_and_suppresses_later_match() {
        let mut decoder = EventLineDecoder::new(TARGET.to_vec());
        let mut evidence = Vec::new();
        let oversized = vec![b'x'; MAX_EVENT_LINE_BYTES + 1];

        assert_eq!(
            decoder.feed(&oversized, &mut evidence),
            Err(EventWitnessError::LineTooLong)
        );

        let mut exact = b"monitoradded>>".to_vec();
        exact.extend_from_slice(TARGET);
        exact.push(b'\n');
        assert_eq!(
            decoder.feed(&exact, &mut evidence),
            Err(EventWitnessError::Poisoned)
        );
        assert_eq!(decoder.finish(), Err(EventWitnessError::Poisoned));
        assert!(evidence.is_empty());
    }

    #[test]
    fn unterminated_line_poisons_decoder() {
        let mut decoder = EventLineDecoder::new(TARGET.to_vec());
        let mut evidence = Vec::new();

        decoder
            .feed(b"windowtitle>>private", &mut evidence)
            .expect("buffer partial line");
        assert_eq!(decoder.finish(), Err(EventWitnessError::PartialLine));
        assert_eq!(decoder.finish(), Err(EventWitnessError::Poisoned));
        assert!(evidence.is_empty());
    }

    #[test]
    fn maximum_length_line_is_accepted_but_next_byte_is_not() {
        let mut accepted = EventLineDecoder::new(TARGET.to_vec());
        let mut evidence = Vec::new();
        let mut maximum = vec![b'x'; MAX_EVENT_LINE_BYTES];
        maximum.push(b'\n');
        accepted
            .feed(&maximum, &mut evidence)
            .expect("maximum line is allowed");
        accepted.finish().expect("finish maximum line");

        let mut rejected = EventLineDecoder::new(TARGET.to_vec());
        assert_eq!(
            rejected.feed(&maximum[..MAX_EVENT_LINE_BYTES], &mut evidence),
            Ok(())
        );
        assert_eq!(
            rejected.feed(b"x\n", &mut evidence),
            Err(EventWitnessError::LineTooLong)
        );
        assert!(evidence.is_empty());
    }
}
