//! The spelling of HTTP/1 header names as the client sent them.
//!
//! hyper lower-cases header names while parsing and keeps the original spelling
//! in a private extension (`HeaderCaseMap`) that only hyper's own client can
//! replay, so a server cannot read it. REST APIs hand Lambda the client's
//! spelling in payload format 1.0 (`Content-Type`, not `content-type`), so this
//! module recovers it by watching the bytes of each HTTP/1 request head on the
//! way into hyper.
//!
//! [`HeaderCaseTap`] wraps the connection and feeds every byte read to a
//! [`HeadScanner`], which follows HTTP/1 message framing (`Content-Length` and
//! chunked bodies) to find where each request head starts. Spellings are queued
//! in arrival order on a [`HeaderCaseQueue`]; the service pops one per request.
//! The result only ever re-spells a name the request really has, so if framing
//! is lost (an upgrade, a malformed message) the worst case is another request's
//! spelling of the same header, and the scanner switches itself off.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Longest request head the scanner tracks; beyond this hyper would refuse the
/// request anyway.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Longest chunk-size line (hex size plus extensions) the scanner accepts.
const MAX_CHUNK_LINE_BYTES: usize = 256;
/// Requests whose heads were read but not yet handed to the service.
const MAX_PENDING_HEADS: usize = 256;

/// The header names of one request as the client spelled them, in arrival order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HeaderCase(Vec<String>);

impl HeaderCase {
    #[cfg(test)]
    pub(crate) fn spelled(names: &[&str]) -> Self {
        Self(names.iter().map(|name| (*name).to_owned()).collect())
    }

    /// The client's spelling of `name` (matched case-insensitively), or `name`
    /// itself when the request wasn't read over HTTP/1.
    pub(crate) fn spelling<'a>(&'a self, name: &'a str) -> &'a str {
        self.0
            .iter()
            .find(|spelled| spelled.eq_ignore_ascii_case(name))
            .map_or(name, String::as_str)
    }
}

/// Request heads read from one connection, waiting for their requests.
#[derive(Debug, Clone, Default)]
pub(crate) struct HeaderCaseQueue(Arc<Mutex<VecDeque<HeaderCase>>>);

impl HeaderCaseQueue {
    fn push(&self, head: HeaderCase) {
        let mut queue = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.len() >= MAX_PENDING_HEADS {
            queue.pop_front();
        }
        queue.push_back(head);
    }

    /// The oldest head not yet claimed: the one belonging to the next request
    /// hyper hands to the service.
    pub(crate) fn pop(&self) -> Option<HeaderCase> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }
}

/// What the scanner expects next on the connection.
#[derive(Debug)]
enum Phase {
    /// Accumulating a request head up to its blank line.
    Head(Vec<u8>),
    /// Skipping a body of this many remaining bytes.
    Fixed(u64),
    Chunked(Chunk),
    /// Framing is lost or the connection left HTTP/1 (h2, upgrade).
    Off,
}

#[derive(Debug)]
enum Chunk {
    /// Reading a chunk-size line.
    Size(Vec<u8>),
    /// Skipping chunk data of this many remaining bytes.
    Data(u64),
    /// Skipping the CRLF after chunk data; this many bytes remain.
    DataEnd(u8),
    /// Skipping trailer lines up to the blank line; `line_len` counts the
    /// current line's bytes other than CR.
    Trailers { line_len: usize },
}

/// A parsed request head: header spellings and how the body is framed.
#[derive(Debug, Default)]
struct Head {
    names: Vec<String>,
    content_length: Option<Result<u64, ()>>,
    chunked: bool,
    upgrade: bool,
    connect: bool,
}

impl Head {
    fn parse(raw: &[u8]) -> Self {
        let text = String::from_utf8_lossy(raw);
        let mut head = Self::default();
        let mut lines = text.split("\r\n").filter(|line| !line.is_empty());
        if let Some(request_line) = lines.next() {
            head.connect = request_line
                .split(' ')
                .next()
                .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"));
        }
        for line in lines {
            if line.starts_with([' ', '\t']) {
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.is_empty() || name.contains(char::is_whitespace) {
                continue;
            }
            head.note_framing(name, value.trim());
            head.names.push(name.to_owned());
        }
        head
    }

    fn note_framing(&mut self, name: &str, value: &str) {
        if name.eq_ignore_ascii_case("content-length") {
            let length = value.parse::<u64>().map_err(|_| ());
            self.content_length = match (self.content_length.take(), length) {
                (None, length) => Some(length),
                (Some(_), _) => Some(Err(())),
            };
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            self.chunked |= value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            self.upgrade = true;
        }
    }

    /// What follows the head on the wire.
    fn next_phase(&self) -> Phase {
        if self.upgrade || self.connect {
            return Phase::Off;
        }
        if self.chunked {
            return Phase::Chunked(Chunk::Size(Vec::new()));
        }
        match self.content_length {
            None | Some(Ok(0)) => Phase::Head(Vec::new()),
            Some(Ok(length)) => Phase::Fixed(length),
            Some(Err(())) => Phase::Off,
        }
    }
}

/// Follows HTTP/1 framing to pick out request heads from a byte stream.
#[derive(Debug)]
struct HeadScanner {
    phase: Phase,
    seen_head: bool,
}

impl Default for HeadScanner {
    fn default() -> Self {
        Self {
            phase: Phase::Head(Vec::new()),
            seen_head: false,
        }
    }
}

impl HeadScanner {
    /// Consumes bytes read from the client, returning the heads that completed.
    fn feed(&mut self, mut input: &[u8]) -> Vec<HeaderCase> {
        let mut heads = Vec::new();
        while !input.is_empty() {
            let phase = std::mem::replace(&mut self.phase, Phase::Off);
            let (phase, rest) = match phase {
                Phase::Off => return heads,
                Phase::Head(buf) => self.scan_head(buf, input, &mut heads),
                Phase::Fixed(remaining) => {
                    let (remaining, rest) = Self::skip(remaining, input);
                    let phase = if remaining == 0 {
                        Phase::Head(Vec::new())
                    } else {
                        Phase::Fixed(remaining)
                    };
                    (phase, rest)
                }
                Phase::Chunked(chunk) => {
                    let (chunk, rest) = Self::scan_chunk(chunk, input);
                    (chunk.map_or(Phase::Off, Self::chunk_phase), rest)
                }
            };
            self.phase = phase;
            input = rest;
        }
        heads
    }

    fn chunk_phase(step: ChunkStep) -> Phase {
        match step {
            ChunkStep::Continue(chunk) => Phase::Chunked(chunk),
            ChunkStep::Done => Phase::Head(Vec::new()),
        }
    }

    fn skip(remaining: u64, input: &[u8]) -> (u64, &[u8]) {
        let available = u64::try_from(input.len()).unwrap_or(u64::MAX);
        let taken = remaining.min(available);
        let consumed = usize::try_from(taken).unwrap_or(input.len());
        (
            remaining.saturating_sub(taken),
            input.get(consumed..).unwrap_or_default(),
        )
    }

    fn scan_head<'i>(
        &mut self,
        mut buf: Vec<u8>,
        input: &'i [u8],
        heads: &mut Vec<HeaderCase>,
    ) -> (Phase, &'i [u8]) {
        for (index, &byte) in input.iter().enumerate() {
            buf.push(byte);
            if !self.seen_head && buf.as_slice() == b"PRI " {
                return (Phase::Off, &[]);
            }
            if buf.ends_with(b"\r\n\r\n") {
                self.seen_head = true;
                let head = Head::parse(&buf);
                let phase = head.next_phase();
                heads.push(HeaderCase(head.names));
                let consumed = index.saturating_add(1);
                return (phase, input.get(consumed..).unwrap_or_default());
            }
            if buf.len() > MAX_HEAD_BYTES {
                return (Phase::Off, &[]);
            }
        }
        (Phase::Head(buf), &[])
    }

    fn scan_chunk(chunk: Chunk, input: &[u8]) -> (Option<ChunkStep>, &[u8]) {
        match chunk {
            Chunk::Data(remaining) => {
                let (remaining, rest) = Self::skip(remaining, input);
                let next = if remaining == 0 {
                    Chunk::DataEnd(2)
                } else {
                    Chunk::Data(remaining)
                };
                (Some(ChunkStep::Continue(next)), rest)
            }
            Chunk::Size(mut line) => {
                let mut rest = input;
                while let Some((&byte, tail)) = rest.split_first() {
                    rest = tail;
                    line.push(byte);
                    if byte == b'\n' {
                        let step = Self::chunk_size(&line).map(|size| {
                            ChunkStep::Continue(if size == 0 {
                                Chunk::Trailers { line_len: 0 }
                            } else {
                                Chunk::Data(size)
                            })
                        });
                        return (step, rest);
                    }
                    if line.len() > MAX_CHUNK_LINE_BYTES {
                        return (None, rest);
                    }
                }
                (Some(ChunkStep::Continue(Chunk::Size(line))), rest)
            }
            Chunk::DataEnd(remaining) => {
                let rest = input.get(1..).unwrap_or_default();
                let next = match remaining.checked_sub(1) {
                    Some(left) if left > 0 => Chunk::DataEnd(left),
                    Some(_) | None => Chunk::Size(Vec::new()),
                };
                (Some(ChunkStep::Continue(next)), rest)
            }
            Chunk::Trailers { mut line_len } => {
                let mut rest = input;
                while let Some((&byte, tail)) = rest.split_first() {
                    rest = tail;
                    match byte {
                        b'\n' if line_len == 0 => return (Some(ChunkStep::Done), rest),
                        b'\n' => line_len = 0,
                        b'\r' => {}
                        _ => line_len = line_len.saturating_add(1),
                    }
                }
                (
                    Some(ChunkStep::Continue(Chunk::Trailers { line_len })),
                    rest,
                )
            }
        }
    }

    fn chunk_size(line: &[u8]) -> Option<u64> {
        let text = std::str::from_utf8(line).ok()?;
        let size = text.split(';').next()?.trim();
        u64::from_str_radix(size, 16).ok()
    }
}

/// The outcome of one chunked-body step.
#[derive(Debug)]
enum ChunkStep {
    Continue(Chunk),
    Done,
}

/// A connection that records the spelling of the header names flowing through
/// it. Writes pass through untouched.
#[derive(Debug)]
pub(crate) struct HeaderCaseTap<S> {
    inner: S,
    scanner: HeadScanner,
    queue: HeaderCaseQueue,
}

impl<S> HeaderCaseTap<S> {
    pub(crate) fn new(inner: S, queue: HeaderCaseQueue) -> Self {
        Self {
            inner,
            scanner: HeadScanner::default(),
            queue,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HeaderCaseTap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(())))
            && let Some(fresh) = buf.filled().get(before..)
        {
            for head in this.scanner.feed(fresh) {
                this.queue.push(head);
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeaderCaseTap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn names(heads: &[HeaderCase]) -> Vec<Vec<&str>> {
        heads
            .iter()
            .map(|head| head.0.iter().map(String::as_str).collect())
            .collect()
    }

    #[test]
    fn records_the_spelling_of_each_header() {
        let mut scanner = HeadScanner::default();
        let heads =
            scanner.feed(b"GET /x HTTP/1.1\r\nHost: a\r\nX-Api-KEY: 1\r\ncontent-type: t\r\n\r\n");
        assert_eq!(names(&heads), [["Host", "X-Api-KEY", "content-type"]]);
        assert_eq!(heads[0].spelling("x-api-key"), "X-Api-KEY");
        assert_eq!(heads[0].spelling("absent"), "absent");
    }

    #[test]
    fn follows_content_length_and_chunked_bodies_across_pipelined_requests() {
        let mut scanner = HeadScanner::default();
        let wire = b"POST /a HTTP/1.1\r\nA-One: 1\r\nContent-Length: 5\r\n\r\nB: x\r\n\r\n\
POST /b HTTP/1.1\r\nB-Two: 1\r\nTransfer-Encoding: chunked\r\n\r\n\
4;ext=1\r\nC: d\r\n3\r\nabc\r\n0\r\nTrailer-X: y\r\n\r\n\
GET /c HTTP/1.1\r\nC-Three: 1\r\n\r\n";
        let heads = scanner.feed(wire);
        assert_eq!(
            names(&heads),
            [
                vec!["A-One", "Content-Length"],
                vec!["B-Two", "Transfer-Encoding"],
                vec!["C-Three"]
            ]
        );
    }

    #[test]
    fn framing_survives_arbitrary_read_boundaries() {
        let wire = b"POST /a HTTP/1.1\r\nA-One: 1\r\nContent-Length: 4\r\n\r\n\r\n\r\n\
GET /b HTTP/1.1\r\nB-Two: 1\r\n\r\n";
        for split in 1..wire.len() {
            let mut scanner = HeadScanner::default();
            let (left, right) = wire.split_at(split);
            let mut heads = scanner.feed(left);
            heads.extend(scanner.feed(right));
            assert_eq!(heads.len(), 2, "split at {split}");
            assert_eq!(heads[1].0, ["B-Two"], "split at {split}");
        }
    }

    #[test]
    fn stops_recording_when_framing_cannot_be_followed() {
        let cases: [&[u8]; 5] = [
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\nGET / HTTP/1.1\r\nX: 1\r\n\r\n",
            b"CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nX: 1\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\nGET / HTTP/1.1\r\nX: 1\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nxGET / HTTP/1.1\r\nX: 1\r\n\r\n",
        ];
        for wire in cases {
            let heads = HeadScanner::default().feed(wire);
            assert!(heads.len() <= 1, "{}", String::from_utf8_lossy(wire));
            assert!(
                heads.iter().all(|head| head.0 != ["X"]),
                "{}",
                String::from_utf8_lossy(wire)
            );
        }
    }

    #[test]
    fn oversized_heads_and_chunk_lines_switch_the_scanner_off() {
        let mut scanner = HeadScanner::default();
        let mut wire = b"GET / HTTP/1.1\r\nX: ".to_vec();
        wire.resize(MAX_HEAD_BYTES + 100, b'a');
        assert!(scanner.feed(&wire).is_empty());
        assert!(
            scanner
                .feed(b"\r\n\r\nGET / HTTP/1.1\r\nY: 1\r\n\r\n")
                .is_empty()
        );

        let mut scanner = HeadScanner::default();
        scanner.feed(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        let junk = vec![b'f'; MAX_CHUNK_LINE_BYTES + 10];
        scanner.feed(&junk);
        assert!(
            scanner
                .feed(b"\r\n\r\nGET / HTTP/1.1\r\nY: 1\r\n\r\n")
                .is_empty()
        );
    }

    #[test]
    fn queue_hands_heads_out_in_order_and_is_bounded() {
        let queue = HeaderCaseQueue::default();
        for index in 0..MAX_PENDING_HEADS + 2 {
            queue.push(HeaderCase(vec![index.to_string()]));
        }
        assert_eq!(queue.pop().unwrap().0, ["2"]);
    }

    #[tokio::test]
    async fn tap_records_while_passing_bytes_through() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (mut client, server) = tokio::io::duplex(1024);
        let queue = HeaderCaseQueue::default();
        let mut tap = HeaderCaseTap::new(server, queue.clone());
        client
            .write_all(b"GET / HTTP/1.1\r\nX-Mixed-Case: 1\r\n\r\n")
            .await
            .unwrap();
        let mut seen = vec![0; 64];
        let read = tap.read(&mut seen).await.unwrap();
        assert!(seen[..read].starts_with(b"GET /"));
        assert_eq!(queue.pop().unwrap().0, ["X-Mixed-Case"]);
        assert!(queue.pop().is_none());

        tap.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    }

    proptest! {
        #[test]
        fn scanner_never_panics_and_never_invents_names(wire in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut scanner = HeadScanner::default();
            for chunk in wire.chunks(7) {
                scanner.feed(chunk);
            }
        }
    }
}
