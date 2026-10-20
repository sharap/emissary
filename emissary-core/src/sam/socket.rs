// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::{
    runtime::{AsyncRead, AsyncWrite, Runtime},
    sam::parser::SamCommand,
    util::AsyncWriteExt,
};

use futures::Stream;

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    mem,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::socket";

/// Write state
enum WriteState {
    /// Read next outbound message from message buffer.
    GetMessage,

    /// Send message.
    SendMessage {
        /// Write offset.
        offset: usize,

        /// SAMv3 message, potentially partially written.
        message: Vec<u8>,
    },

    /// [`WriteState`] has been poisoned due to a bug.
    Poisoned,
}

/// Read state.
enum ReadState {
    /// Reading a line-delimited command.
    Command,

    /// Reading the payload which follows a `DATAGRAM SEND`/`RAW SEND` command.
    Payload {
        /// The command, its `datagram` is filled as the payload is read.
        command: SamCommand,

        /// How many bytes of payload remain to be read.
        remaining: usize,
    },
}

/// SAMv3 socket.
///
/// Reads new line-delimeted commands from socket and returns them to the caller. The payload of
/// `DATAGRAM SEND`/`RAW SEND` commands is read after the command line and returned as part of the
/// command.
///
/// Invalid commands are ignored, malformed input causes the socket to be closed.
pub struct SamSocket<R: Runtime> {
    /// Pending messages.
    pending_messages: VecDeque<Vec<u8>>,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Number of unprocessed bytes at the start of `read_buffer`.
    read_offset: usize,

    /// Read state.
    read_state: ReadState,

    /// TCP stream.
    stream: R::TcpStream,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> SamSocket<R> {
    /// Create new [`SamSocket`] from an active TCP stream.
    pub fn new(stream: R::TcpStream) -> Self {
        Self {
            pending_messages: VecDeque::new(),
            read_buffer: vec![0u8; 4096],
            read_offset: 0usize,
            read_state: ReadState::Command,
            stream,
            write_state: WriteState::GetMessage,
        }
    }

    /// Convert [`SamSocket`] into `TcpStream`.
    pub fn into_inner(self) -> R::TcpStream {
        self.stream
    }

    /// Send `message` to client.
    pub fn send_message(&mut self, message: Vec<u8>) {
        self.pending_messages.push_back(message);
    }

    /// Send `message` to client and block until the message has been fully written.
    pub async fn send_message_blocking(&mut self, message: Vec<u8>) -> crate::Result<()> {
        self.stream.write_all(&message).await
    }

    /// Discard the first `len` bytes of the read buffer, keeping the rest for later.
    fn consume(&mut self, len: usize) {
        self.read_buffer.copy_within(len..self.read_offset, 0);
        self.read_offset -= len;
    }

    /// Process the buffered input.
    ///
    /// Returns a command if one has been fully read, `None` if more input is needed and an error if
    /// the socket must be closed.
    fn process_buffer(&mut self) -> Result<Option<SamCommand>, ()> {
        loop {
            match mem::replace(&mut self.read_state, ReadState::Command) {
                ReadState::Command => {
                    let Some(pos) =
                        self.read_buffer[..self.read_offset].iter().position(|byte| byte == &b'\n')
                    else {
                        if self.read_offset == self.read_buffer.len() {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "command too long",
                            );
                            return Err(());
                        }

                        return Ok(None);
                    };

                    let command = match core::str::from_utf8(&self.read_buffer[..pos]) {
                        Ok(command) => match SamCommand::parse::<R>(command) {
                            Some(command) => Some(command),
                            None => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    %command,
                                    "invalid sam command",
                                );
                                None
                            }
                        },
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?error,
                                "invalid command"
                            );
                            return Err(());
                        }
                    };
                    self.consume(pos + 1);

                    match command {
                        None => {}
                        Some(command) => match &command {
                            // the payload follows the command line
                            SamCommand::SendDatagram { size, .. } if *size > 0 => {
                                let remaining = *size;
                                self.read_state = ReadState::Payload { command, remaining };
                            }
                            _ => return Ok(Some(command)),
                        },
                    }
                }
                ReadState::Payload {
                    mut command,
                    remaining,
                } => {
                    let available = self.read_offset.min(remaining);

                    if let SamCommand::SendDatagram { datagram, .. } = &mut command {
                        datagram.extend_from_slice(&self.read_buffer[..available]);
                    }
                    self.consume(available);

                    if remaining > available {
                        self.read_state = ReadState::Payload {
                            command,
                            remaining: remaining - available,
                        };
                        return Ok(None);
                    }

                    return Ok(Some(command));
                }
            }
        }
    }
}

impl<R: Runtime> Stream for SamSocket<R> {
    type Item = SamCommand;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        loop {
            // process buffered input first, the buffer may hold a full command (or the payload of
            // one) left over from a previous read
            match this.process_buffer() {
                Err(()) => return Poll::Ready(None),
                Ok(Some(command)) => return Poll::Ready(Some(command)),
                Ok(None) => {}
            }

            match Pin::new(&mut this.stream)
                .poll_read(cx, &mut this.read_buffer[this.read_offset..])
            {
                Poll::Pending => break,
                Poll::Ready(Err(error)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "socket read error",
                    );

                    return Poll::Ready(None);
                }
                Poll::Ready(Ok(0)) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        offset = ?this.read_offset,
                        "read zero bytes from socket",
                    );

                    return Poll::Ready(None);
                }
                Poll::Ready(Ok(nread)) => {
                    this.read_offset += nread;
                }
            }
        }

        let mut stream = Pin::new(&mut this.stream);

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetMessage => match this.pending_messages.pop_front() {
                    None => {
                        this.write_state = WriteState::GetMessage;
                        break;
                    }
                    Some(message) => {
                        this.write_state = WriteState::SendMessage {
                            offset: 0usize,
                            message,
                        };
                    }
                },
                WriteState::SendMessage { offset, message } =>
                    match stream.as_mut().poll_write(cx, &message[offset..]) {
                        Poll::Pending => {
                            this.write_state = WriteState::SendMessage { offset, message };
                            break;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(None),
                        Poll::Ready(Ok(0)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                "wrote zero bytes to socket",
                            );

                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(nwritten)) => match nwritten + offset == message.len() {
                            true => {
                                this.write_state = WriteState::GetMessage;
                            }
                            false => {
                                this.write_state = WriteState::SendMessage {
                                    offset: offset + nwritten,
                                    message,
                                };
                            }
                        },
                    },
                WriteState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "write state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(None);
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::base64_encode,
        primitives::Destination,
        runtime::{
            mock::{MockRuntime, MockTcpStream},
            TcpStream as _,
        },
        sam::parser::{SamVersion, SessionKind},
    };
    use futures::StreamExt;
    use std::time::Duration;
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    #[tokio::test]
    async fn read_command_normal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        tokio::spawn(async move {
            let (mut stream, _) = stream1.unwrap();
            stream.write_all("HELLO VERSION\n".as_bytes()).await.unwrap();

            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        match socket.next().await {
            Some(command) => assert_eq!(
                command,
                SamCommand::Hello {
                    min: None,
                    max: None
                }
            ),
            None => panic!("socket exited"),
        }

        assert_eq!(socket.read_offset, 0usize);
    }

    #[tokio::test(start_paused = true)]
    async fn read_command_partial() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        // send partial command at first
        stream.write_all("HELLO VER".as_bytes()).await.unwrap();

        // poll socket until the partial command has been read
        loop {
            futures::future::poll_fn(|cx| match socket.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("socket is ready"),
            })
            .await;

            if socket.read_offset == 9usize {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // send rest of the command
        stream.write_all("SION MIN=3.1 MAX=3.3\n".as_bytes()).await.unwrap();

        match socket.next().await {
            Some(command) => assert_eq!(
                command,
                SamCommand::Hello {
                    min: Some(SamVersion::V31),
                    max: Some(SamVersion::V33)
                }
            ),
            None => panic!("socket exited"),
        }

        assert_eq!(socket.read_offset, 0usize);
    }

    #[tokio::test]
    async fn read_pipelined_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());

        // two commands in one write, the second must not be lost
        stream.write_all("HELLO VERSION\nPING\n".as_bytes()).await.unwrap();

        assert_eq!(
            socket.next().await,
            Some(SamCommand::Hello {
                min: None,
                max: None
            })
        );
        assert_eq!(socket.next().await, Some(SamCommand::Ping(None)));
        assert_eq!(socket.read_offset, 0usize);
    }

    #[tokio::test]
    async fn read_datagram_send_with_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let (mut stream, _) = stream1.unwrap();
        let mut socket = SamSocket::<MockRuntime>::new(stream2.unwrap());
        let (destination, _) = Destination::random();
        let encoded = base64_encode(destination.serialize());

        // command, payload and a follow-up command in one write
        stream
            .write_all(
                format!("RAW SEND DESTINATION={encoded} SIZE=12 TO_PORT=7\nhello, worldPING\n")
                    .as_bytes(),
            )
            .await
            .unwrap();

        match socket.next().await {
            Some(SamCommand::SendDatagram {
                destination: parsed,
                kind: SessionKind::Anonymous,
                size: 12,
                datagram,
                options,
            }) => {
                assert_eq!(parsed.id(), destination.id());
                assert_eq!(datagram, b"hello, world");
                assert_eq!(options.get("TO_PORT"), Some(&"7".to_string()));
            }
            command => panic!("invalid command: {command:?}"),
        }
        assert_eq!(socket.next().await, Some(SamCommand::Ping(None)));

        // payload split across multiple writes
        stream
            .write_all(format!("DATAGRAM SEND DESTINATION={encoded} SIZE=12\nhel").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        futures::future::poll_fn(|cx| match socket.poll_next_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("socket is ready"),
        })
        .await;

        stream.write_all(b"lo, wo").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.write_all(b"rld").await.unwrap();

        match socket.next().await {
            Some(SamCommand::SendDatagram {
                kind: SessionKind::Datagram,
                datagram,
                ..
            }) => {
                assert_eq!(datagram, b"hello, world");
            }
            command => panic!("invalid command: {command:?}"),
        }
        assert_eq!(socket.read_offset, 0usize);

        // empty payload
        stream
            .write_all(format!("RAW SEND DESTINATION={encoded} SIZE=0\n").as_bytes())
            .await
            .unwrap();

        match socket.next().await {
            Some(SamCommand::SendDatagram { datagram, .. }) => assert!(datagram.is_empty()),
            command => panic!("invalid command: {command:?}"),
        }
    }
}
