use crate::smtp_server::Envelope;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpSocket;

const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

/// Sends an email using an SMTP server at `localhost:<smtp_port>`.
pub async fn send(smtp_port: u16, envelope: &Envelope) -> Result<(), crate::error::Error> {
    let socket = TcpSocket::new_v4()?;

    // Disable Nagle's algorithm.
    socket.set_nodelay(true)?;

    let stream = socket
        .connect(SocketAddr::new(LOCALHOST, smtp_port))
        .await?;

    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut response = String::new();

    macro_rules! cmd {
        ($command:expr, $context:expr, $expected_code:expr) => {
            cmd!(write $command);
            cmd!(read $context, $expected_code);
        };
        (write $command:expr) => {
            writer.write_all($command).await?;
            writer.flush().await?;
        };
        (read $context:expr, $expected_code:expr) => {
            reader.read_line(&mut response).await?;
            if !response.starts_with($expected_code) {
                return Err(crate::error::Error::MailSend {
                    context: $context.to_string(),
                    raw_smtp_answer: response.clone(),
                });
            }
            response.clear();
        };
    }

    // Read initial greeting
    cmd!(read "initial greeting", "220");

    // Greet (Using HELO as we don't want to deal with extended SMTP anyway.)
    cmd!(b"HELO localhost\r\n", "HELO", "250");

    // MAIL FROM
    cmd!(
        format!("MAIL FROM:<{}>\r\n", envelope.mail_from).as_bytes(),
        "MAIL FROM",
        "250"
    );

    // RCPT TO
    for rcpt in &envelope.rcpt_to {
        cmd!(
            format!("RCPT TO:<{}>\r\n", rcpt).as_bytes(),
            "RCPT TO",
            "250"
        );
    }

    // DATA
    cmd!(b"DATA\r\n", "DATA", "354");
    cmd!(write & envelope.data);
    cmd!(write b".\r\n");
    cmd!(read "end of DATA", "250");

    Ok(())
}
