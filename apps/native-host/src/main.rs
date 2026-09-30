#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

const MAX_FRAME: usize = 64 * 1024;

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
enum Request {
    #[serde(rename = "fill_request")]
    Fill {
        #[serde(rename = "requestId")]
        request_id: String,
        origin: String,
        #[serde(rename = "frameOrigin")]
        frame_origin: String,
        #[serde(rename = "documentId")]
        document_id: String,
        #[serde(rename = "tabId")]
        tab_id: i64,
        #[serde(rename = "frameId")]
        frame_id: i64,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "type")]
enum Response {
    #[serde(rename = "error")]
    Error {
        #[serde(rename = "requestId")]
        request_id: Option<String>,
        code: &'static str,
    },
}

fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(writer: &mut impl Write, response: &Response) -> io::Result<()> {
    let body = serde_json::to_vec(response).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    writer.write_all(&(body.len() as u32).to_ne_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

fn safe_origin(origin: &str) -> bool {
    let Ok(url) = url::Url::parse(origin) else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.host().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

fn handle(body: &[u8]) -> Response {
    let Ok(request) = serde_json::from_slice::<Request>(body) else {
        return Response::Error {
            request_id: None,
            code: "invalid_message",
        };
    };
    match request {
        Request::Fill {
            request_id,
            origin,
            frame_origin,
            document_id,
            tab_id,
            frame_id,
        } => {
            let _ = (tab_id, frame_id);
            if request_id.is_empty()
                || request_id.len() > 128
                || document_id.is_empty()
                || document_id.len() > 128
                || !safe_origin(&origin)
                || origin != frame_origin
            {
                return Response::Error {
                    request_id: Some(request_id),
                    code: "origin_rejected",
                };
            }
            // The host intentionally has no ambient access to a vault. A Tauri
            // session-bound, authenticated IPC adapter must be installed before
            // this process can release credentials. Failing closed keeps a
            // browser page from turning native messaging into a secret oracle.
            Response::Error {
                request_id: Some(request_id),
                code: "desktop_session_unavailable",
            }
        }
        Request::Unknown => Response::Error {
            request_id: None,
            code: "unsupported_message",
        },
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    while let Some(body) = read_frame(&mut reader)? {
        write_frame(&mut writer, &handle(&body))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_and_userinfo() {
        assert!(!safe_origin("http://example.test/"));
        assert!(!safe_origin("https://user@example.test/"));
        assert!(!safe_origin("data:text/plain,secret"));
        assert!(safe_origin("https://example.test/"));
    }

    #[test]
    fn malformed_request_fails_closed() {
        let response = handle(br#"{"type":"fill_request","requestId":"x","origin":"http://example.test/","frameOrigin":"http://example.test/","documentId":"d","tabId":1,"frameId":0}"#);
        assert!(matches!(
            response,
            Response::Error {
                code: "origin_rejected",
                ..
            }
        ));
    }

    #[test]
    fn valid_request_still_requires_authenticated_desktop_session() {
        let response = handle(br#"{"type":"fill_request","requestId":"x","origin":"https://example.test/","frameOrigin":"https://example.test/","documentId":"d","tabId":1,"frameId":0}"#);
        assert!(matches!(
            response,
            Response::Error {
                code: "desktop_session_unavailable",
                ..
            }
        ));
    }
}
