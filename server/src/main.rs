use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::io;

mod socket {
    use libc::*;
    use std::io;
    use std::os::fd::RawFd;

    pub fn create_socket() -> io::Result<RawFd> {
        let sock = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        if sock < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sock)
        }
    }

    pub fn bind_socket(sock: RawFd, port: u16) -> io::Result<()> {
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: in_addr {
                s_addr: INADDR_ANY.to_be(),
            },
            sin_zero: [0; 8],
        };

        let res = unsafe {
            bind(
                sock,
                &addr as *const _ as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as u32,
            )
        };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn listen_socket(sock: RawFd) -> io::Result<()> {
        let res = unsafe { listen(sock, 10) };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn accept_connection(sock: RawFd) -> io::Result<RawFd> {
        let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<sockaddr_in>() as u32;
        let client_fd =
            unsafe { accept(sock, &mut addr as *mut _ as *mut sockaddr, &mut addr_len) };

        if client_fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(client_fd)
        }
    }
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    http_version: String,
    headers: HashMap<String, String>,
    body: String,
}

fn parse_http_request(request: &str) -> Option<HttpRequest> {
    let mut lines = request.lines();
    let request_line = lines.next()?.trim();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let http_version = parts.next()?.to_string();

    let mut headers = HashMap::new();
    // 헤더 파싱: 빈 줄이 나오기 전까지의 모든 라인
    for line in lines.by_ref() {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    // 빈 줄 이후의 나머지가 body
    let body = lines.collect::<Vec<&str>>().join("\n");

    Some(HttpRequest {
        method,
        path,
        http_version,
        headers,
        body,
    })
}

fn main() -> io::Result<()> {
    let server_fd = socket::create_socket()?;
    socket::bind_socket(server_fd, 8080)?;
    socket::listen_socket(server_fd)?;

    println!("서버가 8080 포트에서 대기 중...");

    // DB 연결 초기화 (data.db가 없으면 생성됩니다)
    let conn = match Connection::open("data.db") {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("DB connection error: {:?}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "DB connection error"));
        }
    };

    // 간단한 테이블 생성 (이미 테이블이 있다면 무시)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS my_table (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )
    .expect("테이블 생성 실패");

    loop {
        let client_fd = socket::accept_connection(server_fd)?;

        let mut buffer = [0; 1024];
        let read_size = unsafe {
            libc::read(
                client_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        if read_size < 0 {
            eprintln!("read error: {}", io::Error::last_os_error());
            unsafe { libc::close(client_fd) };
            continue;
        }

        if read_size > 0 {
            let size = read_size as usize;
            let request_str = String::from_utf8_lossy(&buffer[..size]);
            let mut response = String::new();

            if let Some(parsed_request) = parse_http_request(&request_str) {
                println!("{:#?}", parsed_request);
                let method = parsed_request.method;
                match method.as_str() {
                    "OPTIONS" => {
                        response = format!(
                            "HTTP/1.1 204 No Content\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Access-Control-Allow-Methods: GET, POST, PUT, HEAD, OPTIONS\r\n\
                             Access-Control-Allow-Headers: Content-Type\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\r\n"
                        );
                    }
                    "GET" => {
                        let key = if parsed_request.path.starts_with('/') {
                            &parsed_request.path[1..]
                        } else {
                            &parsed_request.path
                        };
                        let mut stmt = conn
                            .prepare("SELECT value FROM my_table WHERE key = ?1")
                            .expect("프리페어 실패");
                        let mut rows = stmt.query(params![key]).expect("쿼리 실패");
                        let response_body = if let Some(row) = rows.next().expect("row 얻기 실패")
                        {
                            let value: String = row.get(0).expect("값 얻기 실패");
                            format!("GET: {}", value)
                        } else {
                            "404 Not Found".to_string()
                        };
                        response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n\
                             Access-Control-Allow-Headers: *\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\r\n{}",
                            response_body.len(),
                            response_body
                        );
                    }
                    "POST" => {
                        if let Some((key, value)) = parsed_request.body.split_once(':') {
                            let response_body = match conn.execute(
                                "INSERT INTO my_table (key, value) VALUES (?1, ?2)",
                                params![key.trim(), value.trim()],
                            ) {
                                Ok(_) => "201 Created".to_string(),
                                Err(e) => format!("DB Error: {:?}", e),
                            };
                            response = format!(
                                "HTTP/1.1 201 Created\r\n\
                                 Content-Type: text/plain\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Access-Control-Allow-Methods: POST, OPTIONS\r\n\
                                 Access-Control-Allow-Headers: Content-Type\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n{}",
                                response_body.len(),
                                response_body
                            );
                        } else {
                            response = format!(
                                "HTTP/1.1 400 Bad Request\r\n\
                                 Content-Type: text/plain\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Access-Control-Allow-Methods: POST, OPTIONS\r\n\
                                 Access-Control-Allow-Headers: Content-Type\r\n\
                                 Content-Length: 19\r\n\
                                 Connection: close\r\n\r\n{}",
                                "400 Bad Request"
                            );
                        }
                    }
                    "PUT" => {
                        if let Some((key, value)) = parsed_request.body.split_once(':') {
                            let response_body = match conn.execute(
                                "UPDATE my_table SET value = ?1 WHERE key = ?2",
                                params![value.trim(), key.trim()],
                            ) {
                                Ok(count) => {
                                    if count > 0 {
                                        "200 OK".to_string()
                                    } else {
                                        "404 Not Found".to_string()
                                    }
                                }
                                Err(e) => format!("DB Error: {:?}", e),
                            };
                            response = format!(
                                "HTTP/1.1 {}\r\n\
                                 Content-Type: text/plain\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Access-Control-Allow-Methods: PUT, OPTIONS\r\n\
                                 Access-Control-Allow-Headers: Content-Type\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n{}",
                                if response_body == "200 OK" {
                                    "200 OK"
                                } else {
                                    "404 Not Found"
                                },
                                response_body.len(),
                                response_body
                            );
                        } else {
                            response = format!(
                                "HTTP/1.1 400 Bad Request\r\n\
                                 Content-Type: text/plain\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Access-Control-Allow-Methods: PUT, OPTIONS\r\n\
                                 Access-Control-Allow-Headers: Content-Type\r\n\
                                 Content-Length: 19\r\n\
                                 Connection: close\r\n\r\n{}",
                                "400 Bad Request"
                            );
                        }
                    }
                    "HEAD" => {
                        response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Access-Control-Allow-Methods: HEAD, OPTIONS\r\n\
                             Access-Control-Allow-Headers: *\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\r\n"
                        );
                    }
                    _ => {
                        eprintln!("Wrong method!");
                        response = format!(
                            "HTTP/1.1 400 Bad Request\r\n\
                             Content-Type: text/plain\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Access-Control-Allow-Methods: GET, POST, PUT, HEAD, OPTIONS\r\n\
                             Access-Control-Allow-Headers: Content-Type\r\n\
                             Content-Length: 19\r\n\
                             Connection: close\r\n\r\n{}",
                            "400 Bad Request"
                        );
                    }
                }
            } else {
                eprintln!("Request parsing failed!");
                response = format!(
                    "HTTP/1.1 400 Bad Request\r\n\
                     Content-Type: text/plain\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Access-Control-Allow-Methods: GET, POST, PUT, HEAD, OPTIONS\r\n\
                     Access-Control-Allow-Headers: Content-Type\r\n\
                     Content-Length: 19\r\n\
                     Connection: close\r\n\r\n{}",
                    "400 Bad Request"
                );
            }

            let write_size = unsafe {
                libc::write(
                    client_fd,
                    response.as_ptr() as *const libc::c_void,
                    response.len(),
                )
            };

            if write_size < 0 {
                eprintln!("write error: {}", io::Error::last_os_error());
            }
        }

        unsafe { libc::close(client_fd) };
    }
}
