use std::io;
use std::collections::HashMap;
use rusqlite::{params, Connection};

mod socket {
    use libc::*;
    use std::os::fd::RawFd;
    use std::io;

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
            sin_addr: in_addr { s_addr: INADDR_ANY.to_be() },
            sin_zero: [0; 8],
        };

        let res = unsafe { bind(sock, &addr as *const _ as *const sockaddr, std::mem::size_of::<sockaddr_in>() as u32) };
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
        let client_fd = unsafe { accept(sock, &mut addr as *mut _ as *mut sockaddr, &mut addr_len) };

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
    ).expect("테이블 생성 실패");

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
                    "GET" => {
                        let key = if parsed_request.path.starts_with('/') {
                            &parsed_request.path[1..]
                        } else {
                            &parsed_request.path
                        };
                        let mut stmt = conn.prepare("SELECT value FROM my_table WHERE key = ?1")
                            .expect("프리페어 실패");
                        let mut rows = stmt.query(params![key])
                            .expect("쿼리 실패");
                        if let Some(row) = rows.next().expect("row 얻기 실패") {
                            let value: String = row.get(0).expect("값 얻기 실패");
                            response = format!("GET: {}", value);
                        } else {
                            response = "404 Not Found".to_string();
                        }
                    },
                    "POST" => {
                        // 예: 요청 body에 "key:value" 형식 데이터가 있다고 가정
                        if let Some((key, value)) = parsed_request.body.split_once(':') {
                            match conn.execute(
                                "INSERT INTO my_table (key, value) VALUES (?1, ?2)",
                                params![key.trim(), value.trim()],
                            ) {
                                Ok(_) => response = "201 Created".to_string(),
                                Err(e) => response = format!("DB Error: {:?}", e),
                            }
                        } else {
                            response = "400 Bad Request".to_string();
                        }
                    },
                    "PUT" => {
                        // 예: 요청 body에 "key:value" 형식 데이터가 있다고 가정
                        if let Some((key, value)) = parsed_request.body.split_once(':') {
                            match conn.execute(
                                "UPDATE my_table SET value = ?1 WHERE key = ?2",
                                params![value.trim(), key.trim()],
                            ) {
                                Ok(count) => {
                                    if count > 0 {
                                        response = "200 OK".to_string();
                                    } else {
                                        response = "404 Not Found".to_string();
                                    }
                                },
                                Err(e) => response = format!("DB Error: {:?}", e),
                            }
                        } else {
                            response = "400 Bad Request".to_string();
                        }
                    },
                    "HEAD" => {
                        // 예: 서버 상태 확인 응답
                        response = "HEAD: Server is running".to_string();
                    },
                    _ => {
                        eprintln!("Wrong method!");
                        response = "400 Bad Request".to_string();
                    },
                }
            } else {
                eprintln!("Request parsing failed!");
                response = "400 Bad Request".to_string();
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
