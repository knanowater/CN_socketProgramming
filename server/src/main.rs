// rusqlite 크레이트에서 Connection 및 params를 사용. 데이터베이스 상호작용에 필요함.
use rusqlite::{Connection, params};
// 표준 라이브러리의 HashMap을 사용하여 HTTP 헤더를 키-값 쌍으로 저장.
use std::collections::HashMap;
// 표준 라이브러리의 io 모듈을 사용하여 입출력 에러 등을 처리.
use std::io;

// 소켓 관련 저수준 함수들을 캡슐화한 모듈. libc 크레이트를 사용.
mod socket {
    // C 표준 라이브러리의 소켓 관련 함수들을 사용하기 위해 libc를 임포트.
    use libc::*;
    // io 모듈을 사용하여 에러 타입을 정의하고 반환.
    use std::io;
    // 운영체제 파일 디스크립터를 나타내는 타입. 소켓이 파일처럼 다루어짐.
    use std::os::fd::RawFd;

    // 새 TCP 소켓을 생성.
    pub fn create_socket() -> io::Result<RawFd> {
        // socket(domain, type, protocol) 함수 호출:
        // AF_INET: IPv4 주소 체계
        // SOCK_STREAM: TCP 스트림 소켓
        // 0: 프로토콜 자동 선택 (대부분의 경우 TCP는 0)
        let sock = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        // socket 함수는 성공 시 양수 파일 디스크립터, 실패 시 -1을 반환.
        if sock < 0 {
            // 실패 시 운영체제의 마지막 에러 코드를 기반으로 io::Error를 생성하여 반환.
            Err(io::Error::last_os_error())
        } else {
            // 성공 시 파일 디스크립터를 RawFd로 감싸 반환.
            Ok(sock)
        }
    }

    // 생성된 소켓에 특정 주소(IP)와 포트를 할당.
    pub fn bind_socket(sock: RawFd, port: u16) -> io::Result<()> {
        // sockaddr_in 구조체는 IPv4 소켓 주소 정보를 담음.
        let addr = sockaddr_in {
            sin_family: AF_INET as u16, // 주소 체계 (AF_INET)
            sin_port: port.to_be(),     // 포트 번호 (네트워크 바이트 순서로 변환)
            sin_addr: in_addr {
                s_addr: INADDR_ANY.to_be(), // 모든 네트워크 인터페이스의 IP 주소 (네트워크 바이트 순서로 변환)
            },
            sin_zero: [0; 8], // 패딩 (0으로 채움)
        };

        // bind(sockfd, addr, addrlen) 함수 호출:
        // sockfd: 바인딩할 소켓의 파일 디스크립터
        // addr: 바인딩할 주소 구조체에 대한 포인터. sockaddr* 타입으로 캐스팅해야함.
        // addrlen: 주소 구조체의 크기
        let res = unsafe {
            bind(
                sock,
                &addr as *const _ as *const sockaddr, // sockaddr_in* 포인터를 sockaddr* 포인터로 캐스팅
                std::mem::size_of::<sockaddr_in>() as u32, // 구조체 크기를 u32로 캐스팅
            )
        };
        // bind 함수는 성공 시 0, 실패 시 -1을 반환.
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    // 소켓을 들어오는 연결 요청을 대기하는 상태로 만듦.
    pub fn listen_socket(sock: RawFd) -> io::Result<()> {
        // listen(sockfd, backlog) 함수 호출:
        // sockfd: 대기 상태로 만들 소켓의 파일 디스크립터
        // backlog: 동시에 처리 대기할 수 있는 연결 요청의 최대 수
        let res = unsafe { listen(sock, 10) }; // 최대 10개의 연결 요청을 큐에 대기시킬 수 있음.
        // listen 함수는 성공 시 0, 실패 시 -1을 반환.
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    // 대기 중인 소켓에서 새로운 클라이언트 연결 요청을 수락.
    // 연결이 수락되면 클라이언트와의 통신에 사용할 새 소켓 디스크립터를 반환.
    pub fn accept_connection(sock: RawFd) -> io::Result<RawFd> {
        // 클라이언트 주소 정보를 저장할 구조체를 0으로 초기화함.
        let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
        // 주소 구조체 크기를 저장할 변수와 그 포인터. accept 호출 시 이 값을 사용하여 주소 정보를 채움.
        let mut addr_len = std::mem::size_of::<sockaddr_in>() as u32;
        // accept(sockfd, addr, addrlen) 함수 호출:
        // sockfd: 연결 대기 중인 서버 소켓 디스크립터
        // addr: 클라이언트 주소 정보를 저장할 버퍼의 포인터
        // addrlen: addr 버퍼의 크기를 가리키는 포인터 (호출 후 실제 채워진 크기가 업데이트)
        let client_fd =
            unsafe { accept(sock, &mut addr as *mut _ as *mut sockaddr, &mut addr_len) }; // sockaddr_in* 포인터를 sockaddr* 포인터로 캐스팅

        // accept 함수는 성공 시 클라이언트 소켓의 양수 파일 디스크립터, 실패 시 -1을 반환.
        if client_fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // 성공 시 클라이언트 소켓 디스크립터를 RawFd로 감싸 반환.
            Ok(client_fd)
        }
    }
}

// HTTP 요청의 구조를 정의하는 구조체
#[derive(Debug)] // Debug 트레이트를 사용하여 구조체 값을 쉽게 출력할 수 있도록 함.
struct HttpRequest {
    method: String,                   // HTTP 메서드 (GET, POST, PUT 등)
    path: String,                     // 요청된 경로 (URL의 일부)
    http_version: String,             // 사용된 HTTP 버전 (HTTP/1.1 등)
    headers: HashMap<String, String>, // 요청 헤더 (키-값 쌍)
    body: String,                     // 요청 본문
}

// 주어진 문자열로부터 HTTP 요청을 파싱하여 HttpRequest 구조체로 변환하는 함수.
// 파싱에 실패하면 None을 반환.
fn parse_http_request(request: &str) -> Option<HttpRequest> {
    // 요청 문자열을 줄 단위로 분할하는 이터레이터를 생성.
    let mut lines = request.lines();
    // 첫 번째 줄은 HTTP 요청 라인. None이면 파싱 실패.
    let request_line = lines.next()?.trim();
    // 요청 라인을 공백 기준으로 분할.
    let mut parts = request_line.split_whitespace();
    // 메서드, 경로, HTTP 버전을 순서대로 받아옴. None이면 파싱 실패.
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let http_version = parts.next()?.to_string();

    // 헤더를 저장할 빈 HashMap을 생성.
    let mut headers = HashMap::new();
    // 빈 줄이 나올 때까지 각 줄을 처리.
    for line in lines.by_ref() {
        let line = line.trim();
        if line.is_empty() {
            // 빈줄이면 헤더의 끝이니 break.
            break;
        }
        // "Key: Value" 형식의 헤더 줄을 ':' 기준으로 분할.
        if let Some((key, value)) = line.split_once(':') {
            // 키와 값의 앞뒤 공백을 제거하고 HashMap에 삽입.
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    // 헤더 이후의 남은 모든 줄은 요청 body. 모아서 String으로 만듦
    let body = lines.collect::<Vec<&str>>().join("\n");

    // 파싱된 정보를 담은 HttpRequest 구조체를 Some으로 감싸 반환.
    Some(HttpRequest {
        method,
        path,
        http_version,
        headers,
        body,
    })
}

// 서버의 메인 함수.
fn main() -> io::Result<()> {
    // 소켓 모듈을 사용하여 서버 소켓을 생성. 실패 시 즉시 종료.
    let server_fd = socket::create_socket()?;
    // 생성된 소켓에 8080 포트를 바인딩. 실패 시 즉시 종료.
    socket::bind_socket(server_fd, 8080)?;
    // 소켓을 연결 대기 상태로 만듦. 실패 시 즉시 종료.
    socket::listen_socket(server_fd)?;

    println!("서버가 8080 포트에서 대기 중...");

    // SQLite 데이터베이스에 연결 & 데이터베이스가 없으면 생성
    let conn = match Connection::open("data.db") {
        Ok(conn) => conn,
        // 연결 실패 시 에러를 출력하고 프로그램을 종료.
        Err(e) => {
            eprintln!("DB connection error: {:?}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "DB connection error"));
        }
    };

    // my_table 테이블을 생성 (이미 존재하면 무시).
    // key는 TEXT 타입의 PK, value는 NOT NULL인 TEXT 타입.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS my_table (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )
    .expect("테이블 생성 실패"); // 테이블 생성 실패 시 프로그램 강제 종료

    // 서버의 메인 루프. 클라이언트 요청을 계속 받음.
    loop {
        // 클라이언트 연결 요청을 수락하고, 연결된 클라이언트 소켓의 파일 디스크립터를 얻음.
        // accept 실패 시 에러를 출력하고 다음 루프 반복으로 넘어감.
        let client_fd = match socket::accept_connection(server_fd) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("accept error: {}", e);
                continue; // accept 실패 시 이 클라이언트 처리를 건너뛰고 다음 연결을 기다림.
            }
        };

        // 클라이언트로부터 데이터를 읽어올 버퍼를 생성.
        let mut buffer = [0; 1024]; // 1KB 크기의 버퍼
        // libc::read 함수를 사용하여 소켓에서 데이터를 읽음.
        // 성공 시 읽어온 바이트 수, 실패 시 -1을 반환.
        let read_size = unsafe {
            libc::read(
                client_fd,
                buffer.as_mut_ptr() as *mut libc::c_void, // 버퍼의 mutable 포인터를 void*로 캐스팅
                buffer.len(),                             // 버퍼의 크기
            )
        };

        // 읽기 에러 발생 시 에러 메시지를 출력하고 클라이언트 소켓을 닫은 후 다음 루프 반복으로 넘어감.
        if read_size < 0 {
            eprintln!("read error: {}", io::Error::last_os_error());
            unsafe { libc::close(client_fd) }; // 소켓 리소스 해제
            continue; // 다음 루프 반복으로 이동
        }

        // 데이터를 성공적으로 읽어왔다면 (읽어온 바이트 수가 0보다 큰 경우)
        if read_size > 0 {
            let size = read_size as usize;
            // 읽어온 바이트 슬라이스를 UTF-8 문자열로 변환.
            let request_str = String::from_utf8_lossy(&buffer[..size]);

            let mut response = String::new();

            // HTTP 요청 문자열을 파싱.
            if let Some(parsed_request) = parse_http_request(&request_str) {
                // 파싱된 요청 정보를 디버그 형식으로 콘솔에 출력.
                println!("{:#?}", parsed_request);
                // 요청 메서드를 가져옴.
                let method = parsed_request.method;

                // HTTP 메서드에 따라 다른 처리를 수행.
                match method.as_str() {
                    // OPTIONS 메서드 핸들러 (CORS 사전 요청)
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
                    // GET 메서드 핸들러 (데이터 조회)
                    "GET" => {
                        // 요청 경로를 DB의 키로 사용. 경로 시작의 '/'를 제거.
                        let key = if parsed_request.path.starts_with('/') {
                            &parsed_request.path[1..]
                        } else {
                            &parsed_request.path
                        };
                        // DB에서 해당 키의 value를 조회하는 SQL 쿼리를 준비.
                        let mut stmt = conn
                            .prepare("SELECT value FROM my_table WHERE key = ?1")
                            .expect("SELECT 쿼리 준비 실패"); // 쿼리 준비 실패 시 패닉
                        // 쿼리를 실행하고 결과를 받아옴.
                        let mut rows = stmt.query(params![key]).expect("SELECT 쿼리 실행 실패"); // 쿼리 실행 실패 시 패닉
                        // 조회 결과에 따라 응답 본문을 생성.
                        let response_body = if let Some(row) =
                            rows.next().expect("결과 행 가져오기 실패")
                        // 첫 번째 결과 행을 가져옴.
                        {
                            let value: String = row.get(0).expect("조회된 값 가져오기 실패"); // 결과 행의 첫 번째 컬럼(value)을 String으로 가져옴.
                            format!("GET: {}", value) // 값을 포함한 응답 본문
                        } else {
                            "404 Not Found".to_string() // 해당하는 키가 없으면 404 메시지
                        };

                        // 응답 본문 내용에 따라 HTTP 상태 코드를 결정함.
                        let status_line = if response_body == "404 Not Found" {
                            "HTTP/1.1 404 Not Found"
                        } else {
                            "HTTP/1.1 200 OK"
                        };

                        // HTTP 응답 문자열을 생성.
                        response = format!(
                            "{}\r\n\
                             Content-Type: text/plain\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n\
                             Access-Control-Allow-Headers: *\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\r\n{}",
                            status_line,
                            response_body.len(),
                            response_body
                        );
                    }

                    // POST 메서드 핸들러 (데이터 삽입)
                    "POST" => {
                        // 요청 본문에서 'key:value' 형식을 파싱.
                        if let Some((key, value)) = parsed_request.body.split_once(':') {
                            // DB에 새 데이터를 삽입하는 SQL 쿼리를 실행.
                            let response_body = match conn.execute(
                                "INSERT INTO my_table (key, value) VALUES (?1, ?2)",
                                params![key.trim(), value.trim()], // key와 value의 앞뒤 공백 제거 후 바인딩
                            ) {
                                Ok(_) => "201 Created".to_string(),     // 삽입 성공 시 메시지
                                Err(e) => format!("DB Error: {:?}", e), // DB 에러 시 메시지
                            };

                            // 응답 본문 내용에 따라 HTTP 상태 코드를 결정.
                            let status_line = if response_body == "201 Created" {
                                "HTTP/1.1 201 Created"
                            } else {
                                "HTTP/1.1 500 Internal Server Error" // DB 에러 시 500 에러
                            };

                            // HTTP 응답 문자열을 생성.
                            response = format!(
                                "{}\r\n\
                                 Content-Type: text/plain\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Access-Control-Allow-Methods: POST, OPTIONS\r\n\
                                 Access-Control-Allow-Headers: Content-Type\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n{}",
                                status_line,
                                response_body.len(),
                                response_body
                            );
                        } else {
                            // 요청 본문 형식이 잘못된 경우 400 Bad Request 응답을 생성.
                            response = format!(
                                "HTTP/1.1 400 Bad Request\r\n\
                                 Content-Type: text/plain\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Access-Control-Allow-Methods: POST, OPTIONS\r\n\
                                 Access-Control-Allow-Headers: Content-Type\r\n\
                                 Content-Length: 11\r\n\
                                 Connection: close\r\n\r\n{}",
                                "Bad Request" // 응답 본문
                            );
                        }
                    }

                    // PUT 메서드 핸들러 (데이터 업데이트)
                    "PUT" => {
                        // 요청 본문에서 'key:value' 형식을 파싱.
                        if let Some((key, value)) = parsed_request.body.split_once(':') {
                            // DB에서 해당 키의 value를 업데이트하는 SQL 쿼리를 실행.
                            let response_body = match conn.execute(
                                "UPDATE my_table SET value = ?1 WHERE key = ?2",
                                params![value.trim(), key.trim()], // value와 key의 앞뒤 공백 제거 후 바인딩
                            ) {
                                Ok(count) => {
                                    // execute 함수는 영향을 받은 행 수를 반환.
                                    if count > 0 {
                                        "200 OK".to_string() // 업데이트된 행이 하나 이상이면 성공
                                    } else {
                                        "404 Not Found".to_string() // 해당하는 키가 없으면 404 Not Found
                                    }
                                }
                                Err(e) => format!("DB Error: {:?}", e), // DB 에러 시 메시지
                            };

                            // 응답 본문 내용에 따라 HTTP 상태 코드를 결정.
                            let status_line = if response_body == "200 OK" {
                                // 업데이트 성공 시
                                "HTTP/1.1 200 OK"
                            } else if response_body == "404 Not Found" {
                                // 업데이트할 키가 없는 경우
                                "HTTP/1.1 404 Not Found"
                            } else {
                                // 그 외 (DB 에러 등)
                                "HTTP/1.1 500 Internal Server Error"
                            };

                            // HTTP 응답 문자열을 생성.
                            response = format!(
                                "{}\r\n\
                                 Content-Type: text/plain\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Access-Control-Allow-Methods: PUT, OPTIONS\r\n\
                                 Access-Control-Allow-Headers: Content-Type\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\r\n{}",
                                status_line,
                                response_body.len(),
                                response_body
                            );
                        } else {
                            // 요청 본문 형식이 잘못된 경우 400 Bad Request 응답을 생성.
                            response = format!(
                                "HTTP/1.1 400 Bad Request\r\n\
                                 Content-Type: text/plain\r\n\
                                 Access-Control-Allow-Origin: *\r\n\
                                 Access-Control-Allow-Methods: PUT, OPTIONS\r\n\
                                 Access-Control-Allow-Headers: Content-Type\r\n\
                                 Content-Length: 11\r\n\
                                 Connection: close\r\n\r\n{}",
                                "Bad Request"
                            );
                        }
                    }
                    // HEAD 메서드 핸들러 (헤더만 요청)
                    "HEAD" => {
                        // HEAD 요청은 GET과 같지만 응답 본문이 없음.
                        // 200 OK 상태와 본문 길이 0인 응답을 생성.
                        response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Access-Control-Allow-Methods: HEAD, OPTIONS\r\n\
                             Access-Control-Allow-Headers: *\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\r\n"
                        );
                    }
                    // 지원하지 않는 다른 메서드인 경우 400 Bad Request 응답을 생성.
                    _ => {
                        eprintln!("Unsupported method: {}", method); // 지원하지 않는 메서드 로그 출력
                        response = format!(
                            "HTTP/1.1 400 Bad Request\r\n\
                             Content-Type: text/plain\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Access-Control-Allow-Methods: GET, POST, PUT, HEAD, OPTIONS\r\n\
                             Access-Control-Allow-Headers: Content-Type\r\n\
                             Content-Length: 11\r\n\
                             Connection: close\r\n\r\n{}",
                            "Bad Request"
                        );
                    }
                }
            } else {
                // HTTP 요청 파싱에 실패한 경우 400 Bad Request 응답을 생성.
                eprintln!("Request parsing failed!"); // 파싱 실패 로그 출력
                response = format!(
                    "HTTP/1.1 400 Bad Request\r\n\
                     Content-Type: text/plain\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Access-Control-Allow-Methods: GET, POST, PUT, HEAD, OPTIONS\r\n\
                     Access-Control-Allow-Headers: Content-Type\r\n\
                     Content-Length: 11\r\n\
                     Connection: close\r\n\r\n{}",
                    "Bad Request"
                );
            }

            // 생성된 HTTP 응답 문자열을 클라이언트 소켓에 씀.
            // write 함수는 성공 시 쓴 바이트 수, 실패 시 -1을 반환.
            let write_size = unsafe {
                libc::write(
                    client_fd,
                    response.as_ptr() as *const libc::c_void, // 응답 문자열의 const 포인터를 const void*로 캐스팅
                    response.len(),                           // 응답 문자열의 바이트 길이
                )
            };

            // 쓰기 에러 발생 시 에러 메시지를 출력.
            if write_size < 0 {
                eprintln!("write error: {}", io::Error::last_os_error());
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // 클라이언트 소켓을 닫아 연결을 종료.
        unsafe { libc::close(client_fd) }; // 소켓 리소스 해제
    }
}
