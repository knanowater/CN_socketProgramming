// C 표준 라이브러리 함수들을 사용하기 위해 libc 크레이트를 임포트.
use libc::*;
// 파일 시스템 작업을 위해 표준 라이브러리의 fs 모듈을 임포트. (index.html 파일 읽기용)
use std::fs;
// 입출력 관련 트레이트(Read, Write)와 에러 타입(io::Result) 등을 위해 표준 라이브러리의 io 모듈을 임포트.
use std::io::{self, Read, Write};
// 메모리 관련 작업을 위해 표준 라이브러리의 mem 모듈을 임포트. (구조체 크기, 바이트 순서 변환 등)
use std::mem;
// 유닉스 계열 시스템의 파일 디스크립터 타입을 위해 표준 라이브러리의 os::unix::io::RawFd를 임포트.
use std::os::unix::io::RawFd;
// 널 포인터 등을 사용하기 위해 표준 라이브러리의 ptr 모듈을 임포트.
use std::ptr;
// 멀티스레딩을 위해 표준 라이브러리의 thread 모듈을 임포트. 각 클라이언트 연결을 별도 스레드에서 처리함.
use std::thread;

// 소켓 파일 디스크립터(RawFd)를 래핑(wrapping)하는 구조체.
struct Socket {
    fd: RawFd, // 운영체제의 소켓 파일 디스크립터
}

impl Socket {
    // 특정 IP와 포트로 TCP 연결을 시도하는 연관 함수.
    // Ipv4 주소는 u32 형식으로 받음.
    pub fn connect(ip: u32, port: u16) -> io::Result<Self> {
        // socket(AF_INET, SOCK_STREAM, 0) 호출: IPv4, 스트림(TCP) 소켓을 생성.
        let sock = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        // 소켓 생성 실패 시 -1을 반환.
        if sock < 0 {
            // 에러 정보를 io::Error로 변환하여 반환.
            return Err(io::Error::last_os_error());
        }

        // 연결할 대상 서버의 주소 정보를 담는 sockaddr_in 구조체를 설정.
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,               // 주소 체계 (IPv4)
            sin_port: port.to_be(), // 포트 번호 (호스트 바이트 순서 -> 네트워크 바이트 순서)
            sin_addr: in_addr { s_addr: ip.to_be() }, // IP 주소 (호스트 바이트 순서 -> 네트워크 바이트 순서)
            sin_zero: [0; 8],                         // 패딩
        };

        // connect(sockfd, addr, addrlen) 함수 호출:
        // sockfd: 연결을 시도할 소켓의 파일 디스크립터
        // addr: 연결할 대상 주소 구조체에 대한 포인터 (sockaddr* 타입으로 캐스팅)
        // addrlen: 주소 구조체의 크기
        let res = unsafe {
            connect(
                sock,
                &addr as *const _ as *const sockaddr, // sockaddr_in* 포인터를 sockaddr* 포인터로 캐스팅
                mem::size_of::<sockaddr_in>() as u32, // 구조체 크기를 u32로 캐스팅
            )
        };

        // connect 함수는 성공 시 0, 실패 시 -1을 반환.
        if res < 0 {
            // 연결 실패 시 소켓 리소스를 즉시 해제.
            unsafe {
                close(sock);
            }
            // 에러 정보를 io::Error로 변환하여 반환.
            return Err(io::Error::last_os_error());
        }

        // 성공 시 Socket 구조체를 생성하여 반환.
        Ok(Socket { fd: sock })
    }
}

// Socket 구조체에 io::Write 트레이트를 구현하여 write 메소드를 제공.
impl io::Write for Socket {
    // 버퍼의 내용을 소켓에 씀.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            // libc::write(fd, buf, count) 함수 호출:
            // fd: 데이터를 쓸 파일 디스크립터
            // buf: 쓸 데이터가 있는 버퍼의 포인터 (const void* 타입으로 캐스팅)
            // count: 쓸 바이트 수
            let res = libc::write(self.fd, buf.as_ptr() as *const _, buf.len());
            // write 함수는 성공 시 쓴 바이트 수, 실패 시 -1을 반환.
            if res < 0 {
                // 에러 정보를 io::Error로 변환하여 반환.
                Err(io::Error::last_os_error())
            } else {
                // 성공 시 쓴 바이트 수를 usize로 캐스팅하여 반환.
                Ok(res as usize)
            }
        }
    }

    // 버퍼에 있는 데이터를 강제로 비워 소켓에 쓰도록 함.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Socket 구조체에 io::Read 트레이트를 구현하여 read 메소드를 제공.
impl io::Read for Socket {
    // 소켓에서 데이터를 읽어 버퍼에 채움.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            // libc::read(fd, buf, count) 함수 호출:
            // fd: 데이터를 읽을 파일 디스크립터
            // buf: 읽어온 데이터를 저장할 버퍼의 포인터 (mutable void* 타입으로 캐스팅)
            // count: 읽어올 최대 바이트 수 (버퍼의 크기)
            let res = libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len());
            // read 함수는 성공 시 읽어온 바이트 수 (0은 연결 종료), 실패 시 -1을 반환.
            if res < 0 {
                // 에러 정보를 io::Error로 변환하여 반환.
                Err(io::Error::last_os_error())
            } else {
                // 성공 시 읽어온 바이트 수를 usize로 캐스팅하여 반환.
                Ok(res as usize)
            }
        }
    }
}

// Socket 구조체가 스코프를 벗어날 때 자동으로 호출되는 Drop 트레이트를 구현.
impl Drop for Socket {
    // 소켓 객체가 파괴될 때 소켓 파일 디스크립터를 닫아 리소스를 해제.
    fn drop(&mut self) {
        unsafe {
            // libc::close(fd) 함수 호출: 파일 디스크립터를 닫음.
            close(self.fd);
        }
    }
}

// send_request_forward 함수:
// 주어진 메서드, 본문, 대상 서버 정보(IP, 포트, 경로)를 사용하여 대상 서버로 HTTP 요청을 보내고 응답을 문자열로 받아 반환.
fn send_request_forward(
    method: &str,
    request_body: &str,
    target_ip: &str,   // 대상 서버 IP 주소 문자열
    target_port: u16,  // 대상 서버 포트
    target_path: &str, // 대상 서버의 요청 경로
) -> io::Result<String> {
    // 입력받은 대상 IP 문자열을 std::net::Ipv4Addr 타입으로 파싱.
    let ip_addr: std::net::Ipv4Addr = target_ip
        .parse() // 문자열을 Ipv4Addr로 파싱 시도
        // 파싱 실패 시 에러를 io::Error 타입으로 매핑.
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    // Ipv4Addr을 u32 정수 형태로 변환.
    let ip_u32 = u32::from(ip_addr);

    // 대상 서버 IP와 포트로 Socket 연결을 시도. 실패 시 에러를 반환.
    let mut socket = Socket::connect(ip_u32, target_port)?;

    // 대상 서버로 보낼 HTTP 요청 문자열의 시작 부분을 구성.
    // 요청 라인: 메서드 경로 HTTP/1.1
    // Host 헤더: 대상 서버의 IP
    // Connection: close 헤더: 요청 처리 후 연결을 닫도록 요청
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, target_path, target_ip
    );

    // POST 또는 PUT 메서드인 경우 요청 본문과 Content-Length 헤더를 추가.
    if method == "POST" || method == "PUT" {
        // Content-Length 헤더 추가: 본문의 바이트 길이를 지정.
        req.push_str(&format!("Content-Length: {}\r\n", request_body.len()));
        // 헤더 끝을 나타내는 빈 줄을 추가.
        req.push_str("\r\n");
        // 요청 본문을 추가.
        req.push_str(request_body);
    } else {
        // 본문이 없는 메서드인 경우 헤더 끝을 나타내는 빈 줄만 추가.
        req.push_str("\r\n");
    }

    // 완성된 HTTP 요청 문자열을 대상 서버 소켓에 모두 씀.
    // write_all은 전체 바이트를 모두 쓸 때까지 시도.
    socket.write_all(req.as_bytes())?;

    // 대상 서버로부터의 응답을 읽어올 버퍼를 준비.
    let mut buffer = [0; 1024];
    // 소켓으로부터 응답 데이터를 읽음.
    let n = socket.read(&mut buffer)?;

    // 읽어온 데이터가 있는 경우
    if n > 0 {
        // 읽어온 바이트 슬라이스를 UTF-8 문자열로 변환. 유효하지 않은 문자는 대체.
        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    } else {
        // 읽어온 데이터가 없는 경우 (연결이 즉시 닫혔거나 데이터가 없는 경우)
        Ok("응답 없음".to_string())
    }
}

// handle_client 함수:
// 새로 연결된 클라이언트의 파일 디스크립터(client_fd)를 인자로 받아 해당 클라이언트의 요청을 처리.
// 각 클라이언트 연결은 이 함수를 호출하는 별도의 스레드에서 처리.
fn handle_client(client_fd: RawFd) {
    // 클라이언트 요청을 읽어올 버퍼를 준비.
    let mut buffer = [0u8; 2048]; // 2KB 버퍼

    unsafe {
        // libc 함수 호출을 위해 unsafe 블록 사용
        // 클라이언트 소켓으로부터 요청 데이터를 읽음.
        let bytes_read = read(client_fd, buffer.as_mut_ptr() as *mut _, buffer.len());

        // 읽어온 데이터가 없거나(0) 에러(-1)인 경우 소켓을 닫고 함수를 종료.
        if bytes_read <= 0 {
            close(client_fd);
            return;
        }

        // 읽어온 바이트 슬라이스를 UTF-8 문자열로 변환.
        let request = String::from_utf8_lossy(&buffer[..bytes_read as usize]).to_string();

        // 요청의 첫 번째 줄(메서드 경로 HTTP버전)을 가져옴. 줄이 없으면 빈 문자열.
        let first_line = request.lines().next().unwrap_or("");
        // 첫 번째 줄을 공백 기준으로 분할.
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        // 최소한 메서드, 경로, HTTP 버전이 있어야하니 3개 이상이어야 함.
        if parts.len() >= 3 {
            let method = parts[0]; // HTTP 메서드
            let full_path = parts[1]; // 요청 경로 (쿼리 스트링 포함)

            // 요청을 포워딩할 대상 서버의 기본 정보. (로컬호스트 8080 포트, 기본 경로 "/")
            let mut target_ip = "127.0.0.1";
            let mut target_port = 8080;
            let mut target_path = "/";

            // 전체 경로(full_path)에서 '?' 문자를 찾아 쿼리 스트링이 있는지 확인.
            if let Some(qmark) = full_path.find('?') {
                // '?' 이후 부분이 쿼리 스트링.
                let query = &full_path[qmark + 1..];
                // 쿼리 스트링을 '&' 문자로 분할하여 각 매개변수를 얻음.
                for param in query.split('&') {
                    // 각 매개변수를 '=' 문자로 분할하여 키와 값을 얻음.
                    let kv: Vec<&str> = param.split('=').collect();
                    // 키-값 쌍이 제대로 분할되었는지 확인
                    if kv.len() == 2 {
                        // 매개변수 키에 따라 대상 IP, 포트, 경로 값을 업데이트.
                        match kv[0] {
                            "target_ip" => target_ip = kv[1],
                            "target_port" => {
                                // 포트 값을 u16으로 파싱하고 성공하면 업데이트.
                                if let Ok(p) = kv[1].parse::<u16>() {
                                    target_port = p;
                                }
                            }
                            "path" => target_path = kv[1],
                            _ => {} // 다른 매개변수는 무시.
                        }
                    }
                }
            }

            // 요청 경로가 "/send"로 시작하는 경우에만 요청을 대상 서버로 포워딩.
            if full_path.starts_with("/send") {
                // OPTIONS 메서드 요청인 경우 CORS 사전 응답을 보냄.
                if method == "OPTIONS" {
                    let response = "HTTP/1.1 204 No Content\r\n\
                                    Access-Control-Allow-Origin: *\r\n\
                                    Access-Control-Allow-Methods: GET, POST, PUT, HEAD, OPTIONS\r\n\
                                    Access-Control-Allow-Headers: Content-Type\r\n\
                                    Content-Length: 0\r\n\
                                    Connection: close\r\n\r\n";
                    // 클라이언트 소켓에 응답을 씀. 쓰기 실패는 무시.
                    let _ = write(client_fd, response.as_ptr() as *const _, response.len());
                } else {
                    // OPTIONS 외의 메서드인 경우 요청 본문을 추출.
                    // HTTP 요청은 헤더와 본문이 "\r\n\r\n"으로 구분.
                    // split("\r\n\r\n")의 두 번째 요소(인덱스 1)가 본문. 없으면 빈 문자열.
                    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");

                    // send_request_forward 함수를 호출하여 대상 서버로 요청을 포워딩하고 응답을 받아옴.
                    match send_request_forward(method, body, target_ip, target_port, target_path) {
                        Ok(response_body) => {
                            // 대상 서버로부터 응답을 성공적으로 받은 경우
                            // 클라이언트에게 보낼 HTTP 응답 헤더를 생성. (200 OK 상태)
                            let header = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                response_body.len() // 받은 응답 본문의 길이를 Content-Length에 설정
                            );
                            // 헤더를 클라이언트에게 씀.
                            let _ = write(client_fd, header.as_ptr() as *const _, header.len());
                            // HEAD 메서드가 아닌 경우에만 받은 응답 본문을 클라이언트에게 씀.
                            if method != "HEAD" {
                                let _ = write(
                                    client_fd,
                                    response_body.as_ptr() as *const _,
                                    response_body.len(),
                                );
                            }
                        }
                        Err(e) => {
                            // 대상 서버 연결 또는 요청/응답 처리 중 오류가 발생한 경우
                            // 클라이언트에게 500 Internal Server Error 응답을 보냄.
                            let body = format!("Forwarding Error: {}", e); // 오류 메시지를 응답 본문에 포함
                            // 500 에러 상태 라인과 오류 메시지 길이를 포함한 헤더 생성
                            let header = format!(
                                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            // 헤더와 본문을 클라이언트에게 씀.
                            let _ = write(client_fd, header.as_ptr() as *const _, header.len());
                            let _ = write(client_fd, body.as_ptr() as *const _, body.len());
                        }
                    }
                }
            } else if request.starts_with("GET / ") {
                // 요청이 "GET / " (루트 경로 GET 요청)인 경우 index.html 파일을 서빙. (Web UI)
                match fs::read_to_string("index.html") {
                    // index.html 파일의 내용을 읽음.
                    Ok(content) => {
                        // 파일 읽기 성공 시 200 OK 응답 헤더를 생성.
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
                            content.len() // 읽어온 파일 내용의 길이
                        );
                        // 헤더를 클라이언트에게 씀.
                        let _ = write(client_fd, header.as_ptr() as *const _, header.len());
                        // 파일 내용을 클라이언트에게 씀.
                        let _ = write(client_fd, content.as_ptr() as *const _, content.len());
                    }
                    Err(e) => {
                        // 파일 읽기 실패 시 500 Internal Server Error 응답을 보냄.
                        let body = format!("Error reading index.html: {}", e); // 오류 메시지를 본문에 포함
                        // 500 에러 헤더 생성
                        let header = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
                            body.len()
                        );
                        // 헤더와 본문을 클라이언트에게 씀.
                        let _ = write(client_fd, header.as_ptr() as *const _, header.len());
                        let _ = write(client_fd, body.as_ptr() as *const _, body.len());
                    }
                }
            } else {
                // "/send" 요청도 아니고 "GET / " 요청도 아닌 경우 404 Not Found 응답을 보냄.
                let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
                // 404 응답을 클라이언트에게 씀. (본문 없음)
                let _ = write(client_fd, response.as_ptr() as *const _, response.len());
            }
        } else {
            // 요청 라인이 최소한 3개 부분으로 분할되지 않은 경우 (잘못된 형식의 요청) 400 Bad Request 응답을 보냄.
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
            // 400 응답을 클라이언트에게 씀. (본문 없음)
            let _ = write(client_fd, response.as_ptr() as *const _, response.len());
        }
        // 클라이언트와의 통신이 끝났으므로 클라이언트 소켓을 닫음.
        close(client_fd);
    }
}

// 메인 서버 함수.
fn main() -> io::Result<()> {
    unsafe {
        // 서버 소켓을 생성 (IPv4, TCP).
        let server_fd = socket(AF_INET, SOCK_STREAM, 0);
        // 소켓 생성 실패 시 에러 반환 후 종료.
        if server_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // 소켓 옵션 설정: 주소 재사용 (SO_REUSEADDR) 옵션을 켬.
        let opt: i32 = 1; // 옵션 값 (활성화: 1)
        setsockopt(
            server_fd,                     // 소켓 디스크립터
            SOL_SOCKET,                    // 소켓 레벨 옵션
            SO_REUSEADDR,                  // 재사용 옵션
            &opt as *const _ as *const _,  // 옵션 값에 대한 포인터
            mem::size_of_val(&opt) as u32, // 옵션 값의 크기
        );

        // 서버가 바인딩할 주소 구조체를 설정. (127.0.0.1:8081)
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,      // 주소 체계 (IPv4)
            sin_port: (8081 as u16).to_be(), // 포트 8081 (네트워크 바이트 순서)
            sin_addr: in_addr {
                s_addr: htonl(0x7F000001), // 127.0.0.1 IP 주소 (네트워크 바이트 순서). 16진수로 표현되어있음.
            },
            sin_zero: [0; 8], // 패딩
        };

        // 소켓에 주소와 포트를 바인딩.
        let ret = bind(
            server_fd,                            // 바인딩할 소켓 디스크립터
            &addr as *const _ as *const sockaddr, // 주소 구조체 포인터
            mem::size_of::<sockaddr_in>() as u32, // 주소 구조체 크기
        );
        // 바인딩 실패 시 에러 반환 후 종료하고 소켓을 닫음.
        if ret < 0 {
            close(server_fd);
            return Err(io::Error::last_os_error());
        }

        // 소켓을 연결 대기 상태로 만듦.
        if listen(server_fd, 128) < 0 {
            // 최대 128개의 연결 요청을 큐에 대기
            // listen 실패 시 에러 반환 후 종료하고 소켓을 닫음.
            close(server_fd);
            return Err(io::Error::last_os_error());
        }

        println!("웹 서버가 http://127.0.0.1:8081 에서 시작되었습니다.");

        // 무한 루프: 요청을 계속 받음.
        loop {
            // 연결 요청을 수락.
            let client_fd = accept(server_fd, ptr::null_mut(), ptr::null_mut());

            // 연결 수락 실패 시 에러 메시지를 출력하고 넘어감.
            if client_fd < 0 {
                eprintln!("클라이언트 연결 수락 실패: {}", io::Error::last_os_error());
                continue;
            }

            // 새 스레드를 생성하여 현재 연결 요청을 처리.
            // move 로 client_fd의 소유권을 새 스레드로 이동.
            thread::spawn(move || {
                handle_client(client_fd); // 새 스레드에서 handle_client 함수 실행
            });
        }
    }
}
