use std::fs;
use std::io::{self, Read, Write};
use std::mem;
use std::ptr;
use std::os::unix::io::RawFd;
use std::thread;
use libc::*;

struct Socket {
    fd: RawFd,
}

impl Socket {
    pub fn connect(ip: u32, port: u16) -> io::Result<Self> {
        let sock = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: in_addr { s_addr: ip.to_be() },
            sin_zero: [0; 8],
        };
        let res = unsafe {
            connect(sock, &addr as *const _ as *const sockaddr, mem::size_of::<sockaddr_in>() as u32)
        };
        if res < 0 {
            unsafe { close(sock); }
            return Err(io::Error::last_os_error());
        }
        Ok(Socket { fd: sock })
    }
}

impl io::Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let res = libc::write(self.fd, buf.as_ptr() as *const _, buf.len());
            if res < 0 { Err(io::Error::last_os_error()) } else { Ok(res as usize) }
        }
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl io::Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let res = libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len());
            if res < 0 { Err(io::Error::last_os_error()) } else { Ok(res as usize) }
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { close(self.fd); }
    }
}

// send_request_forward: target 서버(ip, port)로 메서드와 body를 포함한 요청을 보냅니다.
fn send_request_forward(method: &str, request_body: &str, target_ip: &str, target_port: u16, target_path: &str) -> io::Result<String> {
    // 입력받은 target_ip 문자열을 Ipv4Addr로 파싱
    let ip_addr: std::net::Ipv4Addr = target_ip.parse().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let ip_u32 = u32::from(ip_addr);
    let mut socket = Socket::connect(ip_u32, target_port)?;
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, target_path, target_ip
    );
    if method == "POST" || method == "PUT" {
        req.push_str(&format!("Content-Length: {}\r\n", request_body.len()));
        req.push_str("\r\n");
        req.push_str(request_body);
    } else {
        req.push_str("\r\n");
    }
    socket.write_all(req.as_bytes())?;
    let mut buffer = [0; 1024];
    let n = socket.read(&mut buffer)?;
    if n > 0 {
        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    } else {
        Ok("응답 없음".to_string())
    }
}

// 클라이언트 연결 처리 웹 ui
fn handle_client(client_fd: RawFd) {
    let mut buffer = [0u8; 2048];
    unsafe {
        // 요청 읽기
        let bytes_read = read(client_fd, buffer.as_mut_ptr() as *mut _, buffer.len());
        if bytes_read <= 0 {
            close(client_fd);
            return;
        }
        let request = String::from_utf8_lossy(&buffer[..bytes_read as usize]).to_string();
        let first_line = request.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() >= 3 {
            let method = parts[0]; // GET, POST, HEAD, PUT 등
            let full_path = parts[1]; // 예: "/send?target_ip=1.2.3.4&target_port=8080&path=user"
            // 기본 목표 서버 정보 및 기본 path 값
            let mut target_ip = "127.0.0.1";
            let mut target_port = 8080;
            let mut target_path = "/";  // default
            
            if let Some(qmark) = full_path.find('?') {
                // full_path의 "?" 이전은 경로 (예: "/send")
                let _ = &full_path[..qmark]; // 사용하지 않음
                let query = &full_path[qmark + 1..];
                for param in query.split('&') {
                    let kv: Vec<&str> = param.split('=').collect();
                    if kv.len() == 2 {
                        match kv[0] {
                            "target_ip" => target_ip = kv[1],
                            "target_port" => {
                                if let Ok(p) = kv[1].parse::<u16>() {
                                    target_port = p;
                                }
                            },
                            "path" => target_path = kv[1],
                            _ => {},
                        }
                    }
                }
            }
            // 아래 path가 "/send" 인 경우에만 타겟 서버로 요청 전달
            if full_path.starts_with("/send") {
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                match send_request_forward(method, body, target_ip, target_port, target_path) {
                    Ok(response) => {
                        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", response.len());
                        let _ = write(client_fd, header.as_ptr() as *const _, header.len());
                        if method != "HEAD" {
                            let _ = write(client_fd, response.as_ptr() as *const _, response.len());
                        }
                    },
                    Err(e) => {
                        let body = format!("연결 오류: {}", e);
                        let header = format!("HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n", body.len());
                        let _ = write(client_fd, header.as_ptr() as *const _, header.len());
                        let _ = write(client_fd, body.as_ptr() as *const _, body.len());
                    }
                }
            } else if request.starts_with("GET / ") {
                // index.html 요청 처리
                match fs::read_to_string("index.html") {
                    Ok(content) => {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n", 
                            content.len()
                        );
                        let _ = write(client_fd, header.as_ptr() as *const _, header.len());
                        let _ = write(client_fd, content.as_ptr() as *const _, content.len());
                    },
                    Err(e) => {
                        let body = format!("index.html 파일 읽기 오류: {}", e);
                        let header = format!("HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n", body.len());
                        let _ = write(client_fd, header.as_ptr() as *const _, header.len());
                        let _ = write(client_fd, body.as_ptr() as *const _, body.len());
                    }
                }
            } else {
                // 지원하지 않는 요청
                let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                let _ = write(client_fd, response.as_ptr() as *const _, response.len());
            }
        } else {
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            let _ = write(client_fd, response.as_ptr() as *const _, response.len());
        }
        close(client_fd);
    }
}

fn main() -> io::Result<()> {
    unsafe {
        // 서버 소켓 생성
        let server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if server_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // 주소 재사용 옵션 설정
        let opt: i32 = 1;
        setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &opt as *const _ as *const _,
            mem::size_of_val(&opt) as u32,
        );
        // 주소 구조체 설정 (127.0.0.1:8081)
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: (8081 as u16).to_be(),
            sin_addr: in_addr { s_addr: htonl(0x7F000001) },
            sin_zero: [0; 8],
        };
        let ret = bind(
            server_fd,
            &addr as *const _ as *const sockaddr,
            mem::size_of::<sockaddr_in>() as u32,
        );
        if ret < 0 {
            close(server_fd);
            return Err(io::Error::last_os_error());
        }
        if listen(server_fd, 128) < 0 {
            close(server_fd);
            return Err(io::Error::last_os_error());
        }
        
        println!("웹 서버가 http://127.0.0.1:8081 에서 시작되었습니다.");
        
        loop {
            // 클라이언트 연결 수락 (client address는 사용하지 않음)
            let client_fd = accept(server_fd, ptr::null_mut(), ptr::null_mut());
            if client_fd < 0 {
                eprintln!("클라이언트 연결 수락 실패: {}", io::Error::last_os_error());
                continue;
            }
            // 별도 스레드에서 연결 처리
            thread::spawn(move || { handle_client(client_fd); });
        }
    }
}