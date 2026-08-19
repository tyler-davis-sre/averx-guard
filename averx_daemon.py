import socket, threading, re, time

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9090

# Core detection patterns: common API keys & secrets
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),               # AWS Access Key
    re.compile(r"sk-proj-[a-zA-Z0-9_-]{32,}"),      # OpenAI API Key
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),             # GitHub PAT
]

RED = "\033[91m"; GREEN = "\033[92m"; BOLD = "\033[1m"; RESET = "\033[0m"

def handle_client(client_sock):
    try:
        raw_request = client_sock.recv(4096)
        if not raw_request:
            client_sock.close()
            return

        text = raw_request.decode('utf-8', errors='ignore')
        t0 = time.perf_counter()

        # Check for canary secrets in raw payload
        secret_found = any(p.search(text) for p in SECRET_PATTERNS)
        elapsed_us = (time.perf_counter() - t0) * 1_000_000

        if secret_found:
            print(f" {RED}[BLOCKED]{RESET} Canary secret detected in payload! ({elapsed_us:.1f}µs overhead) -> Dropping connection.")
            # Return HTTP 403 Forbidden with security header
            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Server: AverxGuard/0.1\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n\r\n"
                "Blocked by Averx: Secret detected in outbound egress payload.\n"
            )
            client_sock.sendall(response.encode('utf-8'))
        else:
            print(f" {GREEN}[ALLOWED]{RESET} Payload clean ({elapsed_us:.1f}µs overhead).")
            client_sock.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
    except Exception as e:
        pass
    finally:
        client_sock.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(10)
    print(f"\n{BOLD}=== AVERX GUARD DAEMON (v0.1-alpha) ==={RESET}")
    print(f"Listening on {LISTEN_HOST}:{LISTEN_PORT} [Sub-millisecond loopback filtering active]\n")
    
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    main()
