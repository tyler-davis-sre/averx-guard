import os, sys, urllib.request, urllib.error, json, time

RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; BOLD = "\033[1m"; RESET = "\033[0m"

CANARY_SECRETS = {
    "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
    "OPENAI_API_KEY": "sk-proj-CANARY99887766554433221100aabbccddeeff",
    "GITHUB_PAT": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
}
# Fast, reliable HTTPS echo endpoint for egress verification
TEST_EXTERNAL_ENDPOINT = "http://httpbin.org/post"

def print_banner():
    print(f"\n{BOLD}=== AVERX GUARD // AGENT EGRESS AUDIT BENCHMARK ==={RESET}")
    print(f"Auditing local subshell & agent network boundaries...\n")

def run_audit():
    print_banner()
    score = 10
    results = []

    # 1. Test Environment Variable Exfiltration Risk
    exposed_env = [k for k, v in CANARY_SECRETS.items() if k in os.environ]
    if exposed_env:
        results.append((f"{RED}[FAIL]{RESET} Raw credentials active in environment", f"Exposed: {', '.join(exposed_env)}", -3))
        score -= 3
    else:
        results.append((f"{GREEN}[PASS]{RESET} No canary secrets in active environment", "Standard isolation", 0))

    # 2. Test Unrestricted Outbound Network Egress (HTTP POST with canary payload)
    payload = json.dumps({"agent_id": "test-runner", "canary": CANARY_SECRETS["AWS_ACCESS_KEY"]}).encode('utf-8')
    req = urllib.request.Request(
        TEST_EXTERNAL_ENDPOINT, 
        data=payload, 
        headers={"Content-Type": "application/json", "User-Agent": "AverxAudit/1.0"}
    )
    
    try:
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=5) as resp:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            results.append((f"{RED}[CRITICAL]{RESET} Unrestricted outbound egress permitted", f"Payload reached external host ({elapsed_ms:.1f}ms)", -5))
            score -= 5
    except urllib.error.HTTPError as e:
        if e.code == 403:
            results.append((f"{GREEN}[BLOCKED]{RESET} Egress blocked by firewall policy", "HTTP 403 Forbidden received", 0))
        else:
            results.append((f"{RED}[CRITICAL]{RESET} Payload reached external server", f"Server responded with HTTP {e.code}", -5))
            score -= 5
    except urllib.error.URLError as e:
        results.append((f"{GREEN}[BLOCKED]{RESET} Outbound egress blocked or dropped", f"Connection dropped ({e.reason})", 0))
    except (TimeoutError, TimeoutException) if 'TimeoutException' in globals() else TimeoutError:
        results.append((f"{RED}[CRITICAL]{RESET} Unrestricted outbound egress attempted", "External request sent (Timed out waiting for response)", -5))
        score -= 5

    # 3. Test Proxy Invariant Enforcement
    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not http_proxy or "127.0.0.1" not in http_proxy:
        results.append((f"{YELLOW}[WARN]{RESET} No local loopback proxy detected in shell", "Subshell traffic is unmonitored", -2))
        score -= 2
    else:
        results.append((f"{GREEN}[PASS]{RESET} Loopback proxy enforcement active", f"Bound to {http_proxy}", 0))

    # Render Scorecard
    for status, detail, _ in results:
        print(f" {status:<40} -> {detail}")
    
    color = GREEN if score >= 8 else (YELLOW if score >= 5 else RED)
    print(f"\n{BOLD}--------------------------------------------------{RESET}")
    print(f" Overall Security Posture Score: {color}{score}/10{RESET}")
    if score < 8:
        print(f" {RED}RISK: Local coding agents can freely exfiltrate tokens.{RESET}")
    print(f"{BOLD}--------------------------------------------------{RESET}\n")

if __name__ == "__main__":
    run_audit()
