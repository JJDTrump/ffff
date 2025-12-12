
# 读取文件扫描，格式1.1.1.1:443

import requests
import random
from uuid import uuid4
from datetime import datetime, timedelta
import argparse
import threading
import concurrent.futures
import os
from queue import Queue
import time

banner = """\
             __         ___  ___________
     __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________
     \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\\\|    | /  _ \\ \\/ \\/ \\_  __ \\
      \\     / / __ \\|  | \\  \\\\___|   Y  |    |(  <_> \\     / |  | \\\n       \\/\\_/ (____  |__|  \\\\\\\___  |___|__|__  | \\\\__  / \\\/\\_/  |__|
                  \\\          \\\     \\\

        CVE-2024-55591.py
        (*) Fortinet FortiOS Authentication Bypass (CVE-2024-55591) vulnerable detection by watchTowr

          - Sonny , watchTowr (sonny@watchTowr.com)
          - Aliz Hammond, watchTowr (aliz@watchTowr.com)

        CVEs: [CVE-2024-55591]
"""

# Global variables for results tracking
results_lock = threading.Lock()
results = {
    'vulnerable': [],
    'not_vulnerable': [],
    'error': []
}
# 新增：文件写入锁
file_lock = threading.Lock()
output_file = "scan_results.txt"

def generate_random_suffix(length=6):
    """Generate a random lowercase suffix."""
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(length))

def perform_web_interaction(target, port):
    """
    Perform a two-step web interaction with specific parameters.

    Args:
        target (str): Target IP address
        port (int): Target port

    Returns:
        tuple: Results of the two requests
    """
    # Construct base URL
    base_url = f"https://{target}:{port}"

    # Generate random suffix
    random_suffix = generate_random_suffix()

    # Disable SSL verification warnings
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    # First request - login-like endpoint
    first_url = f"{base_url}/login?redir=/ng"
    first_response = requests.get(first_url, verify=False, timeout=10)

    # Second request - endpoint with random suffix
    second_url = f"{base_url}/watchTowr-{random_suffix}"
    second_headers = {
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': 'thFz/fKwzu5wDEy0XO3fcw==',
        'Connection': 'keep-alive, Upgrade',
        'Upgrade': 'websocket'
    }
    second_response = requests.get(second_url, headers=second_headers, verify=False, timeout=10)

    return first_response, second_response

def validate_interaction_conditions(first_response, second_response):
    """
    Validate specific conditions for the web interaction.

    Args:
        first_response (requests.Response): First HTTP response
        second_response (requests.Response): Second HTTP response

    Returns:
        bool: Whether all conditions are met
    """
    try:
        # Check status codes
        status_code_1_check = first_response.status_code == 200
        status_code_2_check = second_response.status_code == 101

        # Check body contents for first response
        html_main_app_check = '<html class="main-app">' in first_response.text
        f_icon_warning_check = '<f-icon class="fa-warning' in first_response.text
        f_icon_closing_check = '</f-icon>' in first_response.text

        body_checks = html_main_app_check and f_icon_warning_check and f_icon_closing_check

        # Check for specific header marker
        header_marker_check = any('APSCOOKIE_' in str(header) for header in first_response.headers.values())

        # Check connection upgrade for second response
        connection_upgrade_check = 'Upgrade' in second_response.headers.get('Connection', '')

        # Skip exiting on non-FortiOS targets in multi-threaded mode
        if not html_main_app_check:
            return False

        if not f_icon_warning_check:
            return False

        # Combine all checks
        return all([
            status_code_1_check,
            status_code_2_check,
            body_checks,
            header_marker_check,
            connection_upgrade_check
        ])
    except Exception as e:
        return False

# 实时写入结果到文件
def write_result_to_file(result_type, data):
    """
    实时写入结果到文件
    
    Args:
        result_type (str): 结果类型 (vulnerable/error)
        data (str): 要写入的数据
    """
    with file_lock:
        try:
            with open(output_file, 'a') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if result_type == 'vulnerable':
                    f.write(f"[{timestamp}] [VULNERABLE] {data}\n")
                f.flush()  # 立即刷新缓冲区
        except Exception as e:
            print(f"[!] Error writing to file: {str(e)}")

def check_single_target(target, port):
    """
    Check a single target and record the result.

    Args:
        target (str): Target IP address
        port (int): Target port
    """
    try:
        first_response, second_response = perform_web_interaction(target, port)

        result = validate_interaction_conditions(first_response, second_response)

        with results_lock:
            if result:
                print(f"[!] VULNERABLE: {target}:{port}")
                results['vulnerable'].append(f"{target}:{port}")
                # 实时写入漏洞结果
                write_result_to_file('vulnerable', f"{target}:{port}")

    except requests.RequestException as e:
        with results_lock:
            error_msg = f"{target}:{port} - {str(e)}"
            # print(f"[!] Request error for {error_msg}")
            results['error'].append(error_msg)
            # 删除错误结果的写入
    except Exception as e:
        with results_lock:
            error_msg = f"{target}:{port} - {str(e)}"
            # print(f"[!] Unexpected error for {error_msg}")
            results['error'].append(error_msg)
            # 删除错误结果的写入

def read_targets_from_file(filename, default_port):
    if not os.path.exists(filename):
        print(f"[!] File not found: {filename}")
        return []

    targets = []
    with open(filename, 'r') as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            if ':' in s:
                host, port_str = s.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = default_port
                targets.append((host.strip(), port))
            else:
                targets.append((s, default_port))
    return targets

def save_summary(output_file):
    """
    Save the scan summary to a file.

    Args:
        output_file (str): Path to the output file
    """
    with file_lock:
        with open(output_file, 'a') as f:
            f.write("\n===== VULNERABLE TARGETS SUMMARY =====\n")
            f.write(f"Total vulnerable: {len(results['vulnerable'])}\n")
            
            # 只写入漏洞目标列表，不写入其他统计信息
            if results['vulnerable']:
                f.write("\n=== VULNERABLE TARGETS LIST ===\n")
                for target in results['vulnerable']:
                    f.write(f"{target}\n")

def main():
    """
    Main function to run the web interaction checks.
    """
    print(banner)

    parser = argparse.ArgumentParser(description='CVE-2024-55591 Detection Tool')
    parser.add_argument('--target', '-t', type=str, help='Target in form ip or ip:port', required=False)
    parser.add_argument('--port', '-p', type=int, help='Default port if not specified', required=False, default=443)
    parser.add_argument('--file', '-f', type=str, help='File with lines in ip:port format', required=False)
    parser.add_argument('--threads', '-th', type=int, help='Number of concurrent threads', default=10)
    parser.add_argument('--output', '-o', type=str, help='Output file for results', default='scan_results.txt')
    args = parser.parse_args()

    # 设置全局输出文件名
    global output_file
    output_file = args.output
    
    # 初始化输出文件
    with open(output_file, 'w') as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"===== FORTINET CVE-2024-55591 VULNERABLE TARGETS ===== {timestamp} =====\n\n")

    # Validate arguments
    if not args.target and not args.file:
        print("[!] Error: Either --target or --file must be specified")
        parser.print_help()
        return

    # If single target mode
    if args.target:
        if ':' in args.target:
            host, port_str = args.target.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = args.port
            check_single_target(host, port)
        else:
            check_single_target(args.target, args.port)
        return

    # Batch mode from file
    targets = read_targets_from_file(args.file, args.port)
    if not targets:
        print("[!] No valid targets found in the file")
        return

    print(f"[*] Loaded {len(targets)} targets from {args.file}")
    print(f"[*] Starting scan with {args.threads} threads")
    print(f"[*] Results being written in real-time to {output_file}")

    start_time = time.time()

    # Use ThreadPoolExecutor for parallel execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(check_single_target, host, port) for (host, port) in targets]
        
        completed = 0
        total = len(targets)
        
        # 显示进度
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            print(f"[*] Progress: {completed}/{total} targets completed ({completed/total*100:.1f}%)", end="\r")

    end_time = time.time()
    scan_duration = end_time - start_time

    print("\n===== SCAN SUMMARY =====")
    print(f"Total targets: {len(targets)}")
    print(f"Vulnerable: {len(results['vulnerable'])}")
    print(f"Not vulnerable: {len(results['not_vulnerable'])}")
    print(f"Errors: {len(results['error'])}")
    print(f"Scan duration: {scan_duration:.2f} seconds")

    # Save final summary to file
    save_summary(args.output)
    print(f"[*] Final results saved to {args.output}")

if __name__ == "__main__":
    main()
