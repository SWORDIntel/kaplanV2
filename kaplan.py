#!/usr/bin/env python3

import requests
import time
import re
import os
from pathlib import Path
from urllib.parse import urlparse, unquote
from stem import Signal
from stem.control import Controller
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import logging
from datetime import datetime


class TorDownloader:
    def __init__(self, 
                 tor_proxy_port=9050, 
                 tor_control_port=9051, 
                 tor_password=None,
                 download_dir="downloads",
                 max_workers=3,
                 max_retries=3,
                 retry_delay=5):
        
        self.tor_proxy_port = tor_proxy_port
        self.tor_control_port = tor_control_port
        self.tor_password = tor_password
        self.download_dir = Path(download_dir)
        self.max_workers = max_workers
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        self.download_dir.mkdir(exist_ok=True)
        
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
        self.setup_logging()
        
        self.tor_lock = Lock()
        
        self.proxies = {
            'http': f'socks5h://127.0.0.1:{tor_proxy_port}',
            'https': f'socks5h://127.0.0.1:{tor_proxy_port}'
        }
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    
    def setup_logging(self):
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"download_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Log-File: {log_file}")
    
    def renew_tor_identity(self):
       
        with self.tor_lock:
            try:
                with Controller.from_port(port=self.tor_control_port) as controller:
                    if self.tor_password:
                        controller.authenticate(password=self.tor_password)
                    else:
                        controller.authenticate()
                    
                    controller.signal(Signal.NEWNYM)
                    self.logger.info("Tor identity updated")
                    
                    time.sleep(5)
                    return True
                    
            except Exception as e:
                self.logger.error(f"Error updating Tor identity: {e}")
                return False
    
    def check_tor_connection(self):
        
        try:
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=self.proxies,
                timeout=10
            )
            data = response.json()
            
            if data.get('IsTor'):
                self.logger.info(f"The connection via Tor is active. IP: {data.get('IP')}")
                return True
            else:
                self.logger.warning(f"The connection is NOT via Tor! IP: {data.get('IP')}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking Tor: {e}")
            return False
    
    def extract_filename_from_url(self, url):
        
        parsed = urlparse(url)
        filename = unquote(os.path.basename(parsed.path))
        
        if not filename or filename == '':
            filename = f"file_{abs(hash(url))}"
        
        return filename
    
    def download_file_with_retry(self, url, custom_filename=None):
        
        for attempt in range(1, self.max_retries + 1):
            try:
                self.logger.info(f"Attempt {attempt}/{self.max_retries} для {url}")
                
                if not self.renew_tor_identity():
                    self.logger.warning("Couldn't update identity, continue...")
                
                result = self.download_file(url, custom_filename)
                
                if result:
                    self.logger.info(f"Successfully downloaded: {url}")
                    return (True, result, None)
                else:
                    raise Exception("The download file returned None")
                    
            except Exception as e:
                error_msg = f"Error on attempt {attempt}: {str(e)}"
                self.logger.warning(error_msg)
                
                if attempt < self.max_retries:
                    self.logger.info(f"Waiting for {self.retry_delay} seconds before the next attempt...")
                    time.sleep(self.retry_delay)
                else:
                    self.logger.error(f"All attempts have been exhausted for {url}")
                    return (False, None, str(e))
        
        return (False, None, "Exceeded the number of attempts")
    
    def download_file(self, url, custom_filename=None):
       
        try:
            self.logger.info(f"Download Start: {url}")
            
            response = requests.get(
                url,
                proxies=self.proxies,
                headers=self.headers,
                stream=True,
                timeout=60
            )
            response.raise_for_status()
            
            if custom_filename:
                filename = custom_filename
            else:

                content_disp = response.headers.get('Content-Disposition', '')
                if 'filename=' in content_disp:
                    match = re.findall(r'filename[^;=\n]*=(([\'"]).*?\2|[^;\n]*)', content_disp)
                    if match:
                        filename = match[0][0].strip('"\'')
                    else:
                        filename = self.extract_filename_from_url(url)
                else:
                    filename = self.extract_filename_from_url(url)
            
            
            filepath = self.download_dir / filename
            
            if filepath.exists():
                base = filepath.stem
                ext = filepath.suffix
                counter = 1
                while filepath.exists():
                    filepath = self.download_dir / f"{base}_{counter}{ext}"
                    counter += 1
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                           
                            if downloaded % (total_size // 10 + 1) < 8192:
                                self.logger.debug(f"Прогресс {filename}: {percent:.1f}%")
            
            self.logger.info(f"The file is saved: {filepath}")
            return filepath
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Download error {url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return None
    
    def load_urls_from_file(self, filepath):
       
        urls = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                   
                    if line and not line.startswith('#'):
                        
                        if line.startswith('http://') or line.startswith('https://'):
                            urls.append(line)
            
            self.logger.info(f"Uploaded {len(urls)} URL from the file")
            return urls
            
        except Exception as e:
            self.logger.error(f"File reading error: {e}")
            return []
    
    def download_all_sequential(self, urls):
       
        total = len(urls)
        successful = 0
        failed = 0
        
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Start of sequential download of {total} files")
        self.logger.info(f"{'='*60}")
        
        for idx, url in enumerate(urls, 1):
            self.logger.info(f"File {idx}/{total}")
            
            success, filepath, error = self.download_file_with_retry(url)
            
            if success:
                successful += 1
            else:
                failed += 1
                self.logger.error(f"Не удалось скачать {url}: {error}")
            
            if idx < total:
                time.sleep(2)
        
        self._print_statistics(total, successful, failed)
    
    def download_all_parallel(self, urls):
       
        total = len(urls)
        successful = 0
        failed = 0
        
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Start of parallel download of {total} files")
        self.logger.info(f"Number of threads: {self.max_workers}")
        self.logger.info(f"{'='*60}")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            
            future_to_url = {
                executor.submit(self.download_file_with_retry, url): url 
                for url in urls
            }
            
            
            for idx, future in enumerate(as_completed(future_to_url), 1):
                url = future_to_url[future]
                try:
                    success, filepath, error = future.result()
                    
                    if success:
                        successful += 1
                        self.logger.info(f"[{idx}/{total}] ✓ Успешно: {url}")
                    else:
                        failed += 1
                        self.logger.error(f"[{idx}/{total}] ✗ Ошибка: {url} - {error}")
                        
                except Exception as e:
                    failed += 1
                    self.logger.error(f"[{idx}/{total}] ✗ Исключение для {url}: {e}")
        
        self._print_statistics(total, successful, failed)
    
    def _print_statistics(self, total, successful, failed):
       
        self.logger.info(f"{'='*60}")
        self.logger.info(f"The download is complete!")
        self.logger.info(f"Successfully: {successful}/{total}")
        self.logger.info(f"Errors: {failed}/{total}")
        self.logger.info(f"Files are saved in: {self.download_dir.absolute()}")
        self.logger.info(f"{'='*60}")


def main():
    
    print("""


.--.   .--.             ____            .-------.           .---.                ____            ,---.   .--. 
|  | _/  /            .'  __ `.         \  _(`)_ \          | ,_|              .'  __ `.         |    \  |  | 
| (`' ) /            /   '  \  \        | (_ o._)|        ,-./  )             /   '  \  \        |  ,  \ |  | 
|(_ ()_)             |___|  /  |        |  (_,_) /        \  '_ '`)           |___|  /  |        |  |\_ \|  | 
| (_,_)   __            _.-`   |        |   '-.-'          > (_)  )              _.-`   |        |  _( )_\  | 
|  |\ \  |  |        .'   _    |        |   |             (  .  .-'           .'   _    |        | (_ o _)  | 
|  | \ `'   /        |  _( )_  |        |   |              `-'`-'|___         |  _( )_  |        |  (_,_)\  | 
|  |  \    /         \ (_ o _) /        /   )               |        \        \ (_ o _) /        |  |    |  | 
`--'   `'-'           '.(_,_).'         `---'               `--------`         '.(_,_).'         '--'    '--' 
                                                                                                              
           Tor Document Downloader v1.0 (Multithreaded) by KL3FT3Z (https://github.com/toxy4ny)       

    """)
    
    URLS_FILE = "urls.txt"              
    DOWNLOAD_DIR = "downloads"          
    TOR_CONTROL_PORT = 9051             
    TOR_PROXY_PORT = 9050               
    TOR_PASSWORD = None                
    MAX_WORKERS = 3                    
    MAX_RETRIES = 3                   
    RETRY_DELAY = 5                    
    
    
    MODE = 'parallel'                   

    downloader = TorDownloader(
        tor_proxy_port=TOR_PROXY_PORT,
        tor_control_port=TOR_CONTROL_PORT,
        tor_password=TOR_PASSWORD,
        download_dir=DOWNLOAD_DIR,
        max_workers=MAX_WORKERS,
        max_retries=MAX_RETRIES,
        retry_delay=RETRY_DELAY
    )
    
   
    print("[*] Checking the connection to Tor...")
    if not downloader.check_tor_connection():
        print("[!] WARNING: Tor may not be active!")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            return
    
    urls = downloader.load_urls_from_file(URLS_FILE)
    
    if not urls:
        print("[!] No download URL found")
        print(f"[*] Create a file '{URLS_FILE}' and add links (one per line)")
        return
    
    try:
        start_time = time.time()
        
        if MODE == 'parallel':
            downloader.download_all_parallel(urls)
        else:
            downloader.download_all_sequential(urls)
        
        elapsed_time = time.time() - start_time
        print(f"\n[*] Total execution time: {elapsed_time:.2f} seconds")
        
    except KeyboardInterrupt:
        print("\n\n[!] The download was interrupted by the user")


if __name__ == "__main__":
    main()
