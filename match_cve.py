import requests
import csv
import time
import re
import json
import os
import logging
from urllib.parse import quote_plus
from threading import Lock
from packaging import version
from datetime import datetime, timedelta

logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("cve_scanner_debug.log"),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_FILE = "api_key.txt"
API_KEY = None
EXCLUDED_RESULTS = set()
TEMP_RESULTS_FILE = "temp_cve_results.json"
BATCH_SIZE = 10

class TokenBucket:
    def __init__(self, tokens, fill_rate):
        self.capacity = tokens
        self.tokens = tokens
        self.fill_rate = fill_rate
        self.last_check = time.time()
        self.lock = Lock()

    def get_token(self):
        with self.lock:
            now = time.time()
            time_passed = now - self.last_check
            self.tokens = min(self.capacity, self.tokens + time_passed * self.fill_rate)
            self.last_check = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

    def wait_for_token(self):
        while not self.get_token():
            time.sleep(0.1)

rate_limiter = TokenBucket(100, 100/60)  # 100 tokens per minute

def set_api_key(key):
    global API_KEY
    API_KEY = key
    with open(API_KEY_FILE, "w") as f:
        f.write(key)

def load_api_key():
    global API_KEY
    if API_KEY:
        return API_KEY
    try:
        with open(API_KEY_FILE, "r") as f:
            API_KEY = f.read().strip()
        logger.info(f"API key loaded successfully from {API_KEY_FILE}")
        return API_KEY
    except FileNotFoundError:
        logger.error(f"API key file not found: {API_KEY_FILE}")
        return None

def api_request(url, params, headers, max_retries=3):
    for attempt in range(max_retries):
        try:
            rate_limiter.wait_for_token()
            
            if 'apiKey' not in headers:
                api_key = load_api_key()
                if not api_key:
                    raise ValueError("API key not found or invalid.")
                headers['apiKey'] = api_key

            query_string = '&'.join(f"{k}={quote_plus(str(v))}" for k, v in params.items())
            full_url = f"{url}?{query_string}"
            
            logger.debug(f"Sending request to: {full_url}")
            logger.debug(f"Headers: {headers}")

            response = requests.get(full_url, headers=headers)
            
            logger.debug(f"Response status code: {response.status_code}")
            logger.debug(f"Response content: {response.text[:200]}...")  # First 200 characters

            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)  # Exponential backoff

    raise Exception("Max retries exceeded for API request")

def query_cpes_batch(software_batch, headers, log_callback):
    log_callback(f"Querying CPEs for batch of {len(software_batch)} software items")
    cpe_results = []
    
    for software, version in software_batch:
        params = {
            "keywordSearch": software,
            "resultsPerPage": "5"
        }
        
        try:
            data = api_request(CPE_API_URL, params, headers)
            products = data.get("products", [])
            if products:
                for product in products:
                    cpe = product["cpe"]
                    if software.lower() in cpe["cpeName"].lower():
                        cpe_results.append((software, version, cpe))
            else:
                logger.info(f"No CPE found for {software} {version}")
        except Exception as e:
            logger.error(f"Error querying CPE for {software} {version}: {str(e)}")
    
    return cpe_results

def query_cves_batch(cpe_batch, headers, log_callback):
    log_callback(f"Querying CVEs for batch of {len(cpe_batch)} CPEs")
    cve_results = []
    
    for software, version, cpe in cpe_batch:
        params = {
            "cpeName": cpe['cpeName'],
            "resultsPerPage": "2000"
        }
        
        try:
            data = api_request(CVE_API_URL, params, headers)
            vulnerabilities = data.get("vulnerabilities", [])
            filtered_vulns = []
            for vuln in vulnerabilities:
                cve_data = vuln.get('cve', {})
                if is_vulnerable(version, cve_data):
                    filtered_vulns.append(vuln)
            cve_results.append((software, version, cpe, filtered_vulns))
        except Exception as e:
            logger.error(f"Error querying CVEs for {cpe['cpeName']}: {str(e)}")
    
    return cve_results

def is_vulnerable(installed_version, cve_data):
    try:
        installed = version.parse(installed_version)
        for config in cve_data.get('configurations', []):
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if check_version_range(installed, cpe_match):
                        return True
        return False
    except Exception as e:
        logger.error(f"Error comparing versions: {str(e)}")
        return True  # Assume vulnerable if version comparison fails

def check_version_range(installed, cpe_match):
    start_including = cpe_match.get('versionStartIncluding')
    start_excluding = cpe_match.get('versionStartExcluding')
    end_including = cpe_match.get('versionEndIncluding')
    end_excluding = cpe_match.get('versionEndExcluding')

    if start_including and installed < version.parse(start_including):
        return False
    if start_excluding and installed <= version.parse(start_excluding):
        return False
    if end_including and installed > version.parse(end_including):
        return False
    if end_excluding and installed >= version.parse(end_excluding):
        return False
    return True

def get_severity(metrics):
    if 'cvssMetricV31' in metrics:
        return metrics['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'NONE')
    elif 'cvssMetricV30' in metrics:
        return metrics['cvssMetricV30'][0]['cvssData'].get('baseSeverity', 'NONE')
    elif 'cvssMetricV2' in metrics:
        score = float(metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0))
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
    return 'NONE'

def process_batch(batch, headers, log_callback, progress_callback):
    cpe_results = query_cpes_batch(batch, headers, log_callback)
    progress_callback(0.5)  # Update progress after CPE query
    
    cve_results = query_cves_batch(cpe_results, headers, log_callback)
    progress_callback(1.0)  # Update progress after CVE query
    
    processed_results = []
    for software, installed_version, cpe, vulnerabilities in cve_results:
        cve_list = []
        max_severity = "NONE"
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id')
            metrics = cve_data.get('metrics', {})
            severity = get_severity(metrics)
            
            if cve_id and severity != 'NONE' and cve_id not in EXCLUDED_RESULTS:
                cve_list.append((cve_id, severity))
                if severity_order(severity) > severity_order(max_severity):
                    max_severity = severity
        
        if cve_list:
            cve_list.sort(key=lambda x: severity_order(x[1]), reverse=True)
            most_severe_cve = cve_list[0][0]
            cve_display = most_severe_cve if len(cve_list) == 1 else f"{most_severe_cve} + {len(cve_list) - 1} more"
            processed_results.append((software, installed_version, cve_display, max_severity))
    
    return processed_results

def severity_order(severity):
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    return order.get(severity.upper(), 0)

def calculate_security_score(results):
    severity_weights = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "NONE": 0
    }
    total_weight = sum(severity_weights.get(result[3], 0) for result in results)
    max_weight = len(results) * severity_weights["CRITICAL"]
    if max_weight == 0:
        return 100
    score = 100 - (total_weight / max_weight) * 100
    return max(0, min(100, round(score, 2)))

def save_temp_results(results):
    with open(TEMP_RESULTS_FILE, 'w') as f:
        json.dump(results, f)

def load_temp_results():
    if os.path.exists(TEMP_RESULTS_FILE):
        with open(TEMP_RESULTS_FILE, 'r') as f:
            return json.load(f)
    return []

def main(log_callback, result_callback, progress_callback):
    api_key = load_api_key()
    if not api_key:
        log_callback("API key not found. Please set the API key and try again.")
        return

    headers = {"apiKey": api_key}

    try:
        with open("installed_software.csv", "r") as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # Skip the header row
            software_list = []
            for row in reader:
                if len(row) >= 2:
                    software_list.append((row[0], row[1]))
                else:
                    log_callback(f"Skipping invalid row: {row}")
        
        total_software = len(software_list)
        log_callback(f"Processing {total_software} valid software items...")
        
        batches = [software_list[i:i + BATCH_SIZE] for i in range(0, total_software, BATCH_SIZE)]
        
        results = []
        start_time = time.time()

        for i, batch in enumerate(batches):
            batch_start = time.time()
            log_callback(f"Processing batch {i+1} of {len(batches)}...")
            batch_results = process_batch(batch, headers, log_callback, lambda p: progress_callback((i + p) / len(batches) * 100))
            results.extend(batch_results)
            for result in batch_results:
                result_callback(result)
            
            elapsed = time.time() - start_time
            estimated_total = elapsed / ((i + 1) / len(batches))
            remaining = estimated_total - elapsed
            eta = datetime.now() + timedelta(seconds=remaining)
            log_callback(f"Progress: {((i + 1) / len(batches)):.2%}. Estimated time remaining: {timedelta(seconds=int(remaining))}. ETA: {eta.strftime('%Y-%m-%d %H:%M:%S')}")

        security_score = calculate_security_score(results)
        log_callback(f"Scan completed. Overall Security Score: {security_score}")
        result_callback(("OVERALL_SCORE", "", "", security_score))

        save_temp_results(results)

        end_time = time.time()
        total_duration = end_time - start_time
        log_callback(f"Total scan duration: {total_duration:.2f} seconds")

    except FileNotFoundError:
        logger.error("installed_software.csv file not found. Please make sure it exists in the same directory.")
        log_callback("installed_software.csv file not found. Please make sure it exists in the same directory.")
    except Exception as e:
        logger.error(f"An error occurred while processing the software list: {str(e)}")
        log_callback(f"An error occurred: {str(e)}")

def exclude_result(cve_id):
    EXCLUDED_RESULTS.add(cve_id)

def cleanup_temp_files():
    if os.path.exists(TEMP_RESULTS_FILE):
        os.remove(TEMP_RESULTS_FILE)

if __name__ == "__main__":
    main(print, print, print)
