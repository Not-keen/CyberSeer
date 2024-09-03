import requests
import csv
import time
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from packaging import version
from datetime import datetime, timedelta
import os

CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

API_KEY = None
EXCLUDED_RESULTS = set()
TEMP_RESULTS_FILE = "temp_cve_results.json"

def set_api_key(key):
    global API_KEY
    API_KEY = key
    save_api_key(key)

def save_api_key(key):
    with open("api_key.txt", "w") as f:
        f.write(key)

def load_api_key():
    global API_KEY
    if API_KEY:
        return API_KEY
    try:
        with open("api_key.txt", "r") as f:
            API_KEY = f.read().strip()
        return API_KEY
    except FileNotFoundError:
        return None

def format_cpe_string(software, version):
    software = re.sub(r'[^a-zA-Z0-9._-]', '_', software.lower())
    if version:
        version = re.sub(r'[^a-zA-Z0-9._-]', '_', version.lower())
        return f"cpe:2.3:a:{software}:{software}:{version}:*:*:*:*:*:*:*"
    else:
        return f"cpe:2.3:a:{software}:*:*:*:*:*:*:*:*:*"

def query_cpe_batch(software_batch, log_callback, headers):
    cpe_results = []
    for item in software_batch:
        if len(item) < 2:
            log_callback(f"Skipping invalid entry: {item}")
            continue
        software, version = item[0], item[1]
        match_string = format_cpe_string(software, version)
        try:
            log_callback(f"Querying CPE for: {software} {version}")
            response = requests.get(f"{CPE_API_URL}?keywordSearch={software}&resultsPerPage=1", headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("totalResults", 0) > 0:
                cpe_results.append((software, version, data["products"][0]["cpe"]))
            else:
                log_callback(f"No CPE found for {software} {version}")
        except requests.exceptions.RequestException as e:
            log_callback(f"Error querying CPE for {software} {version}: {e}")
    return cpe_results

def query_cve_batch(cpe_batch, log_callback, headers):
    cve_results = []
    for software, version, cpe in cpe_batch:
        try:
            log_callback(f"Querying CVE for CPE: {cpe['cpeName']}")
            response = requests.get(f"{CVE_API_URL}?cpeName={cpe['cpeName']}&resultsPerPage=1", headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("totalResults") > 0:
                cve_results.append((software, version, cpe, data["vulnerabilities"]))
            else:
                log_callback(f"No CVEs found for CPE: {cpe['cpeName']}")
        except requests.exceptions.RequestException as e:
            log_callback(f"Error querying CVE for CPE {cpe['cpeName']}: {e}")
    return cve_results

def compare_versions(version1, version2, include_equal=True):
    try:
        v1 = version.parse(version1)
        v2 = version.parse(version2)
        return v1 <= v2 if include_equal else v1 < v2
    except:
        return False

def determine_confidence(cve_version_info, software_version, cve_published_date):
    if software_version:
        for node in cve_version_info:
            for cpe_match in node.get('cpeMatch', []):
                version_start_including = cpe_match.get('versionStartIncluding')
                version_start_excluding = cpe_match.get('versionStartExcluding')
                version_end_including = cpe_match.get('versionEndIncluding')
                version_end_excluding = cpe_match.get('versionEndExcluding')

                if version_start_including and version_end_including:
                    if compare_versions(version_start_including, software_version) and compare_versions(software_version, version_end_including):
                        return "High", False
                elif version_start_excluding and version_end_excluding:
                    if compare_versions(version_start_excluding, software_version, False) and compare_versions(software_version, version_end_excluding, False):
                        return "High", False
                elif version_start_including and version_end_excluding:
                    if compare_versions(version_start_including, software_version) and compare_versions(software_version, version_end_excluding, False):
                        return "High", False
                elif version_start_excluding and version_end_including:
                    if compare_versions(version_start_excluding, software_version, False) and compare_versions(software_version, version_end_including):
                        return "High", False
                elif version_start_including and compare_versions(version_start_including, software_version):
                    return "High", False
                elif version_start_excluding and compare_versions(version_start_excluding, software_version, False):
                    return "High", False
                elif version_end_including and compare_versions(software_version, version_end_including):
                    return "High", False
                elif version_end_excluding and compare_versions(software_version, version_end_excluding, False):
                    return "High", False

    cve_age = datetime.now() - datetime.strptime(cve_published_date, "%Y-%m-%dT%H:%M:%S.%f")

    if cve_age < timedelta(days=5*365):  # Less than 5 years old
        return "Medium", True
    elif cve_age < timedelta(days=10*365):  # 5-10 years old
        return "Low", True
    else:  # More than 10 years old
        return "Very Low", True

def extract_cve_info(vulnerability):
    cve_id = vulnerability.get('cve', {}).get('id')

    severity = None
    metrics = vulnerability.get('cve', {}).get('metrics', {})
    if 'cvssMetricV31' in metrics:
        severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
    elif 'cvssMetricV3' in metrics:
        severity = metrics['cvssMetricV3'][0]['cvssData']['baseSeverity']
    elif 'cvssMetricV2' in metrics:
        severity = metrics['cvssMetricV2'][0]['baseSeverity']

    published_date = vulnerability.get('cve', {}).get('published', '')

    version_info = vulnerability.get('cve', {}).get('configurations', [])

    return cve_id, severity, published_date, version_info

def process_batch(batch, log_callback, result_callback, headers):
    try:
        cpe_results = query_cpe_batch(batch, log_callback, headers)
        cve_results = query_cve_batch(cpe_results, log_callback, headers)
        
        for software, version, cpe, vulnerabilities in cve_results:
            for vulnerability in vulnerabilities:
                try:
                    cve_id, severity, published_date, version_info = extract_cve_info(vulnerability)
                    confidence, needs_manual_check = determine_confidence(version_info, version, published_date)
                    if cve_id and severity and cve_id not in EXCLUDED_RESULTS:
                        log_callback(f"Found CVE: {cve_id} with severity: {severity} for {software} {version} (Confidence: {confidence})")
                        result_callback((software, version, cve_id, severity, confidence, needs_manual_check))
                except Exception as e:
                    log_callback(f"Error processing vulnerability data for {software} {version}: {str(e)}")
    except Exception as e:
        log_callback(f"Error processing batch: {str(e)}")

def calculate_security_score(results):
    severity_weights = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2
    }

    confidence_weights = {
        "High": 1.0,
        "Medium": 0.6,
        "Low": 0.4,
        "Very Low": 0.2
    }

    total_weight = 0
    max_weight = 0
    for result in results:
        severity = result[3]
        confidence = result[4]
        weight = severity_weights.get(severity, 0) * confidence_weights.get(confidence, 0.2)
        total_weight += weight
        max_weight += severity_weights.get("CRITICAL", 10)  # Use the maximum possible weight for each vulnerability

    if max_weight == 0:
        return 100  # Perfect score if no vulnerabilities found

    score = 100 - (total_weight / max_weight) * 100
    final_score = max(0, min(100, round(score, 2)))  # Ensure score is between 0 and 100
    return final_score

def save_temp_results(results):
    formatted_results = [
        [result[0], result[1], result[2], result[3], result[4]]
        for result in results if result[0] != "OVERALL_SCORE"
    ]
    with open(TEMP_RESULTS_FILE, 'w') as f:
        json.dump(formatted_results, f)

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
            software_list = list(reader)

        total_software = len(software_list)
        batch_size = min(10, max(1, total_software // 100))  # Adjust batch size based on total software count
        batches = [software_list[i:i + batch_size] for i in range(0, total_software, batch_size)]

        log_callback("Processing software in batches...")
        results = []
        for i, batch in enumerate(batches):
            log_callback(f"Processing batch {i+1} of {len(batches)}...")
            process_batch(batch, log_callback, lambda x: results.append(x), headers)
            progress_callback((i + 1) / len(batches) * 100)

        for result in results:
            result_callback(result)

        security_score = calculate_security_score(results)
        log_callback(f"Scan completed. Overall Security Score: {security_score}")
        result_callback(("OVERALL_SCORE", "", "", "", security_score, False))

        save_temp_results(results)

    except FileNotFoundError:
        log_callback("installed_software.csv file not found. Please make sure it exists in the same directory.")
    except Exception as e:
        log_callback(f"An error occurred while processing the software list: {str(e)}")
        import traceback
        log_callback(traceback.format_exc())

def exclude_result(cve_id):
    EXCLUDED_RESULTS.add(cve_id)

def cleanup_temp_files():
    if os.path.exists(TEMP_RESULTS_FILE):
        os.remove(TEMP_RESULTS_FILE)

if __name__ == "__main__":
    main(print, print, print)
