import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
import argparse
import os
import logging


# Setup logging
logging.basicConfig(filename='script_output.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')


# Function to run ParamSpider and fetch parameters
def run_paramspider(domain, delay, consolidated_param_output_file):
    try:
        logging.info(f"Processing domain: {domain}")
        cmd = f'paramspider -d {domain} -l 3'
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        
        with open(consolidated_param_output_file, 'a') as f:
            f.write(f"# Output for {domain}\n")
            f.write(result.stdout + "\n")
        
        logging.info(f"ParamSpider completed for domain {domain}. Output appended to {consolidated_param_output_file}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error invoking ParamSpider for domain {domain}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error occurred: {e}")


# Function to run gf tool for filtering LFI-related parameters
def run_gf_lfi(consolidated_param_output_file, consolidated_gf_output_file, domain):
    try:
        logging.info(f"Running gf tool on output for domain {domain} to filter for LFI parameters")
        cmd = f'cat {consolidated_param_output_file} | gf lfi'
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        
        with open(consolidated_gf_output_file, 'a') as f:
            f.write(f"# gf Output for {domain}\n")
            f.write(result.stdout + "\n")
        
        logging.info(f"gf filtering completed for domain {domain}. Output appended to {consolidated_gf_output_file}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running gf on output for domain {domain}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error occurred: {e}")


# Function to check for LFI vulnerabilities
def check_lfi_vulnerabilities(domain, payloads, consolidated_gf_output_file, consolidated_lfi_output_file, delay):
    try:
        with open(consolidated_gf_output_file, 'r') as file:
            urls = file.readlines()


        valid_lfi_urls = []
        for url in urls:
            if url.startswith("#"):
                continue
            url = url.strip()
            for payload in payloads:
                test_url = url.replace("=", f"={payload}")
                if is_valid_url(test_url) and lfi_payload_works(test_url):
                    logging.info(f"LFI vulnerability detected with payload: {test_url}")
                    valid_lfi_urls.append(test_url)
                    break  # Stop after finding a valid LFI with one payload


                if delay > 0:
                    threading.sleep(delay / 1000.0)
        
        with open(consolidated_lfi_output_file, 'a') as lfi_file:
            lfi_file.write(f"# LFI vulnerabilities for {domain}\n")
            for valid_url in valid_lfi_urls:
                lfi_file.write(valid_url + "\n")
        
        logging.info(f"LFI vulnerability check completed for domain {domain}. Output appended to {consolidated_lfi_output_file}.")
    
    except Exception as e:
        logging.error(f"Error during LFI vulnerability check for domain {domain}: {e}")


# Function to validate if the URL is well-formed
def is_valid_url(url):
    try:
        requests.get(url)
        return True
    except requests.RequestException:
        logging.error(f"Malformed URL or connection error: {url}")
        return False


# Function to determine if LFI payload is working
def lfi_payload_works(url):
    try:
        response = requests.get(url)
        content = response.text.lower()  # Convert to lowercase for case-insensitive comparison


        # Check for multiple indicators of LFI
        linux_indicators = ["root:x:0:0", "mail:x:8:", "bin/bash", "etc/passwd"]
        windows_indicators = ["[boot loader]", "[fonts]", "c:\\windows", "c:\\system32"]


        # Look for common LFI indicators in the response body
        if any(indicator in content for indicator in linux_indicators + windows_indicators):
            return True


        # Further checks (e.g., content-length analysis, specific HTTP headers)
        # Example: Check for a significant difference in response size
        if len(content) > 10000:  # Arbitrary threshold, tweak as needed
            return True


        return False


    except requests.RequestException as e:
        logging.error(f"Error fetching webpage content for {url}: {e}")
        return False


# Main script logic
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LFI Vulnerability Checker with ParamSpider and gf")
    parser.add_argument("-i", "--input", required=True, help="Input file path containing list of domains")
    parser.add_argument("-d", "--delay", type=int, default=0, help="Delay time in milliseconds")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads for concurrent processing")
    parser.add_argument("-p", "--payloads", required=True, help="File containing list of LFI payloads")
    parser.add_argument("-o", "--output", default="output", help="Directory to save output files")
    
    args = parser.parse_args()


    # Ensure output directory exists
    os.makedirs(args.output, exist_ok=True)


    # Consolidated output files
    consolidated_param_output_file = os.path.join(args.output, 'consolidated_paramspider_output.txt')
    consolidated_gf_output_file = os.path.join(args.output, 'consolidated_gf_output.txt')
    consolidated_lfi_output_file = os.path.join(args.output, 'consolidated_lfi_output.txt')


    # Read domains from input file
    with open(args.input, 'r') as f:
        domains = [line.strip() for line in f.readlines()]


    # Read LFI payloads from file
    with open(args.payloads, 'r') as f:
        lfi_payloads = [line.strip() for line in f.readlines()]


    # Use multithreading to process domains concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for domain in domains:
            executor.submit(run_paramspider, domain, args.delay, consolidated_param_output_file)
            executor.submit(run_gf_lfi, consolidated_param_output_file, consolidated_gf_output_file, domain)
            executor.submit(check_lfi_vulnerabilities, domain, lfi_payloads, consolidated_gf_output_file, consolidated_lfi_output_file, args.delay)
    
    logging.info("Script execution completed.")
