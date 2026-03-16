import requests
import csv
from datetime import datetime

HEADERS_TO_CHECK = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

HEADER_INFO = {
    "Content-Security-Policy":   "Prevents XSS attacks",
    "X-Frame-Options":           "Prevents clickjacking",
    "Strict-Transport-Security": "Forces HTTPS connection",
    "X-Content-Type-Options":    "Prevents MIME sniffing",
    "Referrer-Policy":           "Controls info leakage",
    "Permissions-Policy":        "Limits browser features"
}

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

def scan_site(url, writer=None):
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\n scanning: {url}")
    print("-" * 50)

    try:
        response = requests.get(url, timeout=5)
        found = 0
        results = {}

        for header in HEADERS_TO_CHECK:
            if header in response.headers:
                print(f"  {GREEN}FOUND    {header}{RESET}")
                print(f"           {HEADER_INFO[header]}")
                results[header] = "FOUND"
                found += 1
            else:
                print(f"  {RED}MISSING  {header}{RESET}")
                print(f"           {HEADER_INFO[header]}")
                results[header] = "MISSING"

        score = f"{found}/{len(HEADERS_TO_CHECK)}"
        print(f"\n  Security Score: {score}")

        if found <= 2:
            risk = "HIGH"
            print(f"  Risk Level: {RED}{risk}{RESET}")
        elif found <= 4:
            risk = "MEDIUM"
            print(f"  Risk Level: {YELLOW}{risk}{RESET}")
        else:
            risk = "LOW"
            print(f"  Risk Level: {GREEN}{risk}{RESET}")

        if writer:
            writer.writerow([
                url,
                score,
                risk,
                results.get("Content-Security-Policy"),
                results.get("X-Frame-Options"),
                results.get("Strict-Transport-Security"),
                results.get("X-Content-Type-Options"),
                results.get("Referrer-Policy"),
                results.get("Permissions-Policy"),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ])

    except requests.exceptions.RequestException as e:
        print(f"  {RED}Could not reach {url}{RESET}")
        print(f"  Error: {e}")

def scan_from_file(filename, writer=None):
    try:
        with open(filename, "r") as f:
            sites = [line.strip() for line in f if line.strip()]

        print(f"  Found {len(sites)} sites to scan")

        for site in sites:
            scan_site(site, writer)

    except FileNotFoundError:
        print(f"  {RED}Could not find {filename}{RESET}")

if __name__ == "__main__":
    print("=" * 50)
    print("   Security Header Scanner")
    print("=" * 50)

    print("\n  1. Scan a single site")
    print("  2. Scan from sites.txt")

    choice = input("\n  Choose 1 or 2: ")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"report_{timestamp}.csv"

    with open(report_name, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "URL",
            "Score",
            "Risk Level",
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Timestamp"
        ])

        if choice == "1":
            url = input("  Enter a website to scan: ")
            scan_site(url, writer)
        elif choice == "2":
            scan_from_file("sites.txt", writer)
        else:
            print("  Invalid choice")

    print(f"\n  {GREEN}Report saved to {report_name}{RESET}")