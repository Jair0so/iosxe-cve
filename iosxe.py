#!/usr/bin/env python3
"""
 ___ ___  ______  _______      ___         _____     ____   ________  ____       ___    ___  __ ___   ___  
|_ _/ _ \/ ___\ \/ / ____|   / ___\ \   / / ____|   |___ \ / _ \___ \|___ /     |___ \ / _ \/ |/ _ \ ( _ )                                              
 | | | | \___ \\  /|  _|    | |    \ \ / /|  _| _____ __) | | | |__) | |_ \ _____ __) | | | | | (_) |/ _ \                                             
 | | |_| |___) /  \| |___   | |___  \ V / | |__|_____/ __/| |_| / __/ ___) |_____/ __/| |_| | |\__, ||(_) |                                             
|___\___/|____/_/\_\_____|   \____|  \_/  |_____|   |_____|\___/_____|____/     |_____|\___/|_|  /_/ \___/

Created by @JairoCCIE to identify if a IOSXE device is vulnerable or not to CVE-2023-20198

Usage:
1. Ensure you have the required libraries installed using the following:
    pip install requests urllib3 rich
2. Run the script from the command line with the target IP addresses or hostnames as arguments, like so:
    python iosxe.py 192.168.1.1 192.168.1.2
3. Alternatively, you can provide a file with a list of targets, one per line, using the -f or --file option:
    python iosxe.py -f targets.txt
4. To output the results to a CSV file, use the -o or --output option:
    python iosxe.py -f targets.txt --output results.csv
5. The script will output a table indicating whether each target is compromised, safe, or not Listening in http/https, and if --output is used,
   it will also write the results to the specified CSV file.
"""




import sys
import argparse
import requests
import urllib3
from rich.console import Console
from rich.table import Table
import csv


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


console = Console()


def is_compromised(session, url) -> str:
    headers = {
        "User-Agent": "0ff4fbf0ecffa77ce8d3852a29263e263838e9bb"
    }
    try:
        response = session.get(url, headers=headers, verify=False)
        return "Compromised" if "<h1>404 Not Found</h1>" in response.text else "Safe"
    except requests.exceptions.RequestException as e:
        return "Not Listening"


def check_target(target: str) -> (str, str):
    with requests.Session() as session:
        http_url = f"http://{target}/%25"
        https_url = f"https://{target}/%25"

        http_result = is_compromised(session, http_url)
        https_result = is_compromised(session, https_url)

        return http_result, https_result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="*", help="Cisco IOS XE Device IP or hostname")
    parser.add_argument("-f", "--file", action="store", dest="filename",
                        help="File containing a list of target hosts (one per line)")
    parser.add_argument("-o", "--output", action="store", dest="output_filename", help="Output CSV filename")
    args = parser.parse_args()

    targets = args.targets
    if args.filename:
        with open(args.filename, mode="r", encoding="utf-8") as file_handle:
            for line in file_handle:
                target = line.strip()
                if target and not target.startswith("#"):
                    targets.append(target)



    results_table = Table(
        title="\n \n \n [bold blue]Cisco Device Scan Results[/bold blue] \n", pad_edge=True
        )
    results_table.add_column("Target", justify="left", style="cyan", no_wrap=True)
    results_table.add_column("HTTP Result", style="magenta")
    results_table.add_column("HTTPS Result", style="magenta")

    if args.output_filename:
        with open(args.output_filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Target", "HTTP Result", "HTTPS Result"])  # header row
            for target in targets:
                http_status, https_status = check_target(target)
                writer.writerow([target, http_status, https_status])
                results_table.add_row(target, http_status, https_status)
    else:
        for target in targets:
            http_status, https_status = check_target(target)
            results_table.add_row(target, http_status, https_status)

    console.print(results_table)

if __name__ == "__main__":
    sys.exit(main())
