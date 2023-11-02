# Cisco IOS XE Implant Detection Script

Script created by @JairoCCIE to check if a Cisco IOS XE device is vulnerable to CVE-2023-20198.

The CVE is detailed in the Cisco Talos advisory https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/

## Ongoing exploitation
How to verify with a simple curl

\```bash
    curl -k -H "Authorization: 0ff4fbf0ecffa77ce8d3852a29263e263838e9bb" -X POST "https[:]//DEVICEIP/webui/logoutconfirm.html?logon_hash=1" 
\```

This will execute a request to the device’s Web UI to see if the implant is present. If the request returns a hexadecimal string, similar to what was outlined in the third function above, a known version of the implant is present. We note this will only work as an indication of compromise if the web server was restarted by the actor after the implant was installed. 

Additionally, a generic curl command can be run to help identify systems with known variants of the implant without interacting with the implant’s core functionality: 

\```bash
    curl -k "https[:]//DEVICEIP/%25"
\```

If this returns a 404 HTTP response with an HTML page comprising of a “404 Not Found” message, a known variation of the implant is present. A system without the implant should return a 200 HTTP response containing a JavaScript redirect. 

## Prerequisites
- Python 3
- Required Libraries: 
\```bash
pip install requests urllib3 rich
\```

## Usage

### Single or Multiple Targets:
\```bash
python script.py 192.168.1.1 192.168.1.2
\```

### File with a List of Targets:
\```bash
python script.py -f targets.txt
\```

### Output Results to a CSV File:
\```bash
python script.py -f targets.txt --output results.csv
\```

## Output
The script outputs a table with the vulnerability status, and optionally writes the results to a CSV file.

## License
[MIT License](LICENSE)

## Example of usage
With this script simple but effective you can test against the devices in your network really easily. 

\```bash
> python iosxe.py 10.250.100.1

           Cisco Device Scan Results

┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Target         ┃ HTTP Result ┃ HTTPS Result  ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ 10.250.100.1   │ Compromised │ Compromised   │
└────────────────┴─────────────┴───────────────┘
\```

If you want to try against multiple targets 
\```bash
> python iosxe.py 10.250.100.1

           Cisco Device Scan Results

┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Target         ┃ HTTP Result ┃ HTTPS Result  ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ 10.250.100.1   │ Compromised │ Compromised   │
└────────────────┴─────────────┴───────────────┘
\```

Also you can hava de posibility of exporting the data to a csv file for easy reporting

\```bash

> python iosxe.py 10.250.100.1 10.250.100.2 --output results.csv



            Cisco Device Scan Results

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Target       ┃ HTTP Result   ┃ HTTPS Result  ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ 10.250.100.1 │ Safe          │ Not Listening │
│ 10.250.100.2 │ Not Listening │ Not Listening │
└──────────────┴───────────────┴───────────────┘
>
>
> cat results.csv
Target,HTTP Result,HTTPS Result
10.250.100.1,Safe,Not Listening
10.250.100.2,Not Listening,Not Listening

\```