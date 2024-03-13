# log_analysis
# A simple log analysis tool

## v0.0.1

Useful for sysadmins to get basic information from logs

**How to use**

`python3 log_analysis.py -f <Path>/<logfile> -a {show,requests,urls,ip,ip-detailed,summary,report}`

Options:

`  -h, --help            show this help message and exit`

`  -f FILE, --file FILE  Path to file to be analyzed`

` -a {show,requests,urls,ip,ip-detailed,summary,report}, --action {show,requests,urls,ip,ip-detailed,summary,report}`

                        
Operations to be performed:
    - "show" - Show basic data in columns
    - "requests" - Total number of requests
    - "urls" - Most visited URLs
    - "ip" - Top 5 identified ips
    - "ip-detailed" - Top 5 identified ips and show sample requests 
    - "ip-detailed-full" - Top 5 identified ips and show all requests 
    - "summary" - Show summary data about file (number of lines), URLs, IPs
    - "report" - Show summary data about file (number of lines), URLs, IPs and generates report to txt file. The name is generated automatically in the current subdirectory with the following format: 
   `log_report_YYYY-MM-DD_HHMMSS.txt`
    

    Example:
    log_report_2024-03-12_184322.txt


Examples of execution

`python3 log_analysis.py -f ../data/access_small.log -a show`

`python3 log_analysis.py -f ../data/access_small.log -a ip`

`python3 log_analysis.py -f ../data/access_small.log -a summary`



**Expected file format**


`IP Address - - [Timestamp] "Http-Method URL" Response-Code Numeric-Code "URL" "Browser-data" "-"`

**General flow control description**

1. Accept and parse arguments
2. Check file format exploring first column to be an IP address
3. According the passed arguments:
	Calls corresponding function to perform a operation
	- show_data
	- count_requests
	- count_top_ten_url
	- count_top_five_ip_requests
	- count_top_five_ip_requests_detail
4. In case of the options
	`show_summary` and `show_summary_report`
	Uses previous defined functions

	In case of `report` option a text file is generated in the current subdirectory with name according the format `log_report_YYYY-MM-DD_HHMMSS.txt`
5. Uses standard Python `loggin` utility to generate log named log_analysis.log


**Python libraries used**
-sys
-argparse
-os
-re
-collections 
-datetime
-logging