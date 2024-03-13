import sys
import argparse
import os
import re
from collections import Counter
import datetime
import logging

# Check for file availability
def check_file(filename):
    
    if not os.path.isfile(filename):
        print(f"File passed as argument not found: {filename}")
        logging.error(f"File not found: {filename}",exc_info=True)
        sys.exit(1)


# Check basic file format
def check_logfile_format(file):

    check_file(file.name)    

    with open(file.name) as f:
        for line in f:
            columns = line.split(' ')

            ip_address = columns[0]
            first_data=re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
            if not first_data.match(ip_address):
                print(f"Invalid file format")
                f.close()
                logging.error(f"Invalid file format",exc_info=True)
                sys.exit(2)

# Parses files and show key data
def show_data(file):
    check_file(file.name)

    with open(file.name) as f:
        for line in f:
            columns = line.split(' ')

            ip_address = columns[0]
            date_info = columns[3].replace("[","")
            http_method = columns[5].replace("\"","")
            url = columns[6]

            print(f"{ip_address}\t{date_info}\t{http_method}\t{url}")
    
    f.close()

# Shows total number of lines
def show_number_of_lines(file,generate_report):

    with open(file.name, 'r') as f:
        for count, line in enumerate(f):
            pass
    total_lines=count+1
    f.close()
    
    print('\nTotal Lines', total_lines)

    if generate_report:
        today = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_file_name="log_report_"+today+".txt"
        try:
            report = open(report_file_name, 'a')
            report.write("Log analysis")
            report.write("\n\nFilename: " + str(file.name))
            number_of_lines="\n\nTotal Lines: " + str(total_lines)
            report.write(number_of_lines)
            report.flush
            report.close
        except IOError  as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))


# Finds HTTP responses
def count_http_200(file,generate_report):
        
    with open(file.name) as f:
        # Find " NNN "
        codes        = re.findall(r'\s(\d{3})\s', f.read())
        code_counts  = Counter(codes)
        total_200    = code_counts['200']
        print(f'Total of reponses HTTP 200: {total_200}')
        total_400    = code_counts['400']
        print(f'Total of reponses HTTP 400: {total_400}')
        total_500    = code_counts['500']
        print(f'Total of reponses HTTP 500: {total_500}')
    f.close()
    
    if generate_report:
        today = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_file_name="log_report_"+today+".txt"
        try:
            report = open(report_file_name, 'a')
            total_200_str="\nTotal of reponses HTTP 200: " + str(total_200);
            report.write(total_200_str)
            total_400_str="\nTotal of reponses HTTP 400: " + str(total_400);
            report.write(total_400_str)
            total_500_str="\nTotal of reponses HTTP 500: " + str(total_500);
            report.write(total_500_str)
            report.flush
            report.close
        except IOError  as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))
        
# Finds the top 10 URLS
def count_top_ten_url(file,generate_report):

    print('\nTop 10 URLs')

    with open(file.name) as f:

        urls = re.findall('://www.([\w\-\.]+)', f.read())
        urls_counts  = Counter(urls)
        sorted_urls = urls_counts.most_common(10)
        for url, count in sorted_urls:
            print([url, count])
    
    f.close()

    if generate_report:
        today = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_file_name="log_report_"+today+".txt"
        try:
            report = open(report_file_name, 'a')
            
            report.write("\n\nURL number of visits")
            for url, count in sorted_urls:
                output="\n" + url + "\t" + str(count)
                report.write(output)
                report.flush
                report.close
        except IOError  as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))


# Finds the top 5 ips
def count_top_five_ip_requests(file,generate_report):

    print('\nTop 5 IP by number of requests')

    with open(file.name) as f:

        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", f.read())
        ips_counts  = Counter(ips)
        sorted_ips = ips_counts.most_common(5)
        for ip, count in sorted_ips:
            print("{:<20} {:<20}".format(ip, count))
            
    f.close()


# Finds the top 5 ips and shows request details
def count_top_five_ip_requests_detail(file,generate_report):

    print('\nTop 5 IP by number of requests')

    with open(file.name) as f:

        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", f.read())
        ips_counts  = Counter(ips)
        sorted_ips = ips_counts.most_common(5)
        for ip, count in sorted_ips:
            print("{:<20} {:<20}".format(ip, count))
            
    f.close()

    output_list=[]

    print('\nDetailed request info by IP')
    for ip in sorted_ips:
        ip_s=''
        ip_s+=str(ip[0])
        output_list.append("\n\nIP of interest: " + ip_s)
        print('\n\nIP of interest: '+ip_s)
        sample_counter = 0

        with open(file.name) as f:
            for line in f:    
                columns = line.split(' ')
                ip_address = columns[0]
                if ip_address == ip_s:
                    if sample_counter > 9:
                        break
                    date_info = columns[3].replace("[","")
                    http_method = columns[5].replace("\"","")
                    url = columns[6]
                    print(f"{ip_address}\t{date_info}\t{http_method}\t{url}")
                    output_data="\n" + ip_address + "\t" + date_info + "\t" + http_method + "\t" + url
                    output_list.append(output_data)
                    sample_counter += 1
    
    f.close()

    if generate_report:
        today = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_file_name="log_report_"+today+".txt"
        try:
            report = open(report_file_name, 'a')
            # Write top 5 ip summary to file
            report.write("\n\nTop 5 IP by number of requests")
            for ip, count in sorted_ips:
                output="\n" + ip + "\t" + str(count)
                report.write(output)
                report.flush
            # Write details to file
            for output_line in output_list:
                report.write(output_line)
                report.flush

        except IOError  as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))


# Finds the top 5 ips and shows request details
def count_top_five_ip_requests_detail_full(file,generate_report):

    print('\nTop 5 IP by number of requests')

    with open(file.name) as f:

        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", f.read())
        ips_counts  = Counter(ips)
        sorted_ips = ips_counts.most_common(5)
        for ip, count in sorted_ips:
            print("{:<20} {:<20}".format(ip, count))
            
    f.close()

    output_list=[]
    print('\nDetailed request info by IP')
    for ip in sorted_ips:
        ip_s=''
        ip_s+=str(ip[0])
        output_list.append("\n\nIP of interest: " + ip_s)
        print('\n\nIP of interest: '+ip_s)
        with open(file.name) as f:
            for line in f:
                columns = line.split(' ')
                ip_address = columns[0]

                if ip_address == ip_s:
                    date_info = columns[3].replace("[","")
                    http_method = columns[5].replace("\"","")
                    url = columns[6]
                    print(f"{ip_address}\t{date_info}\t{http_method}\t{url}")
                    output_data="\n" + ip_address + "\t" + date_info + "\t" + http_method + "\t" + url
                    output_list.append(output_data)
    
    f.close()

    if generate_report:
        today = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_file_name="log_report_"+today+".txt"
        try:
            report = open(report_file_name, 'a')
            # Write top 5 ip summary to file
            report.write("\n\nTop 5 IP by number of requests")
            for ip, count in sorted_ips:
                output="\n" + ip + "\t" + str(count)
                report.write(output)
                report.flush
            # Write details to file
            for output_line in output_list:
                report.write(output_line)
                report.flush

        except IOError  as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))


# Shows total requests basted on HTTP methods
def count_requests(file,generate_report):
        
    with open(file.name) as f:
        requests = re.findall(r'"(GET|POST|PUT|DELETE)\s(\S+)', f.read())
        requests_counts  = Counter(requests)
        total_requests = requests_counts.total()
        print(f'\nTotal of requests (GET|POST|PUT|DELETE): {total_requests}')
    f.close

    if generate_report:
        today = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_file_name="log_report_"+today+".txt"
        try:
            report = open(report_file_name, 'a')
            total_requests_str="\n\nTotal of requests (GET|POST|PUT|DELETE): " + str(total_requests);
            report.write(total_requests_str)
            report.flush
            report.close
        except IOError  as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))


# Show summary of data
def show_summary(file):
    
    check_file(file.name)

    print(f"\nSummary for filename: {file.name}")
    
    generate_report=False
    report_file_name=''

    show_number_of_lines(file,generate_report)

    count_requests(file,generate_report)
    count_http_200(file,generate_report)
    count_top_ten_url(file,generate_report)
    count_top_five_ip_requests_detail(file,generate_report)

# Show summary of data and generate report in txt file
def show_summary_report(file):
    
    check_file(file.name)

    print(f"\nSummary for filename: {file.name}")

    generate_report=True
    
    show_number_of_lines(file,generate_report)

    count_requests(file,generate_report)
    count_http_200(file,generate_report)
    count_top_ten_url(file,generate_report)
    count_top_five_ip_requests_detail(file,generate_report)


if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO, filename="log_analysis.log",filemode="w")

    parser = argparse.ArgumentParser(description="Log analysis tool", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-f", "--file", help='Path to file to be analyzed', dest="file",
                        type=argparse.FileType('r'), required=True)
    parser.add_argument("-a", "--action", help='\nOperations to be performed:\n'
                                            '  - "show" - Show basic data in columns\n'
                                            '  - "requests" - Total number of requests\n'
                                            '  - "urls" - Most visited URLs\n'
                                            '  - "ip" - Top 5 identified ips\n'
                                            '  - "ip-detailed" - Top 5 identified ips and show sample requests\n'
                                            '  - "ip-detailed-full" - Top 5 identified ips and show all requests\n'
                                            '  - "summary" - Show summary data about file (number of lines), URLs, IPs\n'
                                            '  - "report" - Show summary data about file (number of lines), URLs, IPs and generates report to txt file\n',
                        dest="operation", type=str,
                        choices=['show', 'requests', 'urls', 'ip', 'ip-detailed', 'ip-detailed-full', 'summary', 'report'] , required=True)

    args = parser.parse_args()
    
    logging.info("Start execution")

    check_logfile_format(args.file)

    generate_report=False

    if args.operation == 'show':
        logging.info("Show info selected")
        show_data(args.file)
    elif args.operation == 'requests':
        logging.info("Show requests selected")
        count_requests(args.file,generate_report)
    elif args.operation == 'urls':
        logging.info("Show urls selected")
        count_top_ten_url(args.file,generate_report)
    elif args.operation == 'ip':
        logging.info("Show ips selected")
        count_top_five_ip_requests(args.file,generate_report)
    elif args.operation == 'ip-detailed':
        logging.info("Show ip detailed information selected")
        count_top_five_ip_requests_detail(args.file,generate_report)
    elif args.operation == 'summary':
        logging.info("Show summary in console selected")
        show_summary(args.file)
    elif args.operation == 'report':
        logging.info("Show summary in console and generate report selected")
        show_summary_report(args.file)
    elif args.operation == 'ip-detailed-full':
        logging.info("Show top 5 ip detailed full information selected")
        count_top_five_ip_requests_detail_full(args.file,generate_report) 

    logging.info("End execution")