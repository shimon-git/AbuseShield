import os
import requests
import logging
import inspect
from pprint import pprint as p

API_KEYS = [
    '33d36dcad6c18a1c46e23bf21d4987108078a8a1961652c74ef8150c7cee3ce7b34396c3def31e29',
    '94ca6ab6840817146d214cca336b1858a09904a917a2355d8240c64189582c5811ed6437a8d23578',
    '7152c6e038c3573946b5f63d8186aee23c894d6c921bc5a2ac9d7adcc321ede6c7f72e68962d0264',
    ]
OUTPUT_FOLDER = "abuseIP"
LOG_FILE = "abuse_ip_log.txt"
RESULTS_FILE = "abuse_results.txt"
MIN_CONFIDENCE_SCORE = 5
BLACK_LIST = []
Logger = None
ABUSE_DB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
DEBUG_MODE = True

# create_logger - initialize a logger
def create_logger():
    global Logger
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)    
    log_file_path = os.path.join(OUTPUT_FOLDER, LOG_FILE)

    try:
        logging.basicConfig(filename=log_file_path, level=logging.DEBUG if DEBUG_MODE else logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        Logger = logging.getLogger(__name__)
    except Exception as e:
        print(f"Error during logger initialization: {e}")

# logger - log messages
def logger(message, level):
    frame = inspect.currentframe().f_back
    function_name = inspect.getframeinfo(frame).function
    if level.lower() == "debug" and DEBUG_MODE:
        Logger.debug(f"[{function_name}] {message}")
    elif level.lower() == "info":
        Logger.info(f"[{function_name}] {message}")
    elif level.lower() == "warning":
        Logger.warning(f"[{function_name}] {message}")
    elif level.lower() == "error":
        Logger.error(f"[{function_name}] {message}")
    elif level.lower() == "critical":
        Logger.critical(f"[{function_name}] {message}")
    


# get_ip_file - get the ip file path from the user
def get_ip_file():
    file_exist = False
    while not file_exist:
        logger("Get input for ip file path from the user","info")
        ip_file_path = input("please enter the path for the ip file: ")
        ip_file_path = ip_file_path.strip('"')
        if not os.path.exists(ip_file_path):
            logger(f"ip file path: {ip_file_path} - file does not exist","info")
            print(f"File {ip_file_path} does not exist...")
        else:
            file_exist = True
    return ip_file_path

# results_maker - write the black ips to the result file 
def results_maker():
    logger(f"create results file on: {os.path.join(OUTPUT_FOLDER, RESULTS_FILE)}","info")
    with open(os.path.join(OUTPUT_FOLDER, RESULTS_FILE), 'w') as f:
        ips = [ip+'\n' for ip in BLACK_LIST]
        f.writelines(ips)

# check the ip limit based the api keys - each key allow 1000 checks.
def calculate_ips_checker_limit():
    logger(f"Available API keys number: {len(API_KEYS)}","info")
    print(f"{len(API_KEYS) * 1000} can be checked")
    return len(API_KEYS) * 1000


# get_ips_for_check - parse the ip file and return ready ips format to check
def get_ips_for_check(ip_file):
    logger("Reformat IPS for check","info")
    with open(ip_file, 'r') as f:
        ips = [ip.strip() for ip in f.readlines() if ip.strip() != " "]
        logger(f"{len(ips)} are ready for check","info")
    return ips

# ip_check - check if ip is malicious and add the ip to the back list ips
def ip_check(ip,api_key):    
    ip = ip.replace('\n', '')
    logger(f"Sending request to - {ABUSE_DB_ENDPOINT} - for checking the ip: {ip}","info")
    r = requests.get(
        url=ABUSE_DB_ENDPOINT,
        headers={"Key":api_key},
        params={
            "ipAddress": ip,
            "maxAgeInDays": '90',
            'verbose': ''
        }
    )

    if r.status_code != 200:
        print(f"An error ocurred please check your logs file in the following path: {os.path.join(OUTPUT_FOLDER, LOG_FILE)}")
        logger(f"Expected status code: 200, But got {r.status_code} - response data: {r.text}","warning")
        return
    
    for key, value in r.headers.items():
        print(f"{key}: {value}")
    input("q")
    p(r.json())
    input("q")
    ip_data = r.json()
    score = int(ip_data['data']['abuseConfidenceScore'])
    
    if score >= MIN_CONFIDENCE_SCORE:
        logger(f"Malicious IP has been found - {ip} - was added successfully to the malicious ip file - score: {score}","info")
        print(f"[+] Malicious IP has been found - {ip} - was added successfully to the malicious ip file - score: {score}")
        BLACK_LIST.append(ip)
    else:
        print(f"[+] {ip} - is not malicious, score: {score}")
        logger(f"{ip} - is not malicious, score: {score}","debug")


def main():
    create_logger()
    ip_file = get_ip_file()
    ips = get_ips_for_check(ip_file)
    ip_limit = calculate_ips_checker_limit()
    counter = 0
    api_n = 0
    api_key = API_KEYS[api_n]
    for ip in ips:
        counter += 1
        if counter % 1000 == 0:
            api_n+=1
            api_key = API_KEYS[api_n]
        if counter <= ip_limit:
            ip_check(ip,api_key)
    results_maker()



    


if __name__ == '__main__':
    main()