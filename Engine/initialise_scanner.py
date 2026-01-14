import os
import sys
import setproctitle #need to pip
import argparse
from datetime import datetime
import re
import ipaddress
import shutil


from plugins_utils import plugin_init
from scanid_utils import scan_uuid_init
from host_ports_utils import scan_hosts, scan_ports
from vuln_db import app
from db_req_utils import result_db_req_func, vuln_db_req_func
import nasl_interpreter 


def setproctitle_init(argc, argv, env):
    # Concatenate the command-line arguments and environment variables
    args = " ".join(argv[1:])  # Skip the first argument (the script name)
    env_vars = " ".join(f"{key}={value}" for key, value in env.items())

    # Set the process title using setproctitle
    process_title = f"{sys.executable} {args} {env_vars}"
    setproctitle.setproctitle(process_title)

#-----------------
CONF_PATH = os.path.join(os.path.dirname(__file__), 'engine.conf')

def display_conf_content(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            return content
    except FileNotFoundError:
        return "File not found."
    except Exception as e:
        return f"Error occurred: {str(e)}"
#-----------------
class ScanGlobals:
    def __init__(self):
        self.files_translation = None
        self.files_size_translation = None
        self.scan_id = None
        self.host_pid = None
        self.mem = None

def g_malloc0(size):
    if size == 0:
        return None
    return bytearray(size)

def g_strdup(string):
    if string is None:
        return None
    return string
      
def get_scan_id():
    file_path = os.path.join(os.path.dirname(__file__), 'engine.conf')
    
    if os.path.isfile(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
    else:
        raise FileNotFoundError(f"File not found: {file_path}")

    uuid_pattern = r'uuid=([\w-]+)'
    match = re.search(uuid_pattern, content)

    if match:
        uuid_value = match.group(1)
        return uuid_value
    else:
        print('UUID value not found in the file.')
        return False
    
def ip_addr_validation(input_str):
    if '/' in input_str:
        try:
            ipaddress.IPv4Network(input_str, strict=False)
            return True
        except ipaddress.AddressValueError:
            return False
    else:
        try:
            ipaddress.IPv4Address(input_str)
            return True
        except ipaddress.AddressValueError:
            return False

def del_functional_plugins_dir():
    directory_path = os.path.join(os.path.dirname(__file__), 'functional_plugins')
    try:
        # Delete the entire directory with all its files and subdirectories
        shutil.rmtree(directory_path)
    except FileNotFoundError:
        print(f"Directory '{directory_path}' not found.")
    except Exception as e:
        print(f"An error occurred while deleting the directory: {e}")

#------ attack_network()--------
def compare_response(retrieve_str, vuln_response_list: list):
    if any(item["vuln_response"] in retrieve_str for item in vuln_response_list):
        return True
    else:
        return False

def stringifyWord(keyword):
    if isinstance(keyword, list):
        result_string = ', '.join(map(str, keyword))
        return result_string

    elif isinstance(keyword, str):
        return keyword
    
def retrieve_cwe_num_from_folder(sub_foler):
    directory_path = os.path.join(os.path.dirname(__file__), 'functional_plugins', sub_foler)
    numbers = []
    file_pattern = re.compile(r'cwe(\d+)_plugin\.py', re.IGNORECASE)

    # Loop through the files in the given directory
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            match = file_pattern.match(file)
            if match:
                number = int(match.group(1))
                numbers.append(number)

    return numbers

def webapp_plugins_scan(scan_id, ip_address, webapp_plugins_response_list) -> list:
    vuln_cwe =[]
    for item in webapp_plugins_response_list:
        item_def = plugin_response(item.retrieved_response, item.cwe_id, item.count)
        cwe_id = item_def.cwe_id
        script_response = item_def.retrieved_response

        vuln_response_list = result_db_req_func.get_cwe_vuln_pattern(cwe_id)
        if len(vuln_response_list) != 0:
            if compare_response(script_response, vuln_response_list):
                # need: scan_uuid, severity, location , cwss, cwe_id , cwe_name, cwe_description, cwe_solution , file_location_path , keyword_pattern, count 
                plugin_info = nasl_interpreter.parseDescription(cwe_id)
                scan_uuid = scan_id
                location = plugin_info['attributes']['location']
                cwss = plugin_info['attributes']['cwss']
                cwe_solution = plugin_info['attributes']['solution']
                cwe_name = vuln_response_list[0]['vuln_name']
                severity = vuln_response_list[0]['severity']
                cwe_description = vuln_response_list[0]['vuln_description']
                file_location_path = 'http://'+ ip_address +'/dvwa/login.php' #change according to the developer
                keyword_pattern = vuln_response_list[0]["vuln_response"]
                count =1

                result_db_req_func.post_result_vul_cwe_to_RD(scan_uuid, severity, location , cwss, cwe_id , cwe_name, cwe_description, cwe_solution , file_location_path , keyword_pattern, count)
                if cwe_id not in vuln_cwe:
                    vuln_cwe.append(cwe_id)

        else: 
            print("No vuln_response from database for this cwe_id")
    return vuln_cwe

def filesys_plugins_scan(scan_id, filesys_plugins_response_list) ->list:
    vuln_cwe = []
    for item in filesys_plugins_response_list:
        item_def = plugin_response(item.retrieved_response, item.cwe_id, item.count)
        
        cwe_id = item_def.cwe_id
        if cwe_id not in vuln_cwe:
            vuln_cwe.append(cwe_id)

        cwe_info = vuln_db_req_func.get_cwe_info(cwe_id)

        count = item_def.count
        script_response = item_def.retrieved_response
        
        plugin_info = nasl_interpreter.parseDescription(cwe_id)
        
        scan_uuid = scan_id
        location = plugin_info['attributes']['location']
        cwss = plugin_info['attributes']['cwss']
        cwe_solution = plugin_info['attributes']['solution']
        cwe_name = cwe_info['vuln_name']
        severity = cwe_info['severity']
        cwe_description = cwe_info['vuln_description']
        file_location_path = script_response.file_dir  #change according to the developer
        # stringify the keyword pattern 
        keyword_pattern = stringifyWord(script_response.keyword)

        result_db_req_func.post_result_vul_cwe_to_RD(scan_uuid, severity, location , cwss, cwe_id , cwe_name, cwe_description, cwe_solution , file_location_path , keyword_pattern, count)

    return vuln_cwe
    
def calc_risk_score(plugins_num, scan_uuid):
    data_dict = result_db_req_func.get_vuln_cwss(scan_uuid)
    vuln_cwss = 0 
    for item in data_dict:
        vuln_cwss += int(item['cwss'])
    try:
        risk_score = vuln_cwss / (plugins_num * 100) * 100
        return risk_score
    except ZeroDivisionError:
        print("Error: plugins_num cannot be zero.")
        return 0
    
#---------------------------------
class plugin_response:
    def __init__(self, retrieved_response, cwe_id, count):
        self.retrieved_response = retrieved_response
        self.cwe_id = cwe_id
        self.count = count

def attack_network(globals, ip_address):
    start_time = datetime.now()
    scan_id = globals.scan_id
    if not scan_id:
        return
    
    port_list = scan_ports.port_conf(ip_address)
    if not isinstance(port_list, list):
        return 'Error: Make sure all the required ports are open'
    elif len(port_list) == 0:
        return 'Error: No plugins to run'

    nasl_interpreter.parse_nasl_to_plugins(port_list)

    #--------- Initialize the attack
    plugins_num = plugin_init.count_files_existing()
    print("Number of plugins: ", plugins_num, '\n')

    webapp_cwe_num = retrieve_cwe_num_from_folder('web_app')
    filesys_cwe_num = retrieve_cwe_num_from_folder('file_sys')
    # print ('webapp_cwe_num: ', webapp_cwe_num)
    # print ('filesys_cwe_num: ', filesys_cwe_num)

    response_lists = plugin_init.import_plugins_files(ip_address)

    webapp_plugins_response_list = response_lists[0]
    filesys_plugins_response_list = response_lists[1]

    print("\nLength of the web-app plugins responses", len(webapp_plugins_response_list))
    print("Length of the file-sys plugins responses", len(filesys_plugins_response_list), '\n')
    print("***********************************************************************************************************")
    print("Summary of the scan:")
    
    # compare the retrieved result from the web application 
    if len(webapp_plugins_response_list) != 0:
        webapp_vuln_cwe_list = webapp_plugins_scan(scan_id, ip_address, webapp_plugins_response_list)
        # print('detected_cwe: ', webapp_vuln_cwe_list)
        for cwe in webapp_cwe_num :
            if str(cwe) in webapp_vuln_cwe_list:
                print(f'This machine is vulnerable to CWE{cwe}.')
            else:
                print(f'This machine is not vulnerable to CWE{cwe}.')

    if len(filesys_plugins_response_list) != 0:
        # post the vuln res to RD
        filesys_vuln_cwe_list = filesys_plugins_scan(scan_id, filesys_plugins_response_list)
        # print('detected_cwe: ', filesys_vuln_cwe_list)

        for cwe in filesys_cwe_num:
            if str(cwe) in filesys_vuln_cwe_list:
                print(f'This machine is vulnerable to CWE{cwe}.')
            else:
                print(f'This machine is not vulnerable to CWE{cwe}.')

    end_time = datetime.now()

    low_vuln = result_db_req_func.get_vul_severity_count(scan_id, 'Low')
    med_vuln = result_db_req_func.get_vul_severity_count(scan_id, 'Medium')
    high_vuln = result_db_req_func.get_vul_severity_count(scan_id, 'High')

    # total_vuln = sum([low_vuln, med_vuln, high_vuln])
    risk_score = calc_risk_score(plugins_num, scan_id)

    result_db_req_func.post_result_scan_to_RD(scan_id, start_time, end_time, low_vuln, med_vuln, high_vuln, ip_address, risk_score)
    # need: scan_uuid, start_time, end_time, low_vuln, med_vuln, high_vuln, host_ip, risk_score

    print("***********************************************************************************************************")
    return "Done scanning"

#------------- reporting ------------
def display_report(scan_id):
    result_scan = result_db_req_func.retrv_result_scan(scan_id)
    print("\nSCAN INFORMATION:")
    print(f"Start_time: {result_scan[0]['start_time']}")
    print(f"End_time: {result_scan[0]['end_time']}")
    print(f"Host IP: {result_scan[0]['host_ip']}")
    print(f"Average Risk Score: {result_scan[0]['risk_score']}")
    print(f"\nOverall of vulnerabilities detected\n\tLow vulnerabilities: {result_scan[0]['low_vuln']}")
    print(f"\tMedium vulnerabilities: {result_scan[0]['med_vuln']}")
    print(f"\tHigh vulnerabilities: {result_scan[0]['high_vuln']}")

    print('\n*************************************************************************')
    vuln_info = result_db_req_func.get_all_vuln_info(scan_id)
    print("VULNERABILITY SUMMARY")
    for index, item in enumerate(vuln_info):
        cwe_id = item['cwe_id']
        print(f"{index+1}. CWE{item['cwe_id']} - {item['cwe_name']}")
        print(f"Description: \n{item['cwe_description']}\n")
        print(f"Location: {item['location']}")
        print(f"CWSS: {item['cwss']}")
        print(f"Solution: \n{item['cwe_solution']}\n")
        print(f"Count: {item['count']}\n")
        patterns = result_db_req_func.get_vuln_path_pattern(scan_id, cwe_id)
        pattern_str = ''
        for i, pattern in enumerate(patterns):
            one_str = f"\t\t{i+1}. PATH: {pattern['file_location_path']} With KEYWORD: {pattern['keyword_pattern']}\n"
            pattern_str += one_str
        print(f"\n AREA DETECTED:\n {pattern_str}")
        print("#######################################################################################################################################\n")
        
#--------------main func-------------

def initialise_scanner():
    result_data = None

    print("AEGIS - VULNERABILITY SCANNING ENGINE\n")
    print("***********************************************************************************************************")

    err = 0
    
    setproctitle_init(len(sys.argv), sys.argv, os.environ)

    # Create the argument parser
    parser = argparse.ArgumentParser(description="AGES - Vulnerability Assessment Scanner")

    # Add the command-line options
    parser.add_argument('--version', '-V', action='store_true', help='Display version information')
    parser.add_argument('--cfg-specs', '-s', action='store_true', help='Print configuration settings')
    parser.add_argument('--sysconfdir', '-y', action='store_true', help='Print system configuration directory (set at compile time)')
    parser.add_argument('--scan-start', metavar='<string>', help='ID of scan to start. ID and related data must be stored into redis before.')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Access the values of the command-line options
    display_version = args.version
    print_specs = args.cfg_specs
    print_sysconfdir = args.sysconfdir
    scan_start = args.scan_start

    if print_sysconfdir:
        print("Printing system configuration directory:\n")
        print(CONF_PATH)
        return 
    
    if display_version:
        print("Displaying version information: 1.0")
        return 

    if scan_start:
        scan_uuid_init.write_scan_uuid()
        globals = ScanGlobals()
        globals.mem = g_malloc0(sys.getsizeof(ScanGlobals())) #bytearray(ScanGlobals()) shld return a size
        globals.scan_id = g_strdup(get_scan_id())
        if not globals.scan_id:
            return
        
        userip_input = scan_start #input of the ip addr
        if ip_addr_validation(userip_input):
            host_list = scan_hosts.scan_ip_or_subnet(userip_input)
            for ip_address in host_list:
                print(f"Starting scan with ID: {globals.scan_id}, target ip address: {ip_address}")
                result_data = attack_network(globals, ip_address)
                if result_data == 'Done scanning':
                    display_report(globals.scan_id)

        del globals
        del_functional_plugins_dir()
        return result_data

    if print_specs:
        print("Printing configuration settings:\n")
        content = display_conf_content(CONF_PATH)
        print(content)
        return 
    
    # Check if any options were provided
    if args == argparse.Namespace():
        print("No options provided")
        return 

        # existing end of function
    if globals.get("attack") and ip_address:
        result_data = attack_network(globals, ip_address)

    if result_data is None:
        # optional: log why
        print("No result_data generated – check scan parameters or errors above.")
        return {}

    return result_data
    