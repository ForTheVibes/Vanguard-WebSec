import requests

def get_cwe_vuln_pattern(cwe_id) -> list:
    data_list = []
    # API URL
    url = f"http://localhost:5000/get_specific_cwe_vuln_pattern/{cwe_id}"

    # Send GET request to the API
    response = requests.get(url)

    # Check the response status code
    if response.text == "CWEs not found":
        pass
    elif response.status_code == 200:
        data = response.json()
        data_list = data["CWE"]
    else:
        print("Error:", response.text)
    
    return data_list 

def post_result_vul_cwe_to_RD(scan_uuid, severity, location , cwss, cwe_id , cwe_name, cwe_description, cwe_solution , file_location_path , keyword_pattern, count):
    data = {
        'scan_uuid' : scan_uuid,
        'severity' : severity,
        'location' : location,
        'cwss' : cwss,
        'cwe_id' : cwe_id,
        'cwe_name' : cwe_name,
        'cwe_description' : cwe_description,
        'cwe_solution' : cwe_solution,
        'file_location_path' : file_location_path,
        'keyword_pattern' : keyword_pattern,
        'count' : count
    }

    # Send the POST request
    response = requests.post('http://localhost:5000/addvulndetected', json=data)

    # Check the response
    if response.status_code == 200:
        pass
    else:
        print('Error inserting result:', response.text)

def post_result_scan_to_RD(scan_uuid, start_time, end_time, low_vuln, med_vuln, high_vuln, host_ip, risk_score):
    data = {
        'scan_uuid' : scan_uuid,
        'start_time' : start_time.strftime('%a, %d %b %Y %H:%M:%S %Z'),
        'end_time' : end_time.strftime('%a, %d %b %Y %H:%M:%S %Z'),
        'low_vuln' : low_vuln,
        'med_vuln' : med_vuln,
        'high_vuln' : high_vuln,
        'host_ip' : host_ip,
        'risk_score' : round(risk_score, 1)
    }

    # Send the POST request
    response = requests.post('http://localhost:5000/addscanresult', json=data)

    # Check the response
    if response.status_code == 200:
        pass
    else:
        print('Error inserting result:', response.text)

def get_vul_severity_count(scan_uuid, severity):
    data = {
        'scan_uuid': scan_uuid,
        'severity': severity
    }

    try:
        response = requests.get('http://localhost:5000/get_vuln_severity_count', json=data)
        if response.status_code == 200:
            data = response.json()
            data_dict = data["Results"]
            return data_dict
        else:
            return 'Error retrieving data'
    except requests.exceptions.RequestException as e:
        return 'Error sending request: ' + str(e)
    
def get_vuln_cwss(scan_uuid):
    data = {
            'scan_uuid': scan_uuid,
        }

    try:
        response = requests.get('http://localhost:5000/get_total_vuln_cwss', json=data)
        if response.status_code == 200:
            data_dict = response.json()
            return data_dict
        else:
            return 'Error retrieving data'
    except requests.exceptions.RequestException as e:
        return 'Error sending request: ' + str(e)


def get_vuln_path_pattern(scan_uuid, cwe_id):
    try:
        url = "http://localhost:5000/getvulnpathpattern"  # Replace with the actual API URL

        # Set up the request headers and data (if required)
        headers = {'Content-Type': 'application/json'}
        data = {'scan_uuid': scan_uuid, 'cwe_id': cwe_id}

        response = requests.get(url, headers=headers, json=data)

        if response.status_code == 200:
            # Successful response, parse and return the data
            data = response.json()
            return data['Results']
        elif response.status_code == 404:
            # Data not found
            return "No results found"
        else:
            # Other status codes (handle as needed)
            response.raise_for_status()

    except requests.exceptions.RequestException as e:
        return f"Error retrieving results: {e}"

def get_all_vuln_info(scan_uuid):
    try:
        url = "http://localhost:5000/getallvulnscaninfo"  # Replace with the actual API URL

        # Set up the request headers and data (if required)
        headers = {'Content-Type': 'application/json'}
        data = {'scan_uuid': scan_uuid}

        response = requests.get(url, headers=headers, json=data)

        if response.status_code == 200:
            # Successful response, parse and return the data
            data = response.json()
            return data['Scanned a machine']
        elif response.status_code == 404:
            # Data not found
            return f"{scan_uuid} not found"
        else:
            # Other status codes (handle as needed)
            response.raise_for_status()

    except requests.exceptions.RequestException as e:
        return f"Error retrieving result: {e}"

def retrv_result_scan(scan_uuid):
    data = {
        'scan_uuid': scan_uuid,
    }

    try:
        response = requests.get('http://localhost:5000/getspecificscan', json=data)
        if response.status_code == 200:
            data = response.json()
            data_dict = data["Results"]
            return data_dict
        else:
            return 'Error retrieving data'
    except requests.exceptions.RequestException as e:
        return 'Error sending request: ' + str(e)