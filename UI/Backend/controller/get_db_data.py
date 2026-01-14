import requests
import argparse
import json

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
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("function_name", choices=["get_all_vuln_info", "get_vuln_path_pattern", "retrv_result_scan"])  # Add the new function choice
    parser.add_argument("scan_uuid")
    parser.add_argument("--cwe_id", type=int, default=None, help="Required for 'get_vuln_path_pattern' function.")
    args, unknown_args = parser.parse_known_args()

    if args.function_name == "get_all_vuln_info":
        result = get_all_vuln_info(args.scan_uuid)
    elif args.function_name == "get_vuln_path_pattern":
        if args.cwe_id is None:
            parser.error("--cwe_id is required for 'get_vuln_path_pattern' function.")
        result = get_vuln_path_pattern(args.scan_uuid, args.cwe_id)
    elif args.function_name == "retrv_result_scan":  # Add the new function case
        result = retrv_result_scan(args.scan_uuid)
    else:
        parser.error("Invalid function_name")

    # Print the result as a JSON list
    print(json.dumps(result))