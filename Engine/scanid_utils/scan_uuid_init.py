import requests
import os
import re

def get_latest_scan_uuid():
    # API URL
    url = "http://localhost:5000/getlatestresultscanuuid"

    # Send GET request to the API
    response = requests.get(url)

    # Check the response status code
    if response.status_code == 200:
        data = response.json()
        latest_scan_uuid = data.get('latest_scan_uuid')
        return latest_scan_uuid
    else:
        return None

def generate_scan_uuid():
    latest_uuid = get_latest_scan_uuid()
    try:
        new_uuid = int(latest_uuid) + 1
        return new_uuid
    except ValueError:
        print(f"Error: Cannot convert '{latest_uuid}' to an integer.")
        return False

def write_scan_uuid():
    scan_uuid = generate_scan_uuid()
    file_path = os.path.join(os.path.dirname(__file__), '../engine.conf')

    try:
        # Read the content of the engine.conf file
        with open(file_path, 'r') as file:
            data = file.read()

        # Replace the old uuid value with the newUUID
        updated_data = re.sub(r'uuid=(.*)', f'uuid={scan_uuid}', data)

        # Write the updated content back to the file
        with open(file_path, 'w') as file:
            file.write(updated_data)

        return True

    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'.")
        return False

    except Exception as e:
        print(f"Error: {e}")
        return False
