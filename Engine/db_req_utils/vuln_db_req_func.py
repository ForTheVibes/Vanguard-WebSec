import requests

def get_cwe_info(cwe_id):
    # API URL
    url = f"http://localhost:5000/getspecificcwe/{cwe_id}"

    # Send GET request to the API
    response = requests.get(url)

    # Check the response status code
    if response.status_code == 200:
        data_dict = response.json()
        return data_dict
    else:
        return False