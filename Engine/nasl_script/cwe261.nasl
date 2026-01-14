#
#CWE 261 Script
#

if(description)
{
  script_id(261);
  script_version("1.0");

  script_name(english:"Weak Encoding for Password");

  script_set_attribute(attribute:"synopsis", value:"The encoding for the password is not adequate.");
  script_set_attribute(attribute:"description",value:"Obscuring a password with a trivial encoding does not protect the password.");
  script_set_attribute(attribute:"solution", value:"Passwords should be encrypted with keys that are at least 128 bits in length for adequate security.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value: "2023/06/22");
  script_set_attribute(attribute:"plugin_type", value: "Web application");
  script_set_attribute(attribute:"plugin_ref", value: "https://cwe.mitre.org/data/definitions/261.html");
  script_set_attribute(attribute:"cwss", value: "21.1");
  script_set_attribute(attribute:"location", value: "port/80");
  script_end_attributes();

  script_summary(english: "Checks and see if the password is adequately protected by the encoding function that is it using.");
  script_category(ACT_GATHER_INFO);

  script_copyright(english: "Copyright(c) 2023");
  script_family(english: "Finger abuses");

  script_timeout(1800);

  exit(0);
}


# Attack code
import re
import requests
import hashlib
import base64
import sys
import os

# Get the current file's directory
current_dir = os.path.dirname(os.path.abspath(__file__))

# Create the path to the other folder
other_folder_path = os.path.join(current_dir, '..', '..', 'import_nasl_tools')

# Add the other folder path to sys.path
sys.path.append(other_folder_path)
import get_creds
dvwa_credentials = get_creds.get_dvwa_creds()

def get_login_dvwa(ip_address):
    res_list =[]
    cookies_json = {
        'security': 'low'
    }
    weak_algorithms = ['base64', 'md5', 'sha1']
    for algorithm in weak_algorithms:
        password = dvwa_credentials[1]
        # Encode the password using the weak algorithm
        if algorithm == 'base64':
            encoded_password = base64.b64encode(password.encode()).decode()
        else:
            encoded_password = hashlib.new(algorithm, password.encode()).hexdigest()

        payload = {
            'username': dvwa_credentials[0],
            'password': str(encoded_password),
            'Login': 'Login'
        }
    
        with requests.Session() as c:
            url = f'http://{ip_address}/dvwa/login.php'

            r = c.get(url, timeout=5)
            m = re.search(r"user_token'\s*value='(.*?)'", r.text)
            if not m:
                print(f"[CWE261] user_token not found on DVWA login page at {url}")
                return []

            token = m.group(1)
            phpsessid = r.cookies.get('PHPSESSID')
            cookies_json['PHPSESSID'] = phpsessid

            payload['user_token'] = token

            p = c.post(url, data=payload, cookies=cookies_json)

            if p.status_code != 200:
                print(f"[CWE261] login POST returned {p.status_code} for {url}")
                return []
            res_list.append(p.text)
    return res_list 

def run_script(target_host):
    # Example usage
    res = get_login_dvwa(target_host)
    if not res:
        return []
    return res
    
# End of attack code