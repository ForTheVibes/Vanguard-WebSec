#
#CWE 359 Script
#

if(description)
{
  script_id(359);
  script_version("1.0");

  script_name(english:"Exposure of Private personal information to an unauthorized author");

  script_set_attribute(attribute:"synopsis", value:"Application does not properly protect an individual private personal information from unauthorized actors.");
  script_set_attribute(attribute:"description",value:"The product does not properly prevent a person's private, personal information from being accessed by actors who either (1) are not explicitly authorized to access the information or (2) do not have the implicit consent of the person about whom the information is collected.");
  script_set_attribute(attribute:"solution", value:"Modify application source code that will implement forms of control for sensitive information");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_publication_date", value: "2023/06/23");
  script_set_attribute(attribute:"plugin_type", value: "Web application");
  script_set_attribute(attribute:"plugin_ref", value: "https://cwe.mitre.org/data/definitions/359.html");
  script_set_attribute(attribute:"cwss", value: "62.6");
  script_set_attribute(attribute:"location", value: "port/80");
  script_end_attributes();

  script_summary(english: "Search and find if there are any files that can be accessed by anyone");
  script_category(ACT_GATHER_INFO);

  script_copyright(english: "Copyright(c) 2023");
  script_family(english: "Application abuses");

  script_timeout(1800);

  exit(0);
}


# Attack code
import platform
import requests

def http_get_user_agent(vt_string=None, dont_add_oid=False):
    ua_vt_string = vt_string if vt_string else "scanner-VT"
    vendor = platform.platform()  # Get platform information as vendor
    default = ""
    if vendor:
        default = f"Mozilla/5.0 [en] (X11, U; {vendor})"
    else:
        default = f"Mozilla/5.0 [en] (X11, U; {ua_vt_string})"
    
    if '_http_func_user_agent' in globals() and not dont_add_oid:
        ua = globals()['_http_func_user_agent']
    else:
        ua = "Default User Agent"

        if 'http/user-agent' in globals() and globals()['http/user-agent']:
            ua = globals()['http/user-agent']
            globals()['_http_func_user_agent'] = ua
        else:
            globals()['_http_func_user_agent'] = default
            ua = default

    return ua


def get_web_res(ip_address):
    res_list =[]
    target_url = "http://"+ ip_address + "/payment.html"

    # Get the User Agent string
    user_agent = http_get_user_agent()

    # Set the User-Agent header in the HTTP request
    headers = {"User-Agent": user_agent}

    try:
        response = requests.get(target_url, headers=headers)
        res_list.append(response.text)
    
    except requests.RequestException as e:
        print("HTTP Request Failed:", str(e))
    return res_list
    
def run_script(target_host):
    res = get_web_res(target_host)
    if len(res) == 0:
        return None
    return res

# End of attack code