#
#CWE 312 Script
#

if(description)
{
  script_id(312);
  script_version("1.0");

  script_name(english:"Cleartext storage of sensitive information");

  script_set_attribute(attribute:"synopsis", value:"Sensitive information are stored in cleartext");
  script_set_attribute(attribute:"description",value:"The product stores sensitive information in cleartext within a resource that might be accessible to another control sphere.");
  script_set_attribute(attribute:"solution", value:"Modify application source code that will implement forms of control for sensitive information such as encryption or hashing mechanisms or algorithms to protect sensitive information stored in files.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_publication_date", value: "2023/06/23");
  script_set_attribute(attribute:"plugin_type", value: "File system");
  script_set_attribute(attribute:"plugin_ref", value: "https://cwe.mitre.org/data/definitions/321.html");
  script_set_attribute(attribute:"cwss", value: "42.6");
  script_set_attribute(attribute:"location", value: "port/22");
  script_end_attributes();

  script_summary(english: "Search and find if there are any files that can be accessed by anyone");
  script_category(ACT_GATHER_INFO);

  script_copyright(english: "Copyright(c) 2023");
  script_family(english: "File manipulation");

  script_timeout(1800);

  exit(0);
}

# Attack code
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException
import re
import sys
import os

# Get the current file's directory
current_dir = os.path.dirname(os.path.abspath(__file__))

# Create the path to the other folder
other_folder_path = os.path.join(current_dir, '..', 'import_nasl_tools')

# Add the other folder path to sys.path
sys.path.append(other_folder_path)
import get_creds
ssh_credentials = get_creds.get_ssh_creds()

class Response:
    def __init__(self, file_dir, keyword):
        self.file_dir = file_dir
        self.keyword = keyword

def scan_remote_filesystem(hostname, username, password, dir, sensitive_patterns):
    vuln_file_pattern_list =[]
    # Permissions to check for
    insec_permissions = [0o002, 0o020, 0o2002]

    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=username, password=password, timeout=5)
    except AuthenticationException:
        print(f"[CWE312] SSH auth failed for {username}@{hostname} – skipping plugin")
        return []  # no findings instead of raising
    except SSHException as e:
        print(f"[CWE312] SSH error for {hostname}: {e}")
        return []
    # Start the scan from this directory
    stdin, stdout, stderr = ssh.exec_command(f"find {dir} -type f -name '*.conf' -o -name '*.cfg' -o -name '*.ini'")
    files = stdout.read().decode().splitlines()

    for file in files:
        # Read file content
        stdin, stdout, stderr = ssh.exec_command("cat {}".format(file))
        try:
            content = stdout.read().decode()
        except UnicodeDecodeError:
            pass
        # Check for sensitive information patterns
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, content)
            if matches:
                res_match = Response(file, matches)
                vuln_file_pattern_list.append(res_match)

    # Close the SSH connection
    ssh.close()
    return vuln_file_pattern_list

def run_script(target_host):
    # Sensitive information patterns
    sensitive_patterns = [
        "(?i)password[\"']?\s*[:=]\s*[\"']?(\w+)[\"']?",
        "(?i)credentials[\"']?\s*[:=]\s*[\"']?(\w+)[\"']?",
        "(?i)secret[\"']?\s*[:=]\s*[\"']?(\w+)[\"']?"
    ]

    # Provide the hostname, username, and password for the remote machine
    username = ssh_credentials[0]
    password = ssh_credentials[1]

    # Scan the remote machine
    res = scan_remote_filesystem(target_host, username, password, "/etc", sensitive_patterns)
    if not res:
        return []
    return res
    
# End of attack code
