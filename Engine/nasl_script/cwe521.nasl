#
#CWE 521 Script
#

if(description)
{
  script_id(521);
  script_version("1.0");

  script_name(english:"Weak password requirements");

  script_set_attribute(attribute:"synopsis", value:"The application does not enforce strong user password requirements, thus making it easier for attackers to compromise accounts.");
  script_set_attribute(attribute:"description",value:"The application does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts.");
  script_set_attribute(attribute:"solution", value:"Enforce password complexity requirements according to an appropriate password policy.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value: "2023/06/23");
  script_set_attribute(attribute:"plugin_type", value: "File system");
  script_set_attribute(attribute:"plugin_ref", value: "https://cwe.mitre.org/data/definitions/521.html");
  script_set_attribute(attribute:"cwss", value: "84.1");
  script_set_attribute(attribute:"location", value: "port/22");
  script_end_attributes();

  script_summary(english: "Check for any passwords that do not meet the basic password complexity requirements.");
  script_category(ACT_GATHER_INFO);

  script_copyright(english: "Copyright(c) 2023");
  script_family(english: "General");

  script_timeout(1800);

  exit(0);
}

# Attack code
import re
import paramiko
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

def check_password_requirements(password):
    # Example password requirements
    # You can modify these requirements according to your needs
    if len(password) < 8:
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[!@#$%^&*()_+=\-{}[\]:\"|'<>?,./]", password):
        return False
    return True

class Response:
    def __init__(self, file_dir, keyword):
        self.file_dir = file_dir
        self.keyword = keyword

# Remote machine scanning
def scan_remote_filesystem(hostname, username, password, dir, keywords):
    vuln_password_file_list =[]
    try:
        # Establish SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)

        # Execute commands to scan the file system
        stdin, stdout, stderr = ssh.exec_command(f"find {dir} -type f -name '*.conf' -o -name '*.cfg' -o -name '*.ini'")
        file_paths = stdout.read().decode().splitlines()

        for file_path in file_paths:
            # Check passwords in files
            sftp = ssh.open_sftp()
            try:
                with sftp.file(file_path, "rb") as f:
                    try:
                        content = f.read().decode("utf-8")
                    except UnicodeDecodeError:
                        print("files that cannot be decoded as UTF-8")
                        continue  # Skip files that cannot be decoded as UTF-8
                    for pattern in keywords:
                        matches = re.findall(pattern, content)
                        if matches:
                            for match in matches:
                                password = match.strip()
                                if not check_password_requirements(password):
                                    res_match = Response(file_path, password)
                                    vuln_password_file_list.append(res_match)
            except PermissionError:
                continue
            except Exception as e:
                print("Error accessing file:", file_path, str(e))
            

        # Close SSH connection
        ssh.close()

    except paramiko.AuthenticationException:
        print("Authentication failed. Please check the credentials.")
    except paramiko.SSHException as e:
        print("Unable to establish SSH connection:", str(e))
    except Exception as e:
        print("An error occurred:", str(e))

    return vuln_password_file_list

def run_script(target_host):
    # Common configurations
    keywords = ["(?i)password[\"']?\s*[:=]\s*[\"']?(\w+)[\"']?"]

    # Provide the hostname, username, and password for the remote machine
    username = ssh_credentials[0]
    password = ssh_credentials[1]
    # Scan the remote machine
    res = scan_remote_filesystem(target_host, username, password, "/etc", keywords)
    return res

# End of attack code
