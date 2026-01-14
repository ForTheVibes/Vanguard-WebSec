#
#CWE 260 Script
#

if(description)
{
  script_id(260);
  script_version("1.0");

  script_name(english:"Password in configuration file");

  script_set_attribute(attribute:"synopsis", value:"Passwords are stored in configuration files that are accessible by anyone");
  script_set_attribute(attribute:"description",value:"The application stores a password in a configuration file that might be accessible to actors who do not know the password.");
  script_set_attribute(attribute:"solution", value:"Avoid storing passwords in easily accessed locations and|or use a cryptographic hash to replace the passwords when storing the password.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_publication_date", value: "2023/06/23");
  script_set_attribute(attribute:"plugin_type", value: "File system");
  script_set_attribute(attribute:"plugin_ref", value: "https://cwe.mitre.org/data/definitions/260.html");
  script_set_attribute(attribute:"cwss", value: "51.1");
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
import re
import paramiko
import sys
import os

# Get the current file's directory
current_dir = os.path.dirname(os.path.abspath(__file__))

# Create the path to the other folder
other_folder_path = os.path.join(current_dir, '..','..', 'import_nasl_tools')

# Add the other folder path to sys.path
sys.path.append(other_folder_path)
import get_creds
ssh_credentials = get_creds.get_ssh_creds()

class Response:
    def __init__(self, file_dir, keyword):
        self.file_dir = file_dir
        self.keyword = keyword

# Remote machine scanning
def scan_remote_filesystem(hostname, username, password, dir, keywords):
    vuln_conf_file_list = []
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
                            res_match = Response(file_path, matches)
                            vuln_conf_file_list.append(res_match)
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

    return vuln_conf_file_list
    

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
