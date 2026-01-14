import nasl_parser
import os
import re

current_directory = os.path.dirname(os.path.abspath(__file__))

def parseDescription(cwe_num):
    file = os.path.join(current_directory, 'nasl_script', f'cwe{cwe_num}.nasl')
    with open(file) as fh:
        contents = fh.read()
    parsed_data = nasl_parser.NaslScript(contents).to_dict()
    return parsed_data

def parseAttackCode(cwe_num):
    file = os.path.join(current_directory, 'nasl_script', f'cwe{cwe_num}.nasl')
    with open(file) as fh:
        contents = fh.read()
    
    pattern = r'# Attack code\n(.*?)\n# End of attack code'

    # Search for the attack code in the NASL script
    match = re.search(pattern, contents, re.DOTALL)

    if match:
        # Extract the attack code from the matched group
        attack_code = match.group(1)
        return attack_code.strip()
    else:
        # If no match found, return None or handle the error accordingly
        return None

def create_functional_plugins_folder():
    # Create the path to the other folder
    folder_path = os.path.join(current_directory, 'functional_plugins')

    try:
        os.mkdir(folder_path)
    except FileExistsError:
        pass
    except OSError as e:
        print(f"Error creating folder: {str(e)}")

def count_nasl_files_existing():
    folder_path = os.path.join(current_directory, 'nasl_script')
    pattern = fr'{folder_path}{"/"}cwe(\d+)\.nasl'
    nasl_num_list =[]
    # Iterate through all items in the folder
    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isfile(item_path):
            match = re.match(pattern, item_path)
            if match:
                number = int(match.group(1))
                nasl_num_list.append(number)
    return nasl_num_list

def port_num_extract(location):
    # Define the regular expression pattern to match the number
    pattern = r'\d+'
    
    # Use the re.findall() function to find all occurrences of the pattern in the string
    numbers = re.findall(pattern, location)
    
    # Convert the list of matched numbers to integers (assuming there's only one number in the location)
    if numbers:
        return int(numbers[0])
    else:
        return None
    
def parse_nasl_to_plugins(port_list):
    create_functional_plugins_folder()

    nasl_num_list = count_nasl_files_existing()
    for nasl in nasl_num_list:
        file_name = f'cwe{nasl}_plugin.py'
        nasl_description = parseDescription(nasl)
        port_num = port_num_extract(nasl_description['attributes']['location'])
        if port_num in port_list:
            if nasl_description['attributes']['plugin_type'] == "File system":
                folder_path = f'{current_directory}/functional_plugins/file_sys'

            elif nasl_description['attributes']['plugin_type'] == "Web application":
                folder_path = f'{current_directory}/functional_plugins/web_app'
            try:
                os.makedirs(folder_path)
            except FileExistsError:
                pass

            full_file_path = os.path.join(folder_path, file_name)
            # Use os.makedirs() to create the folder if it doesn't exist
            
            attack_code = parseAttackCode(nasl)        
            # Open the new file for writing
            with open(full_file_path, 'w') as file:
                # Write the text lines to the file
                file.write(str(attack_code))


