import os
import importlib.util
import re

def count_files_existing():
    current_directory = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(current_directory, '..', "functional_plugins")

    count = 0

    for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.py'):
                    count += 1

    return count

class plugin_response:
    def __init__(self, retrieved_response, cwe_id, count):
        self.retrieved_response = retrieved_response
        self.cwe_id = cwe_id
        self.count = count

def import_plugins_files(ip_address):
    current_directory = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(current_directory, '..', "functional_plugins")

    webapp_response_list = []
    filesys_response_list =[]

    # Iterate through all items in the folder
    for dir in os.listdir(folder_path):
        dir_path = os.path.join(folder_path, dir)
        for item in os.listdir(dir_path):
            item_path = os.path.join(dir_path, item)
            # Check if the current item is a file and has a .py extension
            if os.path.isfile(item_path) and item.endswith('.py'):
                # Get the module name by removing the file extension
                module_name = os.path.splitext(item)[0]

                # Generate the module spec
                spec = importlib.util.spec_from_file_location(module_name, item_path)

                # Import the module
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Import all names using import *
                globals().update(vars(module))
                
                if hasattr(module, 'run_script') and callable(module.run_script):
                    match = re.search(r"cwe(\d+)_plugin\.py", str(module))
                    if match:
                        print("Running script", str(module))
                        cwe_id = match.group(1)
                        script_response = module.run_script(ip_address)

                        # Treat None as “no findings” from this plugin
                        if not script_response:
                            print(f"[PLUGIN_INIT] {module.__name__} returned no results, skipping")
                            continue

                        # If it’s a single dict/obj, wrap in list
                        if not isinstance(script_response, (list, tuple)):
                            script_response = [script_response]

                        for count, item in enumerate(script_response, start=1):
                            one_plugin_res = plugin_response(item, cwe_id, count)

                        if 'web_app' in dir_path:
                            for item in script_response:
                                count = len(script_response)
                                one_plugin_res = plugin_response(item, cwe_id, count)
                                webapp_response_list.append(one_plugin_res)
                        elif 'file_sys' in dir_path:
                            for item in script_response:
                                count = len(script_response)
                                one_plugin_res = plugin_response(item, cwe_id, count)
                                filesys_response_list.append(one_plugin_res)
                    elif not match:
                        continue
    return webapp_response_list, filesys_response_list
                 
                     


