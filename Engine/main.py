import initialise_scanner
import io
import os, sys
import contextlib 
from datetime import datetime


# @file  main.py
# @brief Main function of the scanner.
# This file separates out the "main" function of initalise_scanner.

#----- check logging func -------
def get_current_printed_output(func, *args, **kwargs):
    # Create a string buffer to capture the printed output
    output_buffer = io.StringIO()

    # Use the context manager to redirect the stdout to the buffer
    with contextlib.redirect_stdout(output_buffer):
        # Call the function with provided arguments and keyword arguments
        func(*args, **kwargs)

    # Retrieve the printed output as a string
    printed_output = output_buffer.getvalue()

    # Close the buffer to free up resources
    output_buffer.close()

    return printed_output

def get_current_timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def setting_logs(output):
    os.makedirs('logs', exist_ok=True)
    log_filename = f"log_{get_current_timestamp()}.log"

    # Set up the log file path
    log_file = os.path.join('logs', log_filename)

    try:
        # Open the file in write mode
        with open(log_file, 'w') as file:
            # Write the content to the file
            file.write(output)
        print("Content has been successfully written to the file.")
    except Exception as e:
        print(f"Error occurred while writing to the file: {e}")

#----- main() func -------
def main():
    result = initialise_scanner.initialise_scanner()
    if result != None:
        print(result)

if __name__ == "__main__":
    output = get_current_printed_output (main)
    print(output)
    setting_logs(output)