import re

def transform_text_in_file(input_file, output_file):
    # Define a regular expression pattern to match [1-99] within square brackets
    pattern = re.compile(r'\s*\[\d{1,3}\]\s*')

    with open(input_file, 'r') as file_in, open(output_file, 'w') as file_out:
        for line in file_in:
            # Use the sub() method to replace the matched pattern with an empty string
            transformed_line = re.sub(pattern, '', line)
            file_out.write(transformed_line)

# Test the function with an input file and create an output file
input_filename = 'input.txt'
output_filename = 'output.txt'
transform_text_in_file(input_filename, output_filename)
