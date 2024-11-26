import pefile

def extract_text_section(input_file, output_file):
    # Load the PE file
    pe = pefile.PE(input_file)
    
    # Find the .text section
    text_section = None
    for section in pe.sections:
        if section.Name.decode('utf-8').strip('\x00') == '.text':
            text_section = section
            break
    
    if not text_section:
        raise Exception(".text section not found in the PE file.")
    
    # Extract the binary contents of the .text section
    text_data = text_section.get_data()

    # Write the binary data to the output file
    with open(output_file, 'wb') as output:
        output.write(text_data)
    print(f"Successfully extracted .text section to {output_file}")

# Example usage
input_executable = 'nimlessELT.exe'  # Path to your PE executable
output_binary = 'nimlessELTPIC.bin'  # Path to output binary file

extract_text_section(input_executable, output_binary)