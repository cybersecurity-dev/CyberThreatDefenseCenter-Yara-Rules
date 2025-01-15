import os

def generate_compressed_binary_detection_rule():
    # Define metadata for the compressed binary detection rule
    rule_metadata =  """
                     rule Compressed_Binary_Detection
                     {
                         meta:
                             description = "Detects compressed binary files (e.g., ZIP, GZip, LZMA)"
                             author = "Cyber Threat Defence Center"
                             date = "2025-01-15"
                             severity = "medium"
                         """
         
    # Define the strings section with compression signatures
    rule_strings =   """
                     strings:
                         // ZIP file signature (PK header)
                         $zip_signature = { 50 4B 03 04 } // "PK\x03\x04"
 
                         // GZip file signature (1F 8B)
                         $gzip_signature = { 1F 8B } // GZip signature
 
                         // LZMA signature (5D 00 00 80 00)
                         $lzma_signature = { 5D 00 00 80 00 } // LZMA signature
                         
                         // LZ77 compression pattern (common in some packed files)
                         $lz77_pattern = { 1F 8F 88 80 } // LZ77 pattern signature
                     """
         
    # Define the condition section
    rule_condition = """
                     condition:
                         // Trigger detection if any of the known compressed file signatures are found
                         any of ($zip_signature, $gzip_signature, $lzma_signature, $lz77_pattern)
                     }
                     """
    
    # Combine the metadata, strings, and condition into a full YARA rule
    yara_rule = rule_metadata + rule_strings + rule_condition
    
    return yara_rule


def save_yara_rule_to_file(rule, file_path):
    with open(file_path, 'w') as file:
        file.write(rule)


def generate_rules_for_directory(input_directory):
    # Check if the directory exists
    if not os.path.isdir(input_directory):
        print(f"Error: The directory {input_directory} does not exist.")
        return

    # Get list of all files in the directory
    files_in_directory = os.listdir(input_directory)
    
    # Check for any files in the directory
    if not files_in_directory:
        print(f"No files found in the directory {input_directory}.")
        return

    # Generate Compressed Binary Detection YARA Rule
    compressed_binary_rule = generate_compressed_binary_detection_rule()
    save_yara_rule_to_file(compressed_binary_rule, os.path.join(input_directory, 'compressed_binary_detection.yara'))

    # Output success message
    print(f"YARA rules have been generated and saved to {input_directory}.")


# Get input directory from the user
input_directory = input("Enter the directory path to save the YARA rules: ")

# Generate YARA rules based on files in the specified directory
generate_rules_for_directory(input_directory)
