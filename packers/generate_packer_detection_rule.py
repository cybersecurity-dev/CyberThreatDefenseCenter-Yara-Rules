import os

def generate_packer_detection_rule():
    # Define metadata for the packer detection rule
    rule_metadata =  """
                     rule Packer_Detection
                     {
                         meta:
                             description = "Detects multiple packers (e.g., UPX, PECompact, MPRESS, ASPack, and more)"
                             author = "Cyber Threat Defence Center"
                             date = "2025-01-16"
                             severity = "high"
                         """
     
    # Define the strings section with patterns for different packers
    rule_strings =   """
                     strings:
                         // UPX signature
                         $upx_magic = { 75 70 78 20 } // "UPX " signature
                         $upx_string = "UPX1" // UPX string signature
 
                         // PECompact signature (packed PE files)
                         $pecompact_signature = { 4D 5A 90 00 4C 01 00 00 00 00 00 00 00 00 00 00 00 } // PECompact header
 
                         // MPRESS signature (common pattern)
                         $mpress_signature = { 4D 50 52 45 53 53 } // "MPRESS"
 
                         // ASPack signature
                         $aspack_signature = { 41 53 50 41 43 4B 00 00 } // ASPack header
 
                         // MoleBox signature
                         $molebox_signature = { 4D 4F 4C 45 42 4F 58 } // "MOLEBOX" string
                         
                         // exe32pack signature (pattern)
                         $exe32pack_signature = { 45 58 45 33 32 } // "EXE32" signature
 
                         // (Win)Upack signature (pattern)
                         $upack_signature = { 55 50 41 43 4B } // "(Win)Upack" signature
 
                         // Petite signature
                         $petite_signature = { 50 45 54 49 54 45 } // "PETITE" signature
 
                         // JDPack signature
                         $jdpack_signature = { 4A 44 50 41 43 4B } // "JDPACK" string
 
                         // NsPacK signature
                         $nspack_signature = { 4E 73 50 61 63 6B } // "NsPacK" string
 
                         // MEW signature
                         $mew_signature = { 4D 45 57 } // "MEW" header
                         
                         // Packman signature
                         $packman_signature = { 50 41 43 4B 4D 41 4E } // "PACKMAN" signature
 
                         // RLPack signature
                         $rlpack_signature = { 52 4C 50 41 43 4B } // "RLPACK" signature
 
                         // NeoLite signature
                         $neolite_signature = { 4E 45 4F 4C 49 54 45 } // "NEOLITE" string
 
                         // BeRoEXEPacker signature
                         $bero_exe_signature = { 42 45 52 4F 45 58 45 50 } // "BeRoEXEPacker" signature
 
                         // FSG signature
                         $fsg_signature = { 46 53 47 20 } // "FSG " signature
                     """
    
    # Define the condition section to check for any of the packer signatures
    rule_condition = """
                     condition:
                         // Trigger detection if any of the known packer signatures are found
                         any of (
                             $upx_magic, $upx_string,
                             $pecompact_signature,
                             $mpress_signature,
                             $aspack_signature,
                             $molebox_signature,
                             $exe32pack_signature,
                             $upack_signature,
                             $petite_signature,
                             $jdpack_signature,
                             $nspack_signature,
                             $mew_signature,
                             $packman_signature,
                             $rlpack_signature,
                             $neolite_signature,
                             $bero_exe_signature,
                             $fsg_signature
                         )
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

    # Generate Packer Detection YARA Rule
    packer_detection_rule = generate_packer_detection_rule()
    save_yara_rule_to_file(packer_detection_rule, os.path.join(input_directory, 'packer_detection_rule.yara'))

    # Output success message
    print(f"YARA rules have been generated and saved to {input_directory}.")


# Get input directory from the user
input_directory = input("Enter the directory path to save the YARA rules: ")

# Generate YARA rules based on files in the specified directory
generate_rules_for_directory(input_directory)
