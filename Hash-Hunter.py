import bcrypt
import hashlib
import binascii
import re
import argparse
import sys
import whirlpool
import zlib
from colorama import Fore, Style
from Crypto.Hash import MD4
from argon2 import PasswordHasher
from passlib.utils.binary import ab64_encode


# ===============================================================================================
# Jenkins One-at-a-Time Hash Function
def jenkins_one_at_a_time_hash(key):
    hash_value = 0
    for byte in key:
        hash_value += byte
        hash_value += (hash_value << 10)
        hash_value ^= (hash_value >> 6)
    hash_value += (hash_value << 3)
    hash_value ^= (hash_value >> 11)
    hash_value += (hash_value << 15)
    return hash_value & 0xFFFFFFFF  # Ensure hash is within 32-bit range

# ===============================================================================================
# Hash Word
def hash_word(word, hash_type):
    try:
        if hash_type == "bcrypt":
            salt = bcrypt.gensalt()
            h = bcrypt.hashpw(word.encode('utf-8'), salt)
            print(Fore.GREEN + h.decode())
        elif hash_type == "NTLM":
            h = hashlib.new('md4', word.encode('utf-16le')).digest()
            print(Fore.GREEN + binascii.hexlify(h).upper().decode())
        elif hash_type == "argon2":
            ph = PasswordHasher()
            h = ph.hash(word)
            print(h)
        elif hash_type == "whirlpool":
            h = whirlpool.new(word.encode('utf-8')).hexdigest()
            print(Fore.GREEN + h.upper())
        elif hash_type == "jenkins":
            h = jenkins_one_at_a_time_hash(word.encode('utf-8'))
            print(Fore.GREEN + f"{h:08x}")
        elif hash_type == "crc32":
            if isinstance(word, str):
                word = word.encode("utf-8")
            checksum = zlib.crc32(word)
            print(Fore.GREEN + format(checksum & 0xFFFFFFFF, '08X'))
        else:
            hash_func = getattr(hashlib, hash_type)
            h = hash_func(word.encode('utf-8')).hexdigest()
            print(Fore.GREEN + h)
    except AttributeError:
        print(Fore.RED + "Invalid hash type")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")



# ===============================================================================================
# Detect Hash
def detect_hash_type(hash_string):
    if len(hash_string) == 32:
        if all(c in '0123456789ABCDEF' for c in hash_string):
            return 'NTLM'
        return 'MD5'
    elif len(hash_string) == 128:
        if hash_string.isupper() and all(c in '0123456789ABCDEF' for c in hash_string):
            return "whirlpool"
        return "SHA-512"
    elif len(hash_string) == 40 and re.match(r"^[a-fA-F0-9]{40}$", hash_string):
        return "SHA-1"
    elif len(hash_string) == 56 and re.match(r"^[a-fA-F0-9]{56}$", hash_string):
        return "SHA-224"
    elif len(hash_string) == 64 and re.match(r"^[a-fA-F0-9]{64}$", hash_string):
        return "SHA-256"
    elif len(hash_string) == 96 and re.match(r"^[a-fA-F0-9]{96}$", hash_string):
        return "SHA-384"
    elif re.match(r"^\$2[ayb]\$.{56}$", hash_string):
        return "bcrypt"
    elif re.match(r"^\$argon2(id|d|i)\$v=\d+\$.*$", hash_string):
        return "Argon2"
    elif len(hash_string) == 8 and re.match(r"^[a-fA-F0-9]{8}$", hash_string):
        return "jenkins"
    else:
        return "Unknown Hash"

# ===============================================================================================
# Unhash Word
def unhash_word(hash_string, hash_type, wordlist, output_file=None):
    found = False
    try:
        with open(wordlist, mode='r', encoding='utf-8', errors='ignore') as wordlist_file:
            for word in wordlist_file:
                word = word.strip()
                try:
                    if hash_type == 'bcrypt':
                        if bcrypt.checkpw(word.encode('utf-8'), hash_string.encode('utf-8')):
                            found = True
                            result = f"{hash_string}:{word}"
                            print(Fore.GREEN + f"Hash Found: {result}")
                            if output_file:
                                output_file.write(result + '\n')
                            break
                    elif hash_type == 'NTLM':
                        h = hashlib.new('md4', word.encode('utf-16le')).digest()
                        hash_result = binascii.hexlify(h).upper().decode()
                        if hash_result == hash_string:
                            found = True
                            result = f"{hash_string}:{word}"
                            print(Fore.GREEN + f"Hash Found: {result}")
                            if output_file:
                                output_file.write(result + '\n')
                            break
                    elif hash_type == 'Argon2':
                        ph = PasswordHasher()
                        try:
                            if ph.verify(hash_string, word):
                                found = True
                                result = f"{hash_string}:{word}"
                                print(Fore.GREEN + f"Hash Found: {result}")
                                if output_file:
                                    output_file.write(result + '\n')
                                break
                        except VerificationError:
                            continue                                                          
                    elif hash_type == 'whirlpool':
                        h = whirlpool.new(word.encode('utf-8')).hexdigest()
                        if h.upper() == hash_string:
                            found = True
                            result = f"{hash_string}:{word}"
                            print(Fore.GREEN + f"Hash Found: {result}")
                            if output_file:
                                output_file.write(result + '\n')
                            break
                    elif hash_type == 'jenkins':
                        h = jenkins_one_at_a_time_hash(word.encode('utf-8'))
                        hash_result = f"{h:08x}"
                        if hash_result == hash_string:
                            found = True
                            result = f"{hash_string}:{word}"
                            print(Fore.GREEN + f"Hash Found: {result}")
                            if output_file:
                                output_file.write(result + '\n')
                            break                 
                    else:
                        h = hashlib.new(hash_type)
                        h.update(word.encode('utf-8'))
                        hash_result = h.hexdigest()
                        if hash_result == hash_string:
                            found = True
                            result = f"{hash_string}:{word}"
                            print(Fore.GREEN + f"Hash Found: {result}")
                            if output_file:
                                output_file.write(result + '\n')
                            break
                except ValueError as ve:
                    print(Fore.RED + f"ValueError: {ve}")
                    continue
    except FileNotFoundError:
        print(Fore.RED + "Wordlist file not found.")
        return

    if not found:
        print(Fore.RED + "Hash not found in the wordlist.")

# ===============================================================================================
# Main Process
class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action(self, action):
        if not action.option_strings:
            return super()._format_action(action)
        else:
            return "  {:25s} {}\n".format(', '.join(action.option_strings), action.help)

def main():
    # Help menu
    parser = argparse.ArgumentParser(formatter_class=CustomHelpFormatter)
    parser.add_argument("--hash", action='store_true', help="Hashing Mode")
    parser.add_argument("--crack", action='store_true', help="Cracking Mode")    
    parser.add_argument("Word", nargs='?', type=str, help="A word to process")
    parser.add_argument("Hash", nargs='?', type=str, help="A hash to process")
    parser.add_argument("-f", "--file", help="Words file", type=str)
    parser.add_argument("-a", "--algorithm", help="Hash type", type=str)
    parser.add_argument("-w", "--wordlist", help="Wordlist file", type=str)
    parser.add_argument("-o", "--output", help="Output file", type=str)
    # Check if no arguments are provided or if the first argument is '-h'
    if len(sys.argv) == 1 or sys.argv[1] == "-h":
        parser.print_help()
        sys.exit() 
    args = parser.parse_args()

    # ---------------------------------------------------------------------------    
    # Hashing Process
    if args.hash:
        print(f"{Fore.RED}Mode: Hashing")
        # Handle word
        if args.Word and args.algorithm:
            hash_type = args.algorithm
            print(f"{Fore.CYAN}Hash_Type: {args.algorithm}")            
            hash_word(args.Word, args.algorithm)
        
        # Handle words_file
        elif args.file and args.algorithm:
            results = []
            print(f"{Fore.CYAN}Hash_Type: {args.algorithm}")
            print(f"Processing words from file: {args.file}") 
            with open(args.file, 'r') as file:
                for line in file:
                    line = line.strip()
                    hash_func = getattr(hashlib, args.algorithm)
                    h = hash_func(line.encode('utf-8')).hexdigest()
                    result = f"{h}:{line}"
                    print(result)
                    results.append(result)
            # Save to output file if specified
            if args.output:
                with open(args.output, 'w') as outfile:
                    for result in results:
                        outfile.write(result + "\n")
                print(f"{Fore.GREEN}Results saved to: {args.output}")

    # ---------------------------------------------------------------------------
    # Cracking Process
    elif args.crack:        
        print(f"{Fore.RED}Mode: Cracking")
        if args.Word:
            hash_type = detect_hash_type(args.Word)
            if hash_type == "Unknown Hash":
                print(Fore.RED + "Hash type could not be determined.")
            else:
                print(Fore.CYAN + "Hash Type is: " + hash_type)                    
                unhash_word(args.Word, hash_type, args.wordlist)

        elif args.file:
            if args.output:
                with open(args.output, mode='w', encoding='utf-8') as output_file:
                    with open(args.file, mode='r', encoding='utf-8', errors='ignore') as file:
                        for line in file:
                            line = line.strip()
                            hash_type = detect_hash_type(line)
                            print(Fore.CYAN + f"Hash Type is: {hash_type}")
                            if hash_type == "Unknown Hash":
                                print(Fore.RED + "Hash type could not be determined.")
                            else:
                                unhash_word(line, hash_type, args.wordlist, output_file)
                    print(Fore.GREEN + "Hashes saved to " + args.output)
            else:
                with open(args.file, mode='r', encoding='utf-8', errors='ignore') as file:
                    for line in file:
                        line = line.strip()
                        hash_type = detect_hash_type(line)
                        print(Fore.CYAN + f"Hash Type is: {hash_type}")
                        if hash_type == "Unknown Hash":
                            print(Fore.RED + "Hash type could not be determined.")
                        else:
                            unhash_word(line, hash_type, args.wordlist)

        else:
            print(Fore.RED + "Hash file not provided.")
    
    else:
        print(Fore.RED + "Error: Invalid mode.")

    print(Style.RESET_ALL)


# ===============================================================================================
if __name__ == "__main__":
    main()
