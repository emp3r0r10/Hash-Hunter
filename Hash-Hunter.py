import bcrypt, sys
import hashlib
import re
import argparse
from colorama import Fore, Back, Style, init
from Crypto.Hash import MD4

# ===============================================================================================
# Detect Hash Type
hash_pattern = {
    "MD5": {"length": 32, "pattern": r"^[a-fA-F0-9]{32}$"},
    "SHA-1": {"length": 40, "pattern": r"^[a-fA-F0-9]{40}$"},
    "SHA-256": {"length": 64, "pattern": r"^[a-fA-F0-9]{64}$"},
    "SHA-512": {"length": 128, "pattern": r"^[a-fA-F0-9]{128}$"},
    "SHA-3-256": {"length": 64, "pattern": r"^[a-fA-F0-9]{64}$"},
    "SHA-3-512": {"length": 128, "pattern": r"^[a-fA-F0-9]{128}$"},
    "CRC32": {"length": 8, "pattern": r"^[a-fA-F0-9]{8}$"},
    "LM": {"length": 32, "pattern": r"^[a-fA-F0-9]{32}$"},
    "bcrypt": {"length": 60, "pattern": r"^\$2[ayb]\$.{56}$"},
    "pbkdf2-sha256": {"length": None, "pattern": r"^sha256:\d+:[a-fA-F0-9]{64}:[a-fA-F0-9]{64}$"},
    "Argon2": {"length": None, "pattern": r"^\$argon2(id|d|i)\$v=\d+\$.*$"},
    "RIPEMD-160": {"length": 40, "pattern": r"^[a-fA-F0-9]{40}$"},
    "Whirlpool": {"length": 128, "pattern": r"^[a-fA-F0-9]{128}$"},
    "GOST R 34.11-94": {"length": 64, "pattern": r"^[a-fA-F0-9]{64}$"},
    "SM3": {"length": 64, "pattern": r"^[a-fA-F0-9]{64}$"},
    "BLAKE2s-256": {"length": 64, "pattern": r"^[a-fA-F0-9]{64}$"},
    "BLAKE2b-512": {"length": 128, "pattern": r"^[a-fA-F0-9]{128}$"},
}

# ===============================================================================================

# Hash Word
def hash_word(word, hash_type):
    try:
        if hash_type == "bcrypt":
            salt = bcrypt.gensalt()
            h = bcrypt.hashpw(word.encode('utf-8'), salt)
            print(Fore.GREEN + h.decode())
        else:
            hash_func = getattr(hashlib, hash_type)
            h = hash_func(word.encode('utf-8')).hexdigest()
            print(Fore.GREEN + h)
    except AttributeError:
        print(Fore.RED + "Invalid hash type")

# ===============================================================================================
# Detect Hash
def detect_hash_type(hash_string):
    for hash_type, properties in hash_pattern.items():
        if len(hash_string) == properties["length"] and re.match(properties["pattern"], hash_string):
            return hash_type
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
    parser.add_argument("--unhash", action='store_true', help="Unhashing Mode")    
    parser.add_argument("Word", nargs='?', type=str, help="A word to process")
    parser.add_argument("Hash", nargs='?', type=str, help="A hash to process")    
    parser.add_argument("-f", "--file", help="Words file", type=str)
    parser.add_argument("-a", "--algorithm", help="Hash type", type=str)
    parser.add_argument("-w", "--wordlist", help="Wordlist file", type=str)
    parser.add_argument("-o", "--output", help="Output file", type=str)
    args = parser.parse_args()

    # Show help if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

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
            print(f"{Fore.WHITE}Processing words from file: {args.file}") 
            with open(args.file, 'r') as file:
                for line in file:
                    line = line.strip()
                    hash_func = getattr(hashlib, args.algorithm)
                    h = hash_func(line.encode('utf-8')).hexdigest()
                    result = f"{h}:{line}"
                    print(Fore.GREEN + result)
                    results.append(result)
            # Save to output file if specified
            if args.output:
                with open(args.output, 'w') as outfile:
                    for result in results:
                        outfile.write(result + "\n")
                print(f"{Fore.GREEN}Results saved to: {args.output}")

    # ---------------------------------------------------------------------------
    # Unhashing Process
    elif args.unhash:
        print(f"{Fore.RED}Mode: Unhashing")
        if args.Word:
            hash_type = detect_hash_type(args.Word)
            if hash_type == "Unknown Hash":
                print(Fore.RED + "Hash type could not be determined.")
            else:
                print(Fore.CYAN + "Hash Type is: " + hash_type)
                unhash_word(args.Word, hash_type, args.wordlist, None)

        elif args.file:
            output_file = open(args.output, mode='w', encoding='utf-8') if args.output else None
            with open(args.file, mode='r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    line = line.strip()
                    hash_type = detect_hash_type(line)
                    print(Fore.CYAN + f"Hash Type is: {hash_type}")
                    if hash_type == "Unknown Hash":
                        print(Fore.RED + "Hash type could not be determined.")
                    else:
                        unhash_word(line, hash_type, args.wordlist, output_file)

            if output_file:
                output_file.close()
                print(Fore.GREEN + "Hashes saved to " + args.output)
        else:
            print(Fore.RED + "Hash file not provided.")

    else:
        print(Fore.RED + "Error: Invalid mode.")

    print(Style.RESET_ALL)
    


# ===============================================================================================
if __name__ == "__main__":
    main()