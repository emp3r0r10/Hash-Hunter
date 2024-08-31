# Hash-Hunter

Hash-Hunter is a Python script designed for both hashing and unhashing processes. It offers a simple and efficient way to convert a word into its corresponding hash and, when possible, reverse a hash back into the original word using a wordlist.

## Usage

**Hashing a Word**:

```bash
python3 script.py --hash --algorithm <algorithm> <word>
```

**Hashing a File**:

```bash
python3 script.py --hash --algorithm <algorithm> -f words_file
```

**Unhashing a Word**:

```bash
python3 script.py --unhash -w <wordlist> <hash>
```

**Unhashing a File**:

```bash
python3 script.py --unhash -w <wordlist> -f hashes_file
```

## Installation

```bash
git clone https://github.com/emp3r0r10/Hash-Hunter.git
cd Hash-Hunter
pip install -r requirements.txt
python3 Hash-Hunter.py
```

## Supported Hash Algorithms

The script supports the following hash algorithms:

1. md5
2. sha1
3. sha224
4. sha256
5. sha384
6. sha512
7. blake2b
8. blake2s
9. sha3_224
10. sha3_256
11. sha3_384
12. sha3_512
13. NTLM
14. Argon2
15. Whirlpool