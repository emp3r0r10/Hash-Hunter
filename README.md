# Hash-Hunter

Hash-Hunter is a Python script designed for generating and cracking a wide range of hash types. It supports several well-known hashing algorithms and includes functionality to detect the type of a given hash.

## Usage

**Hashing a Word**:

```bash
python3 script.py --hash --algorithm <algorithm> <word>
```

**Hashing a File**:

```bash
python3 script.py --hash --algorithm <algorithm> -f <words_file>
```

**Unhashing a Word**:

```bash
python3 script.py --crack -w <wordlist> <hash>
```

**Unhashing a File**:

```bash
python3 script.py --crack -w <wordlist> -f <hashes_file>
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

1. MD5
2. SHA1
3. SHA224
4. SHA256
5. SHA384
6. SHA512
7. SHA3_224
8. SHA3_256
9. SHA3_384
10. SHA3_512
11. blake2b
12. blake2s
13. NTLM
14. Argon2
15. Whirlpool
16. Jenkins
17. CRC32
