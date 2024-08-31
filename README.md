# Hash-Hunter

Hash-Hunter is a Python script designed for both hashing and unhashing processes. It offers a simple and efficient way to convert a word into its corresponding hash and, when possible, reverse a hash back into the original word using a wordlist.

## Usage

**Hashing a Word**:

```bash
python3 script.py --hash --algorithm <algorithm> <word>
```

**Hashing a File**:

```
python3 script.py --hash --algorithm <algorithm> -f words
```

**Unhashing a Word**:

```bash
python3 script.py --unhash -w <wordlist> <hash>
```

**Unhashing a File**:

```bash
python3 script.py --unhash -w <wordlist> -f hashes
```

## Install

```bash
git clone https://github.com/emp3r0r10/Hash-Hunter.git
cd Hash-Hunter
pip install -r requirements.txt
python3 Hash-Hunter.py
```

