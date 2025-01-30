# PowerShell Reverse Shell Generator

This Python script produces a customized PowerShell reverse shell payload with various obfuscation levels (0 through 3). It can also generate a single-line PowerShell command for quick copy-paste execution.

## Features

1. Command-line arguments for IP, port, and output file.  
2. Obfuscation levels:  
   • Level 0: No obfuscation  
   • Level 1: Adds junk code and random variable names  
   • Level 2: Includes Base64-encoded IP addresses and random character casing  
   • Level 3: Encrypts the IP address with AES and includes a built-in decryption function  
3. Optionally converts the final payload to a single-line command with the `--oneliner` flag.

## Usage

    python generator.py --ip <IP> --port <PORT> [--output <NAME>] [--obfuscate 0|1|2|3] [--oneliner]

Example:

    python generator.py -i 192.168.1.10 -p 8080 --obfuscate 3 -o shell --oneliner

This will generate a heavily obfuscated payload (level 3) and produce it as a one-liner saved to shell.ps1.

## Security Notice

This tool is intended for authorized security testing and educational purposes only. Refrain from using it against any assets without explicit permission. Unauthorized usage is both unethical and illegal.