#!/usr/bin/env python3

import argparse
import re
import requests
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings("ignore")

def read_lines(file_path: str) -> list:
    with open(file_path, 'r') as fp:
        return [line.strip() for line in fp.readlines()]

def strip_color_codes(lines: list) -> list:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return [ansi_escape.sub('', line) for line in lines]

def parse_transforms(file_path: str, output_file: str, check_vpn_groups=False):
    content = strip_color_codes(read_lines(file_path))
    ip_transform_sets = {}

    # Regex to capture relevant lines with IP and transforms
    ip_regex = re.compile(r'IP (\d{1,3}(?:\.\d{1,3}){3})')
    transform_regex = re.compile(r'Transform found: Enc=(\w+)(?: KeyLength=(\d+))? Hash=(\w+) Group=(\d+):modp(\d+) Auth=(\w+).*')

    current_ip = None
    for line in content:
        # Match lines that contain IP addresses
        ip_match = ip_regex.search(line)
        transform_match = transform_regex.search(line)

        # If an IP is matched, update current_ip
        if ip_match:
            current_ip = ip_match.group(1)

        if transform_match and current_ip:
            # Extract transform values from the regex match
            enc_type = transform_match.group(1)
            key_length = transform_match.group(2) if transform_match.group(2) else ""

            # Extract the hash algorithm
            hash_algo = transform_match.group(3)
            auth_group = transform_match.group(4)
            # modp_group = transform_match.group(5)

            # Extract the authentication method
            auth_method = transform_match.group(6)

            # Map encryption algorithms using match/case
            match enc_type:
                case "DES":
                    enc_val = "1"
                case "IDEA":
                    enc_val = "2"
                case "Blowfish":
                    enc_val = "3"
                case "RC5":
                    enc_val = "4"
                case "3DES":
                    enc_val = "5"
                case "CAST":
                    enc_val = "6"
                case "AES":
                    enc_val = f"7/{key_length}" if key_length else "7"  # AES needs key length (7/128, 7/192, 7/256)
                case "Camellia":
                    enc_val = f"8/{key_length}" if key_length else "8"  # Camellia might also have key length
                case "Mars":
                    enc_val = "65001"
                case "RC6":
                    enc_val = "65002"
                case "ID_65003":
                    enc_val = "65003"
                case "Serpent":
                    enc_val = "65004"
                case "Twofish":
                    enc_val = "65005"
                case _:
                    enc_val = "0"  # Default value for unknown algorithms

            # Map hashing algorithms using match/case
            match hash_algo:
                case "MD5":
                    hash_val = "1"
                case "SHA1":
                    hash_val = "2"
                case "Tiger":
                    hash_val = "3"
                case "SHA2-256":
                    hash_val = "4"
                case "SHA2-384":
                    hash_val = "5"
                case "SHA2-512":
                    hash_val = "6"
                case _:
                    hash_val = "0"  # Default value for unknown algorithms

            # Map authentication methods using match/case
            match auth_method:
                case "PSK":
                    auth_val = "1"
                case "DSS":
                    auth_val = "2"
                case "RSA_Sig":
                    auth_val = "3"
                case "RSA_Enc":
                    auth_val = "4"
                case "RSA_RevEnc":
                    auth_val = "5"
                case "ElGamel_Enc":
                    auth_val = "6"
                case "ElGamel_RevEnc":
                    auth_val = "7"
                case "ECDSA_Sig":
                    auth_val = "8"
                case "ECDSA_SHA256":
                    auth_val = "9"
                case "ECDSA_SHA384":
                    auth_val = "10"
                case "ECDSA_SHA512":
                    auth_val = "11"
                case "CRACK":
                    auth_val = "128"
                case "Hybrid_RSA":
                    auth_val = "64221"
                case "Hybrid_DSS":
                    auth_val = "64223"
                case "XAUTH_PSK":
                    auth_val = "65001"
                case "XAUTH_DSS":
                    auth_val = "65003"
                case "XAUTH_RSA":
                    auth_val = "65005"
                case "XAUTH_RSA_Enc":
                    auth_val = "65007"
                case "XAUTH_RSA_RevEnc":
                    auth_val = "65009"
                case _:
                    auth_val = "0"  # Default value for unknown authentication methods
            # Store the transform set
            transform_set = f"{enc_val},{hash_val},{auth_val},{auth_group}"

            # Add transform to the current IP
            if current_ip not in ip_transform_sets:
                ip_transform_sets[current_ip] = []
            ip_transform_sets[current_ip].append(transform_set)

    write_output_transform_sets_file(ip_transform_sets, output_file, check_vpn_groups)
    write_html_table(ip_transform_sets)

def get_vpn_groups(ip_address: str) -> list:
    url = f"https://{ip_address}/+CSCOE+/logon.html"
    try:
        # Make a request to the URL
        response = requests.get(url, verify=False)
        response.raise_for_status()

        # Parse the HTML response to extract group names
        return parse_vpn_groups(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return []

def parse_vpn_groups(html_content: str) -> list:
    soup = BeautifulSoup(html_content, "html.parser")
    group_names = []
    
    # Find the <select> element for VPN groups and extract its options
    select_tag = soup.find('select', {'id': 'group_list'})
    if select_tag:
        options = select_tag.find_all('option')
        for option in options:
            group_names.append(option.get('value').replace('&#x2D;', '-'))

    return group_names

def write_output_transform_sets_file(ip_transform_sets: dict, output_file: str, check_vpn_groups: bool):
    # Write the transform sets to the output file
    with open(output_file, 'w') as out_file:
        for ip, transforms in ip_transform_sets.items():
            out_file.write(f"IP: {ip}\n")
            print(f"IP: {ip}")
            with open(f'{ip}-valid-transform-sets.txt', 'w') as ip_output_file:
                for transform in transforms:
                    print(transform)
                    ip_output_file.write(transform + "\n")
                    out_file.write(transform + "\n")
            if check_vpn_groups:
                vpn_groups = get_vpn_groups(ip)
                if vpn_groups:
                    print(f'VPN Groups: {vpn_groups}')
                    out_file.write('VPN Groups: ' + ','.join(vpn_groups)+'\n')
            print("\n")
            out_file.write("\n")  # Separate entries by new lines

def write_html_table(ip_transform_sets: dict):
    output_file = 'all-valid-transform-sets.html'
    # Start HTML structure
    html_content = """
    <html>
    <head>
        <title>IP Transform Sets</title>
        <style>
            table, th, td {
                border: 1px solid #ddd;
                border-collapse: collapse;
            }
            th, td {
                text-align: center;
            }
            tr:nth-child(even) {
                background-color: #f2f2f2;
            }
            th {
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <table>
            <tr>
                <th>IP</th>
                <th>Transform sets</th>
            </tr>
    """

    # Loop over the dictionary and add rows to the table
    for ip, transforms in ip_transform_sets.items():
        # Join transform sets with <br> for proper HTML formatting in a single table cell
        transform_str = "<br>".join(transforms)
        html_content += f"""
            <tr>
                <td>{ip}</td>
                <td>{transform_str}</td>
            </tr>
        """

    # End HTML structure
    html_content += """
        </table>
    </body>
    </html>
    """

    # Write the generated HTML to the output file
    with open(output_file, 'w') as file:
        file.write(html_content)

    print(f"HTML table written to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Parse the transform set numbers from raw iker log output.')
    parser.add_argument('-f', '--iker-file', type=str, required=True, help='iker output.log file')
    parser.add_argument('-o', '--output', type=str, required=True, help='output file to write results.')
    parser.add_argument('-c', '--check-vpn-groups', action='store_true', help='makes a get request to the ip URL over default https and parses out the VPN groups from the dropdown if it exists.')
    args = parser.parse_args()

    parse_transforms(args.iker_file, args.output, args.check_vpn_groups)

if __name__ == "__main__":
    main()
