# iker_transforms_parser

Python script to parse the output from iker.py and get the transform sets in a format that can be used with other tools like ike-scan. Also grabs the vpn groups if available.

## Usage

```shell
usage: parse_transforms_from_iker_output.py [-h] -f IKER_FILE -o OUTPUT [-c]

Parse the transform set numbers from raw iker log output.

options:
  -h, --help            show this help message and exit
  -f IKER_FILE, --iker-file IKER_FILE
                        iker output.log file
  -o OUTPUT, --output OUTPUT
                        output file to write results.
  -c, --check-vpn-groups
                        makes a get request to the ip URL over default https and parses out the
                        VPN groups from the dropdown if it exists.

# example
python3 parse_transforms_from_iker_output.py --iker-file iker-scan-fullalgs.log --output all-valid-transform-sets.txt --check-vpn-groups
```
