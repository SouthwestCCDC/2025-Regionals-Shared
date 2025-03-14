import csv
import argparse

class LDAPProcessor:
    def __init__(self):
        self.gid_number = 5000

    def generate_ldif(self, row: list[str]) -> str:
        self.gid_number += 1
        return f"""
uid={row[0]},ou=users,dc=example,dc=com
gid: {self.gid_number}
...
"""

    def process_csv(self, input_file: str, output_file: str) -> None:
        with open(output_file, 'w') as f:
            with open(input_file) as csvfile:
                csv_data = csv.reader(csvfile)
                for row in csv_data:
                    f.write(self.generate_ldif(row))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate LDIF files from CSV data')
    parser.add_argument('-i', '--input_file', required=True, help='The DN of the manager account (required)')
    parser.add_argument('-o', '--output_file', required=True, help='The password of the manager account (required)')
    args = parser.parse_args()

    ldap_processor = LDAPProcessor()
    ldap_processor.process_csv(args.input_file, args.output_file)