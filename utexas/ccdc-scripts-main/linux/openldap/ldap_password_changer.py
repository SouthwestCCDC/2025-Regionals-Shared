import base64
import hashlib
import os
import subprocess
import shlex
import random
import string
import argparse

class LDAPPasswordChanger:
    def __init__(self, manager_dn: str, manager_password: str, domain: str):
        self.manager_dn = manager_dn
        self.manager_password = manager_password
        self.domain = domain
        self.temp_password_filename = '.ldap_tmp_file'
        with open(self.temp_password_filename, 'w') as f:
            f.write(manager_password)
        self.allowed_characters = string.ascii_letters + string.digits + '-_.?![]+=:^()'

    def load_word_list(self) -> list[str]:
        f = open('words.txt', 'r')
        self.words = f.readlines()
        f.close()

    def ssha_password_hash(self, password: str) -> str:
        salt = os.urandom(4)
        h = hashlib.sha1(password.encode('utf-8')+salt).digest()
        return '{SSHA}' + base64.b64encode(h+salt).decode('utf-8')
    
    def change_password(self, user_dn: str, new_password: str) -> None:
        change_command = f'ldappasswd -x -D "{self.manager_dn}" -y {self.temp_password_filename} -s {new_password} "{user_dn}"'
        subprocess.run(shlex.split(change_command))
    
    def change_password_ldif(self, user_dn: str, new_password: str) -> str:
        new_password_hash = self.ssha_password_hash(new_password)
        ldif = f"""
dn: {user_dn}
changetype: modify
replace: userPassword
userPassword: {new_password_hash}
"""
        return ldif
    
    def find_all_users(self) -> list[str]:
        search_command = f'ldapsearch -x -LLL -b "ou=users,{self.domain}" "(objectclass=posixAccount)" | grep "dn: "'
        raw_out = subprocess.check_output(shlex.split(search_command)).decode('utf-8').split()
        users = [x for x in raw_out if x != 'dn:']
        return users

    def generate_passphrase(self, length: int) -> str:
        if not hasattr(self, 'words'):
            self.load_word_list()
        word_list = (x.strip() for x in random.sample(self.words, length))
        return 'Ut-'+('-'.join((x.upper() if random.random() > 0.5 else x) for x in word_list))
    
    def generate_password(self, length: int) -> str:
        return ''.join(random.choices(self.allowed_characters, k=length))
    
    def generate_user_passwords(self, users: list[str], length: int, passphrase: bool = False) -> dict[str, str]:
        user_passwords = {}
        for user in users:
            if passphrase:
                user_passwords[user] = self.generate_passphrase(length)
            else:
                user_passwords[user] = self.generate_password(length)
        return user_passwords
    
    def change_all_passwords(self, ldif_file: str, password_file: str, length: int, passphrase: bool = False, split: int = 100) -> None:
        users = self.find_all_users()
        user_passwords = self.generate_user_passwords(users, length, passphrase=passphrase)
        modify_ldif = ''
        for user in users:
            password = user_passwords[user]
            modify_ldif += self.change_password_ldif(user, password)
        self.write_passwords_to_file(user_passwords, password_file, split)
        with open(ldif_file, 'w') as f:
            f.write(modify_ldif)
        
    def execute_modify_ldif(self, ldif_file: str) -> None:
        modify_command = f'ldapmodify -x -D "{self.manager_dn}" -y {self.temp_password_filename} -f {ldif_file}'
        subprocess.run(shlex.split(modify_command))
        os.remove(ldif_file)

    def write_passwords_to_file(self, user_passwords: dict[str, str], filename: str, chunk_size: int) -> None:
        data = [f'{user.split("=")[1].split(",")[0]},{password}' for user, password in user_passwords.items()]
        for i in range(0, len(data), chunk_size):
            with open(f'{filename}-part{i//chunk_size}.txt', 'w') as f:
                f.write('\n'.join(data[i:i+chunk_size]))

    def remove_temp_password_file(self) -> None:
        os.remove(self.temp_password_filename)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Change all user passwords in an LDAP directory')
    parser.add_argument('-o', '--ldif_file', default='modify.ldif', help='The file to write the ldif to')
    parser.add_argument('-p', '--password_file', default='passwords.txt', help='The file to write the new passwords to')
    parser.add_argument('-l', '--length', default=16, type=int, help='The length of the new passwords')
    parser.add_argument('-s', '--split', type=int, default=100, help='The number of users in each password file')
    parser.add_argument('--execute', action='store_true', help='Use this flag to execute the ldif file')
    parser.add_argument('--passphrase', action='store_true', help='Use this flag to generate random passphrases instead of passwords')
    args = parser.parse_args()
    
    manager_dn = 'cn=Manager,dc=ccdc,dc=com'
    manager_password = input("Manager password: ") # reading from stdin is probably more secure than storing plaintext in script or in command
    domain = 'dc=ccdc,dc=com'

    password_changer = LDAPPasswordChanger(manager_dn, manager_password, domain)
    password_changer.change_all_passwords(args.ldif_file, args.password_file, args.length, passphrase=args.passphrase, split=args.split)
    if args.execute:
        password_changer.execute_modify_ldif(args.ldif_file)
    password_changer.remove_temp_password_file()