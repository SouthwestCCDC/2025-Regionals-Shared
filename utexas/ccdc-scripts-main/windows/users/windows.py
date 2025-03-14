import subprocess
import shlex
import string
import random
from typing import Callable

class WindowsUserManager:
    def __init__(self):
        self.allowed_characters = string.ascii_letters + string.digits + '-_.?![]+=:^()'
        
    def load_wordlist(self, filename: str = 'words.txt') -> None:
        f = open(filename, 'r')
        self.words = f.readlines()
        f.close()
    
    def generate_password(self, length: int) -> str:
        return ''.join(random.choice(self.allowed_characters) for i in range(length))

    def generate_passphrase(self, length: int) -> str:
        word_list = (x.strip() for x in random.sample(self.words, length))
        return 'Ut-'+('-'.join((x.upper() if random.random() > 0.5 else x) for x in word_list))

    def get_local_users(self) -> list[str]:
        raw_out = subprocess.check_output(shlex.split(f'net user')).decode('utf-8')
        s_index = raw_out.index('--\r\n')
        e_index = raw_out.index('The command completed successfully.\r\n')
        users = raw_out[s_index+4:e_index].split()
        return [u.strip() for u in users if u.strip() != '']
    
    def iterate_users(self, output_file: str, user_filter: Callable[[str],bool], generate_output: Callable[[str,str],str], length: int = 0, passphrase: bool = False) -> dict[str, str] | None:
        if length == 0:
            users = self.get_local_users()
            users = [u for u in users if user_filter(u)]
            output = '\n'.join(generate_output(u, None) for u in users)
            with open(output_file, 'w') as f:
                f.write(output)
            return None
        
        users = self.get_local_users()
        # user_passwords = {}
        output = ""
        if passphrase:
            self.load_wordlist()
        users = [u for u in users if user_filter(u)]
        user_passwords = {u: (self.generate_passphrase(length) if passphrase else self.generate_password(length)) for u in users}
        output = '\n'.join(generate_output(u, p) for u, p in user_passwords.items())
        with open(output_file, 'w') as f:
            f.write(output)
        return user_passwords
    
    def write_passwords_to_file(self, user_passwords: dict[str, str], filename: str) -> None:
        data = [f'{user},{password}' for user, password in user_passwords.items()]
        chunk_size = 100
        for i in range(0, len(data), chunk_size):
            with open(f'{filename}-part{i//chunk_size}.txt', 'w') as f:
                f.write('\n'.join(data[i:i+chunk_size]))


class WindowsModules:

    whitelist = []
    blacklist = []

    def enable_ad_user(user: str, password: str) -> str:
        return f'Enable-ADAccount {user}'

    def disable_ad_user(user: str, password: str) -> str:
        return f'Disable-ADAccount {user}'
    
    def remove_ad_user(user: str, password: str) -> str:
        return f'Remove-ADUser {user}'

    def set_user_password(user: str, password: str) -> str:
        return f'net user {user} "{password}"'

    def add_user_to_group(user: str, password: str) -> str:
        return f'Add-ADGroupMember -Identity "Group Name" -Members {user}'

    def check_user_enabled(user: str) -> bool:
        raw_out = subprocess.check_output(shlex.split(f'net user {user} /domain')).decode('utf-8')
        raw_out = raw_out[raw_out.index('Account active'):].split()
        return raw_out[2] == 'Yes'
    
    def load_whitelists(*filenames: str) -> None:
        WindowsModules.whitelist = []
        for filename in filenames:
            with open(filename, 'r') as f:
                WindowsModules.whitelist.extend(f.readlines())
        WindowsModules.whitelist = [x.strip() for x in WindowsModules.whitelist]

    def load_blacklists(*filenames: str) -> None:
        WindowsModules.blacklist = []
        for filename in filenames:
            with open(filename, 'r') as f:
                WindowsModules.blacklist.extend(f.readlines())
        WindowsModules.blacklist = [x.strip() for x in WindowsModules.blacklist]

    def custom_user_filter(user: str) -> bool:
        avoid_list = ['Administrator', 'krbtgt']
        if user in avoid_list:
            return False
        blackteam_str = 'black'
        if blackteam_str in user:
            return False
        return user not in WindowsModules.blacklist
    
    def simple_whitelist(user: str) -> bool:
        return user in WindowsModules.whitelist
    
    def simple_blacklist(user: str) -> bool:
        return user not in WindowsModules.blacklist




if __name__ == '__main__':
    windows_user_manager = WindowsUserManager()

    # example: remove fired users
    # WindowsModules.load_whitelists('fired.txt')
    # windows_user_manager.iterate_users('fire_users.ps1', WindowsModules.simple_whitelist, WindowsModules.remove_ad_user)

    # example: rotate all user passwords
    WindowsModules.load_blacklists('windows/default-blacklist.txt')
    local_password_data = windows_user_manager.iterate_users('change_passwords.ps1', WindowsModules.simple_blacklist, WindowsModules.set_user_password, length=16)
    windows_user_manager.write_passwords_to_file(local_password_data, 'passwords')
