# chappie
This program uses a word list to attempt to discover the password of Mikrotik hotspot users when CHAP is enabled.

It requires that login page from the Mikrotik device be captured as it is transmitted to the hotspot user.
This login page contains javascript code that includes salt values that are hashed in conjunction with the user's password to authenticate with the Mikrotik hotspot.

Example: document.sendin.password.value = hexMD5('\013' + document.login.password.value + '\331\303\150\252\305\333\221\356\363\354\003\025\056\232\163\311')

Additionally, this script requires that the hashed password be captured as it is posted to the Mikrotik device.
Example: username=user1&password= dba5fe239907280fad8a5ba4167fc55f &dst=&popup=true

Using the salt values and a password list, hashes are generated and then compared to the collected hashes.  If a match is found, then the password used to generate the hash is valid.

************************************************************************************************************************************************************


Mikrotiks use the md5.js javascript module to generate hashes
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
