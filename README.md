## Python HTML Smuggler

Deliver your files behind various security measures. smuggler.py is a Python3 utility that will read the template files in /templates/ directory and generate the respective files for the delivery of your file, aes encrypted and xored. 

The encryption applied is equivalent to the OpenSSL command 

`openssl enc -aes-256-cbc -in un_encrypted.data -out encrypted.data -k <password>`.

### High level description

* A user visits the inital `index.html` page.
* From said page, the javascript file `jquery.min.js` is requested that is responsible for the smuggling.
* The javascript requests another html `data.html` that contains your file encrypted and xored with the keys you specify during the execution of the python script.
* The javascript file is prepopulated with the correct values for the aes encryption key and the xor key.
* The file reconstructed in the user's browser and the file download prompt is presented to the user.

### Things to note

In order to use the script you only need to install pycryptodome 

`pip install pycryptodome`

The javascript, upon execution will perform a request for `/data?auth_key=<value>`. That value is the user agent of the browser the javascript actually run on, xored and base64 encoded. The other script `smuggler-ua.py` can be used with that value and your xor key as inputs in order to retrieve the user agent string.

The mime-type of the file the end user will download can be tampered with but if no input is present the script will auto-determine it and prepopulate the javascript.

A javascript function responsible to detect mouse movement is present in the template js in order to avoid some sandboxes.

It is advised to not use the default values. See the scripts help for the parameters you should input. Also, you could obfuscate the javascript file.

Again, advised, to edit index.html according to the needs of your social engineering context and don't serve the pages as is, use your nginx configuration to serve the files in a believable manner.

A sample hta file is included for testing purposes.

### Help

Main utility smuggler.py:
```
usage: smuggler.py [-h] [-p ENCPASS] [-x XORPASS] [-n FNAME] [-t FTYPE] file

HTML Smuggler 

positional arguments:
  file                  File to smuggle

optional arguments:
  -h, --help            show this help message and exit
  -p ENCPASS, --pass ENCPASS
                        Encryption pass
  -x XORPASS, --xor XORPASS
                        XOR pass
  -n FNAME, --name FNAME
                        File name for download
  -t FTYPE, --type FTYPE
                        File type for download
```

Utility for retrieval of user agent smuggler-ua.py

```
usage: smuggler-ua.py [-h] [-k KEY] b64

Helper script that reverses the base64 value received on the /data?auth_key= request

positional arguments:
  b64                Base64 string as received (non url-decoded)

optional arguments:
  -h, --help         show this help message and exit
  -k KEY, --key KEY  XOR key used for smuggling
```