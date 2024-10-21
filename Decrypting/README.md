This folder will be the output location of the generated RSA private key. Run the setup.py if this is empty!


The next update will most probably have a Python script to decrypt the encrypted data, but for now, unfortunately, you'll have to do it yourself. 
Read through the code of the program and you can figure out how.

Although I suggest doing that, here is a pretty vague explanation:
1. Download the encrypted file from the GoFile link.
2. Create a Python script to read the file and take the RSA encrypted AES key from the end of the file.
3. RSA (CNG) decrypt the AES key with your private key.
4. AES decrypt the file with the RSA (CNG) decrypted AES key.
5. Output the data into some file with the extension of `.zip`.
