import os
import sys
import rsa                              # pip install rsa
from cryptography.fernet import Fernet  # pip install cryptography
import pyminizip                        # pip install pyminizip
import shutil
import argparse


# Script Location
SL = os.path.dirname(__file__)
if getattr(sys, 'frozen', False):
    SL = os.path.dirname(sys.executable)


RSA_FROM_FILE = True
KEY_FILE_NAME = f"{SL}/key.pub"
STATIC_KEY = b"""

"""

ARCHIVE_PASSWORD_NONE = False
ARCHIVE_PASSWORD_FROM_FILE = True
ARCHIVE_PASSWORD_FILE_NAME = f"{SL}/password"
ARCHIVE_PASSWORD = "zaq1@WSX"

TMP_FOLDER_NAME = f"{SL}/tmp"
KEY_EXTENSION = "key"
FINAL_EXTENSION = "encrypted"


def getRsaKey() -> None:
    global rsa_key
    try:
        if rsa_key is not None:
            return
    except NameError:
        pass
    rsa_key = STATIC_KEY
    if RSA_FROM_FILE:
        if not os.path.exists(KEY_FILE_NAME):
            print("No RSA public key found")
            sys.exit()
        with open(KEY_FILE_NAME, 'rb') as file:
            rsa_key = file.read()
    rsa_key = rsa.PublicKey.load_pkcs1(rsa_key)


def getArchivePassword() -> None:
    global archive_password
    if ARCHIVE_PASSWORD_NONE:
        archive_password = ''
        return
    try:
        if archive_password is not None:
            return
    except NameError:
        pass
    archive_password = ARCHIVE_PASSWORD
    if ARCHIVE_PASSWORD_FROM_FILE:
        if not os.path.exists(ARCHIVE_PASSWORD_FILE_NAME):
            print("No password file")
            sys.exit()
        with open(ARCHIVE_PASSWORD_FILE_NAME, 'r') as file:
            archive_password = file.read().strip()


def inputYN(msg: str, default: bool | None = None,
    tryAgain: str | None = "Invalid input. Try again" ,
    y: str = 'Y', n: str = 'N', defaultWord: str = "default") -> bool:
    if default is not None:
        dw = n
        if default:
            dw = y
        msg = f"{msg} ({defaultWord}: {dw}) ({y}/{n}): "
    else:
        msg = f"{msg} ({y}/{n}): "
    v = input(msg).strip().lower()
    if tryAgain is not None:
        msg = f"{tryAgain}: "
    while len(v) > 1 or (len(v) == 0 and default is None) \
        or (len(v) != 0 and v[0] != 'y' and v[0] != 'n'):
        v = input(msg).strip().lower()
    return (len(v) == 0 and default is not None) or v[0] == 'y'


def deleteTmpFolder() -> None:
    shutil.rmtree(TMP_FOLDER_NAME)
    

def prepareTmpFolder() -> None:
    if os.path.exists(TMP_FOLDER_NAME):
        print(f"Folder with name {TMP_FOLDER_NAME} already exists",
              "it maybe caused by program crash or you created",
              "anyway please get rid of it or rename it", sep=', ')
        if inputYN("Do you want to delete it", True):
            deleteTmpFolder()
        else:
            sys.exit()
    os.mkdir(TMP_FOLDER_NAME)


def symeticEncrypt(path: str) -> None:
    key = Fernet.generate_key()
    fernet = Fernet(key)
    with open(path, 'rb') as file:
        content = file.read()
    filename = os.path.basename(path)
    with open(f"{TMP_FOLDER_NAME}/{filename}.{KEY_EXTENSION}", 'wb') as file:
        file.write(key)
    content = fernet.encrypt(content)
    with open(f"{TMP_FOLDER_NAME}/{filename}", 'wb') as file:
        file.write(content)


def asyncKeyEncrypt(path: str) -> None:
    with open(path, 'rb') as file:
        content = file.read()
    getRsaKey()
    content = rsa.encrypt(content, rsa_key)
    with open(path, 'wb') as file:
        file.write(content)


def encryptFile(path: str) -> None:
    prepareTmpFolder()
    symeticEncrypt(path)
    filename = os.path.basename(path)
    filepath = f"{TMP_FOLDER_NAME}/{filename}"
    asyncKeyEncrypt(f"{filepath}.{KEY_EXTENSION}")
    getArchivePassword()
    pyminizip.compress_multiple(
        [filepath, f"{filepath}.{KEY_EXTENSION}"],
        [],
        f"{path}.{FINAL_EXTENSION}",
        archive_password,
        9
    )
    deleteTmpFolder()


def encrypt(path: str) -> None:
    if os.path.isfile(path):
        if os.path.exists(f'{path}.{FINAL_EXTENSION}'):
            return
        encryptFile(path)
        return
    files = os.listdir(path)
    for file in files:
        encrypt(f"{path}/{file}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str)
    parser.add_argument('-np', '--nopassword', action='store_true')
    args = parser.parse_args()
    if not os.path.exists(args.filename):
        print('No such file or directory exists')
        return
    global ARCHIVE_PASSWORD_NONE
    ARCHIVE_PASSWORD_NONE = args.nopassword
    encrypt(args.filename)
    

if __name__ == "__main__":
    main()
