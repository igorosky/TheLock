import os
import sys
import rsa                                              # pip install rsa
from cryptography.fernet import Fernet, InvalidToken    # pip install cryptography
from zipfile import ZipFile
import shutil
import argparse


# Script Location
SL = os.path.dirname(__file__)
if getattr(sys, 'frozen', False):
    SL = os.path.dirname(sys.executable)


RSA_FROM_FILE = True
KEY_FILE_NAME = f"{SL}/key.priv"
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
            print("No RSA private key found")
            sys.exit()
        with open(KEY_FILE_NAME, 'rb') as file:
            rsa_key = file.read()
    rsa_key = rsa.PrivateKey.load_pkcs1(rsa_key)


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


def decryptKey(path: str) -> bool:
    getRsaKey()
    with open(path, 'rb') as file:
        content = file.read()
    try:
        content = rsa.decrypt(content, rsa_key)
    except rsa.DecryptionError:
        return False
    with open(path, 'wb') as file:
        file.write(content)
    return True


def decryptSyncFile(path: str, outputPath: str) -> bool:
    with open(f"{path}.{KEY_EXTENSION}", 'rb') as file:
        key = file.read()
    fernet = Fernet(key)
    with open(path, 'rb') as file:
        content = file.read()
    try:
        content = fernet.decrypt(content)
    except InvalidToken:
        return False
    with open(outputPath, 'wb') as file:
        file.write(content)
    return True


def decryptFile(path: str) -> None:
    prepareTmpFolder()
    getArchivePassword()
    with ZipFile(path, 'r') as file:
        file.setpassword(bytes(archive_password, encoding="utf-8"))
        try:
            file.extractall(TMP_FOLDER_NAME)
        except RuntimeError:
            print(f'Wrong password for {path}')
            deleteTmpFolder()
            return
    destPath = path.removesuffix(f'.{FINAL_EXTENSION}')
    tmpFile = f"{TMP_FOLDER_NAME}/{os.path.basename(destPath)}"
    if not decryptKey(f"{tmpFile}.{KEY_EXTENSION}"):
        print(f'Invalid key for {path}')
    elif not decryptSyncFile(tmpFile, destPath):
        print(f'Invalid encrypted file {path}')
    deleteTmpFolder()


def decrypt(path: str) -> None:
    if os.path.isfile(path):
        if path[-(len(FINAL_EXTENSION) + 1):] != f'.{FINAL_EXTENSION}' \
            or os.path.exists(path.removesuffix(f'.{FINAL_EXTENSION}')):
            return
        decryptFile(path)
        return
    files = os.listdir(path)
    for file in files:
        decrypt(f"{path}/{file}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str)
    parser.add_argument('-np', '--nopassword', action='store_true')
    args = parser.parse_args()
    if not os.path.exists(args.filename):
        print('No such file or directory exists')
        return
    global ARCHIVE_PASSWORD_NONE
    ARCHIVE_PASSWORD_NONE = args.nopassword
    decrypt(args.filename)


if __name__ == "__main__":
    main()
