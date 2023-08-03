import os
import sys
import rsa
import argparse
import theLockLib
import pyperclip


# Script Location
SL = os.path.dirname(__file__)
if getattr(sys, 'frozen', False):
    SL = os.path.dirname(sys.executable)


RSA_KEY_FILE_NAME = os.path.normpath(f"{SL}/key.pub")
RSA_STATIC_KEY = b""""""
RSA_FROM_FILE = len(RSA_STATIC_KEY) == 0

ARCHIVE_PASSWORD_NONE = False
ARCHIVE_PASSWORD_FROM_FILE = True
ARCHIVE_PASSWORD_FILE_NAME = os.path.normpath(f"{SL}/password")
ARCHIVE_PASSWORD = "zaq1@WSX"
ARCHIVE_PART_SIZE = 512

TMP_FOLDER_NAME = os.path.normpath(f"{SL}/tmp")
FINAL_EXTENSION = ".encrypted"
COMPRESSION_LEVEL = 9


def getRsaKey(private: bool = False) -> rsa.PublicKey | rsa.PrivateKey:
    global rsa_key
    try:
        if rsa_key is rsa.PublicKey or rsa_key is rsa.PrivateKey:
            return rsa_key
    except NameError:
        pass
    if RSA_FROM_FILE:
        if private:
            rsa_key = theLockLib.getRsaPrivateKeyFromFile(RSA_KEY_FILE_NAME)
        else:
            rsa_key = theLockLib.getRsaPublicKeyFromFile(RSA_KEY_FILE_NAME)
    else:
        if private:
            rsa_key = rsa.PrivateKey.load_pkcs1(RSA_STATIC_KEY)
        else:
            rsa_key = rsa.PublicKey.load_pkcs1(RSA_STATIC_KEY)
    return rsa_key


def rsaKeyFromClipBoard(private: bool = False) -> None:
    global RSA_STATIC_KEY
    RSA_STATIC_KEY = pyperclip.paste()
    global RSA_FROM_FILE
    RSA_FROM_FILE = False


def getArchivePassword() -> str | None:
    global archive_password
    if ARCHIVE_PASSWORD_NONE:
        archive_password = None
        return None
    try:
        if archive_password is not None:
            return archive_password
    except NameError:
        pass
    archive_password = ARCHIVE_PASSWORD
    if ARCHIVE_PASSWORD_FROM_FILE:
        if not os.path.exists(ARCHIVE_PASSWORD_FILE_NAME):
            raise FileNotFoundError("No password file")
        with open(ARCHIVE_PASSWORD_FILE_NAME, 'r') as file:
            archive_password = file.read().strip()
    return archive_password


class Atributes:
    filename: str
    nopassword: bool
    recursive: bool
    force: bool
    output: str
    archive_compression_level: int
    part_size: int
    password: str
    extension: str
    skip: list[str]
    verbose: bool
    verbose_pretty: bool
    verbose_all: bool
    rsa_key_file: str
    rsa_from_clipboard: bool
    temporary_folder: str
    decrypt: bool


def parseArgs() -> Atributes:
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str, help="File or folder to encrypt")
    parser.add_argument('-np', '--nopassword', action='store_true',
        help="Skip additional password encyption (password file required)")
    parser.add_argument('-r', '--recursive', action='store_true',
        help="Instead encypting whole folder encrypt every file in it")
    parser.add_argument('-f', '--force', action='store_true',
        help="Rencrypt files and override encrypted files")
    parser.add_argument('-o', '--output', type=str, action='store',
        help="Target file or folder in case of recursion")
    parser.add_argument('-c', '--archive-compression-level', type=int, action='store',
        default=COMPRESSION_LEVEL,
        help=f"Level of compression 0-9 (default: {COMPRESSION_LEVEL})")
    parser.add_argument('-s', '--part-size', type=int, action='store',
        default=ARCHIVE_PART_SIZE,
        help=f"Max size of one file part in MB (default: {ARCHIVE_PART_SIZE}MB)")
    parser.add_argument('-p', '--password', type=str, help="Password", action='store')
    parser.add_argument('-pf', '--password-file', type=str, action='store',
        default=ARCHIVE_PASSWORD_FILE_NAME,
        help=f"File with password (default: {ARCHIVE_PASSWORD_FILE_NAME})")
    parser.add_argument('-e', '--extension', type=str, action='store',
        default=FINAL_EXTENSION,
        help=f"File suffix added to encrypted files (default: {FINAL_EXTENSION})")
    parser.add_argument('-k', '--skip', action='store', type=list[str], nargs='*',
        default=[FINAL_EXTENSION], help="Skip files with given suffixes")
    parser.add_argument('-v', '--verbose', action='store_true',
        help="Verbose mode that print affected files")
    parser.add_argument('-vp', '--verbose-pretty', action='store_true',
        help="Verbose mode that print more information")
    parser.add_argument('-va', '--verbose-all', action='store_true',
        help="Verbose mode that print more information")
    parser.add_argument('-rsa', '--rsa-key-file', type=str, action='store',
        default=RSA_KEY_FILE_NAME,
        help=f'File with RSA key (default: {RSA_KEY_FILE_NAME})')
    parser.add_argument('-rc', '--rsa-from-clipboard', action='store_true',
        help=
        f'Take RSA key from clipboard instead of file (default: {RSA_KEY_FILE_NAME})')
    parser.add_argument('-t', '--temporary-folder', type=str, action='store',
        default=TMP_FOLDER_NAME, help='Temporary folder location - ' + 
        f'it should not exists (default: {TMP_FOLDER_NAME})')
    parser.add_argument('-d', '--decrypt', action='store_true',
        help='Decryption mode')
    ans = Atributes()
    parser.parse_args(namespace=ans)
    return ans


def encryption(args: Atributes) -> None:
    if args.recursive:
        results = theLockLib.encryptRecursively(args.filename, getRsaKey(),
            args.output, outputExtension=args.extension, override=args.force,
            archivePassword=getArchivePassword(),
            compressionLevel=args.archive_compression_level,
            archivePartSize=args.part_size*1024*1024,
            tmpFolderName=args.temporary_folder, extensionsToSkip=args.skip)
        if args.verbose or args.verbose_all or args.verbose_pretty:
            for src, path, updated in results:
                if args.verbose_pretty:
                    if updated == 0:
                        print(f'{src} -> {path} (encrypted)')
                    elif updated == 1:
                        print(f'{src} -> {path} (already exists - skipped)')
                    elif updated == 2:
                        print(f"{src} (skipped due to it's suffix)")
                    else:
                        print(f"{src} -> {path}")
                elif updated == 0 or args.verbose_all:
                    print(path)
    else:
        target = f"{args.output}{args.extension}"
        result = theLockLib.encrypt(args.filename, getRsaKey(),
            target,
            override=args.force, archivePassword=getArchivePassword(),
            compressionLevel=args.archive_compression_level,
            archivePartSize=args.part_size*1024*1024,
            tmpFolderName=args.temporary_folder)
        if args.verbose_pretty:
            if result:
                print(f"{args.filename} -> {target} (encrypted)")
            else:
                print(f"{args.filename} -> {target} (already exists - skipped)")
        elif args.verbose_all or result and args.verbose:
            print(target)


def decryption(args: Atributes) -> None:
    if args.recursive:
        pass
    else:
        theLockLib.decrypt(args.filename, getRsaKey(True), args.output,
            tmpFolderName=args.temporary_folder, override=args.force,
            archivePassword=getArchivePassword())


def main() -> None:
    args = parseArgs()
    args.filename = os.path.normpath(args.filename)
    if not os.path.exists(args.filename):
        print('No such file or directory exists')
        return
    if args.rsa_from_clipboard:
        rsaKeyFromClipBoard()
    global RSA_KEY_FILE_NAME
    RSA_KEY_FILE_NAME = args.rsa_key_file
    try:
        _ = getRsaKey(args.decrypt)
    except ValueError as e:
        print(str(e))
        return
    except FileNotFoundError as e:
        print(str(e))
        return
    except Exception as e:
        print("Unhandled exception:")
        print(str(e))
    if args.password is not None:
        global archive_password
        archive_password = args.password
    else:
        global ARCHIVE_PASSWORD_FILE_NAME
        ARCHIVE_PASSWORD_FILE_NAME = args.password_file
    global ARCHIVE_PASSWORD_NONE
    ARCHIVE_PASSWORD_NONE = args.nopassword
    try:
        if args.decrypt:
            decryption(args)
        else:
            encryption(args)
    # except FileNotFoundError as e:
    #     print(str(e))
    except FileExistsError as e:
        print(str(e))
    except PermissionError as e:
        print(str(e))
        print("Possible cause: file is opened")
    # except Exception as e:
    #     print("Unhandled exception:")
    #     print(str(e))
    # theLockLib.deletePath(args.temporary_folder)
    

if __name__ == "__main__":
    main()
