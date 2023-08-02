import os
import sys
import rsa
import argparse
import theLockLib


# Script Location
SL = os.path.dirname(__file__)
if getattr(sys, 'frozen', False):
    SL = os.path.dirname(sys.executable)


RSA_FROM_FILE = True
KEY_FILE_NAME = os.path.normpath(f"{SL}/key.pub")
STATIC_KEY = b"""

"""

ARCHIVE_PASSWORD_NONE = False
ARCHIVE_PASSWORD_FROM_FILE = True
ARCHIVE_PASSWORD_FILE_NAME = os.path.normpath(f"{SL}/password")
ARCHIVE_PASSWORD = "zaq1@WSX"
ARCHIVE_PART_SIZE = 512

TMP_FOLDER_NAME = os.path.normpath(f"{SL}/tmp")
FINAL_EXTENSION = ".encrypted"
COMPRESSION_LEVEL = 9


def getRsaKey() -> rsa.PublicKey:
    global rsa_key
    try:
        if rsa_key is rsa.PublicKey:
            return rsa_key
    except NameError:
        pass
    if RSA_FROM_FILE:
        rsa_key = theLockLib.getRsaPublicKeyFromFile(KEY_FILE_NAME)
    else:
        rsa_key = rsa.PublicKey.load_pkcs1(STATIC_KEY)
    return rsa_key


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


def main() -> None:
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
    global ARCHIVE_PASSWORD_FILE_NAME
    parser.add_argument('-pf', '--password-file', type=str, action='store',
        default=ARCHIVE_PASSWORD_FILE_NAME,
        help=f"File with password (default: {ARCHIVE_PASSWORD_FILE_NAME})")
    parser.add_argument('-e', '--extension', type=str, action='store',
        default=FINAL_EXTENSION,
        help=f"File suffix added to encrypted files (default: {FINAL_EXTENSION})")
    parser.add_argument('-k', '--skip', action='store', nargs='*',
        default=[FINAL_EXTENSION], help="Skip files with given suffixes")
    parser.add_argument('-v', '--verbose', action='store_true',
        help="Verbose mode that print affected files")
    parser.add_argument('-vp', '--verbose-pretty', action='store_true',
        help="Verbose mode that print more information")
    parser.add_argument('-va', '--verbose-all', action='store_true',
        help="Verbose mode that print more information")
    args = parser.parse_args()
    args.filename = os.path.normpath(args.filename)
    if not os.path.exists(args.filename):
        print('No such file or directory exists')
        return
    if args.output is None:
        args.output = args.filename
    if args.password is not None:
        global archive_password
        archive_password = args.password
    else:
        ARCHIVE_PASSWORD_FILE_NAME = args.password_file
    global ARCHIVE_PASSWORD_NONE
    ARCHIVE_PASSWORD_NONE = args.nopassword
    try:
        if args.recursive:
            results = theLockLib.encryptRecursively(args.filename, getRsaKey(),
                args.output, outputExtension=args.extension, override=args.force,
                archivePassword=getArchivePassword(),
                compressionLevel=args.archive_compression_level,
                archivePartSize=args.part_size*1024*1024,
                tmpFolderName=TMP_FOLDER_NAME, extensionsToSkip=args.skip)
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
                tmpFolderName=TMP_FOLDER_NAME)
            if args.verbose_pretty:
                if result:
                    print(f"{args.filename} -> {target} (encrypted)")
                else:
                    print(f"{args.filename} -> {target} (already exists - skipped)")
            elif args.verbose_all or result and args.verbose:
                print(target)
    except FileNotFoundError as e:
        print(str(e))
    except FileExistsError as e:
        print(str(e))
    except PermissionError as e:
        print(str(e))
        print("Possible cause: file is opened")
    except Exception as e:
        print("Unhandled exception:")
        print(str(e))
    theLockLib.deleteTmpFolder(TMP_FOLDER_NAME)
    

if __name__ == "__main__":
    main()
