import os
import sys
import rsa
import argparse
import theLockLib
import pyperclip
from datetime import datetime


# Script Location
SL = os.path.dirname(__file__)
if getattr(sys, 'frozen', False):
    SL = os.path.dirname(sys.executable)


ARCHIVE_PART_SIZE = 256

TMP_FOLDER_NAME = os.path.normpath(f"{SL}/tmp")
FINAL_EXTENSION = ".encrypted"
COMPRESSION_LEVEL = 9


class Atributes:
    filename: str
    recursive: bool
    force: bool
    output: str | None
    archive_compression_level: int
    part_size: int
    password: str | None
    password_file: str | None
    extension: str
    skip: list[str]
    verbose: bool
    verbose_pretty: bool
    verbose_all: bool
    rsa_key_file: str | None
    rsa_from_clipboard: bool
    temporary_folder: str
    decrypt: bool
    generate_keys: int | None


def parseArgs() -> Atributes:
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str, help="File or folder to encrypt")
    parser.add_argument('-c', '--archive-compression-level', type=int, action='store',
        default=COMPRESSION_LEVEL,
        help=f"Level of compression 0-9 (default: {COMPRESSION_LEVEL})")
    parser.add_argument('-d', '--decrypt', action='store_true',
        help='Decryption mode')
    parser.add_argument('-e', '--extension', type=str, action='store',
        default=FINAL_EXTENSION,
        help=f"File suffix added to encrypted files (default: {FINAL_EXTENSION})")
    parser.add_argument('-f', '--force', action='store_true',
        help="Override existing files")
    parser.add_argument('-g', '--generate-keys', type=int, action='store',
        help='Generete public/private key pare of given size\
            and they are saved to filename.pub/filename.priv')
    parser.add_argument('-k', '--skip', action='store', type=list[str], nargs='*',
        default=[FINAL_EXTENSION], help="Skip files with given suffixes")
    parser.add_argument('-o', '--output', type=str, action='store',
        help="Target file or folder in case of recursion and decryption")
    parser.add_argument('-p', '--password', type=str, action='store',
        help="Password used for encryption/decryption")
    parser.add_argument('-pf', '--password-file', type=str, action='store',
        help="File with password used for encryption/decryption")
    parser.add_argument('-r', '--recursive', action='store_true',
        help="Instead encypting whole folder encrypt every file in it" +
        "(in case of decryptio decrypt every encrypted file in designated folder)")
    parser.add_argument('-rc', '--rsa-from-clipboard', action='store_true',
        help='Take RSA key from clipboard')
    parser.add_argument('-rsa', '--rsa-key-file', type=str, action='store',
        help='File with RSA key used for encryption/decryption')
    parser.add_argument('-s', '--part-size', type=int, action='store',
        default=ARCHIVE_PART_SIZE,
        help=f"Max size of one file part in MB (default: {ARCHIVE_PART_SIZE}MB)")
    parser.add_argument('-t', '--temporary-folder', type=str, action='store',
        default=TMP_FOLDER_NAME, help='Temporary folder location - ' + 
        f'it should not exists (default: {TMP_FOLDER_NAME})')
    parser.add_argument('-v', '--verbose', action='store_true',
        help="Verbose mode that prints affected files")
    parser.add_argument('-va', '--verbose-all', action='store_true',
        help="Verbose mode that prints affected files and those which are" +
        "not affected because they already exist")
    parser.add_argument('-vp', '--verbose-pretty', action='store_true',
        help="Verbose mode that prints more, readable information")
    ans = Atributes()
    parser.parse_args(namespace=ans)
    return ans


def encryptionPrettyVerbose(result: theLockLib.EncryptionResult) -> None:
    if result.code == theLockLib.ResultCode.DONE:
        print(f"File {result.filename} has been created and it contains")
        for i in result.sourceFiles:
            print(i)
    elif result.code == theLockLib.ResultCode.EXISTS:
        print(f"File {result.filename} already exists")
    elif result.code == theLockLib.ResultCode.EXTENSION_SKIP:
        print(f"File {result.filename} has been skipped due to it's extenstion")
    print()


def encryption(args: Atributes) -> None:
    rsaKey = None
    if args.rsa_from_clipboard:
        rsaKey = rsa.PublicKey.load_pkcs1(pyperclip.paste())
    elif args.rsa_key_file is not None:
        rsaKey = theLockLib.getRsaPublicKeyFromFile(args.rsa_key_file)
    if args.recursive:
        results = theLockLib.encryptRecursively(args.filename, rsaKey,
            args.output, outputExtension=args.extension, override=args.force,
            archivePassword=args.password,
            compressionLevel=args.archive_compression_level,
            archivePartSize=args.part_size*1024*1024,
            tmpFolderName=args.temporary_folder, extensionsToSkip=args.skip)
        if args.verbose_pretty:
            for i in results:
                encryptionPrettyVerbose(i)
        elif args.verbose or args.verbose_all:
            for result in results:
                if args.verbose_all or result.code == theLockLib.ResultCode.DONE:
                    print(result.filename)
    else:
        if args.output is None:
            args.output = args.filename
        target = f"{args.output}{args.extension}"
        result = theLockLib.encrypt([args.filename], rsaKey, target,
            override=args.force, archivePassword=args.password,
            compressionLevel=args.archive_compression_level,
            archivePartSize=args.part_size*1024*1024,
            tmpFolderName=args.temporary_folder)
        if args.verbose_pretty:
            encryptionPrettyVerbose(result)
        elif args.verbose_all or \
            result.code == theLockLib.ResultCode.DONE and args.verbose:
            print(result.filename)


def fileDecryptionPrettyVerbose(files: list[theLockLib.DecryptedFile]) -> None:
    for file in files:
        print(file.filename, end=' ')
        if file.code == theLockLib.ResultCode.DONE:
            print()
        elif file.code == theLockLib.ResultCode.EXISTS:
            print("- skipped (already decrypted)")


def decryptionPrettyVerbose(results: theLockLib.DecryptionResult) -> None:
    print(f"File {results.sourceFile}")
    if results.code == theLockLib.ResultCode.DONE:
        print("has been decrypted.",
              "It has been encrypted on:",
            datetime.fromtimestamp(results.encryptionTime)
            .strftime("%d-%m-%Y %H:%M:%S"))
        print('It contained:')
        fileDecryptionPrettyVerbose(results.fileList)
    elif results.code == theLockLib.ResultCode.EXISTS:
        print("has been skipped (already decrypted)")
        print('It contained:')
        fileDecryptionPrettyVerbose(results.fileList)
    elif results.code == theLockLib.ResultCode.EXTENSION_SKIP:
        print("has been skipped because it doesn't have desired extension")
    elif results.code == theLockLib.ResultCode.NO_DECRYPTION_KEY:
        print("has been skipped because RSA key hasn't been provided and also",
              f"{results.sourceFile}.priv does not exist")
    print()


def decryption(args: Atributes) -> None:
    rsaKey = None
    if args.rsa_from_clipboard:
        rsaKey = rsa.PrivateKey.load_pkcs1(pyperclip.paste())
    elif args.rsa_key_file is not None:
        rsaKey = theLockLib.getRsaPrivateKeyFromFile(args.rsa_key_file)
    if args.recursive:
        results = theLockLib.decryptRecursively(args.filename, rsaKey,
            args.output, tmpFolderName=args.temporary_folder, override=args.force,
            archivePassword=args.password,encryptedFilesExtension=args.extension)
        for i in results:
            decryptionPrettyVerbose(i)
    else:
        result = theLockLib.decrypt(args.filename, rsaKey, args.output,
            tmpFolderName=args.temporary_folder, override=args.force,
            archivePassword=args.password)
        if args.verbose_pretty:
            decryptionPrettyVerbose(result)
        if args.verbose or args.verbose_all:
            for i in result.fileList:
                if args.verbose_all or i.code == 0:
                    print(i.filename)


def genKeys(args: Atributes) -> None:
    theLockLib.genRSAKeyToFiles(args.generate_keys,
        public_key_file=f'{args.filename}.pub',
        private_key_file=f'{args.filename}.priv', override=args.force)
    if args.verbose_pretty:
        print(f'Key pare of size {args.generate_keys} have been generated')
        print(f'Public key has been saved to {args.filename}.pub')
        print(f'Private key has been saved to {args.filename}.priv')
    elif args.verbose_all or args.verbose:
        print(f'{args.filename}.pub')
        print(f'{args.filename}.priv')


def main() -> None:
    args = parseArgs()
    args.filename = os.path.normpath(args.filename.strip('"'))
    if args.password is None and args.password_file is not None:
        if not os.path.exists(args.password_file):
            print(f"{args.password_file} does't exist")
            return
        if not os.path.isfile(args.password_file):
            print(f'{args.password_file} is a directory, not a file')
            return
        with open(args.password_file, 'r') as file:
            args.password = file.read().strip()
    try:
        if args.generate_keys is not None:
            genKeys(args)
        elif args.decrypt:
            decryption(args)
        else:
            encryption(args)
    except FileNotFoundError as e:
        print(str(e))
    except FileExistsError as e:
        print(str(e))
    except PermissionError as e:
        print(str(e))
        print("Possible cause: file is opened")
    except theLockLib.NotAFileError as e:
        print(str(e))
    except theLockLib.NonASCIIStringError as e:
        print(str(e))
    except theLockLib.NoSymmetricKeyError as e:
        print(str(e))
    except Exception as e:
        print("Unhandled exception:")
        print(str(e))
    theLockLib.deletePath(args.temporary_folder)
    

if __name__ == "__main__":
    main()
