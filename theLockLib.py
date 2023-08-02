import os
import rsa                              # pip install rsa
from cryptography.fernet import Fernet  # pip install cryptography
import pyminizip                        # pip install pyminizip
import shutil
import zipfile


def getRsaPublicKeyFromFile(path: str, cache: bool = True) -> rsa.PublicKey:
    if cache:
        global rsa_public_key_cache
        global rsa_public_key_path_cache
        try:
            if rsa_public_key_cache is rsa.PublicKey \
            and path == rsa_public_key_path_cache:
                return rsa_public_key_cache
        except NameError:
            pass
    if not os.path.exists(path):
        raise FileNotFoundError("No RSA public key file")
    with open(path, 'rb') as file:
        rsa_public_key_cache = file.read()
    rsa_public_key_cache = rsa.PublicKey.load_pkcs1(rsa_public_key_cache)
    rsa_public_key_path_cache = path
    return rsa_public_key_cache


def deleteTmpFolder(path: str) -> None:
    if os.path.exists(path):
        shutil.rmtree(path)
    

# def inputYN(msg: str, default: bool | None = None,
#     tryAgain: str | None = "Invalid input. Try again" ,
#     y: str = 'Y', n: str = 'N', defaultWord: str = "default") -> bool:
#     if default is not None:
#         dw = n
#         if default:
#             dw = y
#         msg = f"{msg} ({defaultWord}: {dw}) ({y}/{n}): "
#     else:
#         msg = f"{msg} ({y}/{n}): "
#     v = input(msg).strip().lower()
#     if tryAgain is not None:
#         msg = f"{tryAgain}: "
#     while len(v) > 1 or (len(v) == 0 and default is None) \
#         or (len(v) != 0 and v[0] != 'y' and v[0] != 'n'):
#         v = input(msg).strip().lower()
#     return (len(v) == 0 and default is not None) or v[0] == 'y'


def prepareTmpFolder(path: str, *, #askForDelete: bool = True,
                     forceDelete: bool = False) -> None:
    if os.path.exists(path):
        # print(f"Folder with name {path} already exists",
        #       "it maybe caused by program crash or you created it",
        #       "anyway please get rid of it or rename it", sep=', ')
        if forceDelete: # or askForDelete and \
            # inputYN("Do you want to delete it and continue", True):
            deleteTmpFolder(path)
        else:
            raise FileExistsError("Temporary folder is required but folder",
                                  "with this name already exists")
    os.mkdir(path)


def symeticEncrypt(path: str, keyName: str,
        dstFolder: str,
        archivePartSize: int) -> (list[str], str):
    key = Fernet.generate_key()
    keyFile = f"{dstFolder}/{keyName}"
    with open(keyFile, 'wb') as file:
        file.write(key)
    fernet = Fernet(key)
    with open(path, 'rb') as file:
        content = file.read(archivePartSize)
        filename = os.path.basename(path)
        ans = list()
        i = 0
        while len(content) != 0:
            ans.append(f"{dstFolder}/{filename}.{i}")
            with open(ans[-1], 'wb') as output:
                output.write(fernet.encrypt(content))
            content = file.read(archivePartSize)
            i += 1
    return ans, keyFile


def asyncKeyEncrypt(path: str, rsaKey: rsa.PublicKey,
                    output: str | None = None) -> None:
    with open(path, 'rb') as file:
        content = file.read()
    content = rsa.encrypt(content, rsaKey)
    if output is None:
        output = path
    with open(output, 'wb') as file:
        file.write(content)


class NonASCIIString(Exception):
    pass


def encryptFile(path: str, rsaPublicKey: rsa.PublicKey,
                output: str | None = None, *,
                tmpFolderName: str = 'tmp', override: bool = False,
                archivePassword: str | None = None, compressionLevel: int = 9,
                noCompression: bool = False,
                archivePartSize: int = 512*1024*1024) -> None:
    if archivePassword is not None and \
        (any(ord(c) > 127 for c in path) or any(ord(c) > 127 for c in output)):
        raise NonASCIIString(
            "Path or output contain non ascii character and the password is not None")
    if output is None:
        output = path
    if not override and os.path.exists(output):
        # if not inputYN(f"File with name {output} already exists. " +
        #                "Do you want to override it", True):
        raise FileExistsError(f"File with name: {output} already exists")
    prepareTmpFolder(tmpFolderName, forceDelete=override)
    files, key = symeticEncrypt(path, 'key', tmpFolderName, archivePartSize)
    files.append(key)
    asyncKeyEncrypt(key, rsaPublicKey)
    try:
        d = os.path.dirname(output)
        if d != '':
            os.makedirs(d)
    except FileExistsError:
        pass
    if archivePassword is None:
        compression = zipfile.ZIP_DEFLATED
        if noCompression:
            compression = zipfile.ZIP_STORED
        with zipfile.ZipFile(output, 'w',
            compression=compression, compresslevel=compressionLevel) as file:
            for p in files:
                file.write(p, os.path.basename(p))
    else:
        pyminizip.compress_multiple(
            files,
            [],
            output,
            archivePassword,
            compressionLevel
        )
    deleteTmpFolder(tmpFolderName)


def getFileTree(path: str) -> list[str]:
    if os.path.isfile(path):
        return [os.path.normpath(path)]
    ans = list()
    files = os.listdir(path)
    for file in files:
        ans.extend(getFileTree(os.path.normpath(f"{path}/{file}")))
    return ans


def encrypt(path: str, rsaPublicKey: rsa.PublicKey,
                output: str | None = None, *,
                tmpFolderName: str = 'tmp',
                wrapperName: str = 'wrapper',
                override: bool = False, archivePassword: str | None = None,
                compressionLevel: int = 9, noCompression: bool = False,
                archivePartSize: int = 512*1024*1024) -> bool:
    if not override and os.path.exists(output):
        return False
    path = os.path.normpath(path)
    fileTree = getFileTree(path)
    prepareTmpFolder(tmpFolderName, forceDelete=override)
    wrapperFile = f"{tmpFolderName}/{wrapperName}"
    with zipfile.ZipFile(wrapperFile, 'w',
        compression=zipfile.ZIP_DEFLATED, compresslevel=compressionLevel) as file:
        for p in fileTree:
            file.write(p, p.removeprefix(path))
    if output is None:
        output = path
    encryptFile(wrapperFile, rsaPublicKey, output, tmpFolderName=f"{tmpFolderName}/0",
                archivePassword=archivePassword,
                compressionLevel=compressionLevel,
                noCompression=noCompression, override=override,
                archivePartSize=archivePartSize)
    deleteTmpFolder(tmpFolderName)
    return True


def encryptRecursively(path: str, rsaPublicKey: rsa.PublicKey,
                        output: str | None = None, *, tmpFolderName: str = 'tmp',
                        outputExtension: str = 'encrypted',
                        override: bool = False, archivePassword: str | None = None,
                        compressionLevel: int = 9, noCompression: bool = False,
                        archivePartSize: int = 512*1024*1024,
                        extensionsToSkip: list[str] | None = None
                        ) -> list[(str, str, int)]:
    fileTree = getFileTree(path)
    if output is None:
        output = path
    ans = list()
    for file in fileTree:
        fileRelative = file.removeprefix(os.path.normpath(path))
        target = os.path.normpath(f"{output}/{fileRelative}{outputExtension}")
        if extensionsToSkip is not None and \
            any(e == file[-len(e):] for e in extensionsToSkip):
            ans.append((file, target, 2))
            continue
        ans.append((file, target,
                not encrypt(file, rsaPublicKey, target, archivePassword=archivePassword,
                override=override, compressionLevel=compressionLevel,
                noCompression=noCompression, archivePartSize=archivePartSize,
                tmpFolderName=tmpFolderName)))
    return ans
