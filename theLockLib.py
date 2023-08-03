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


def getRsaPrivateKeyFromFile(path: str, cache: bool = True) -> rsa.PrivateKey:
    if cache:
        global rsa_private_key_cache
        global rsa_private_key_path_cache
        try:
            if rsa_private_key_cache is rsa.PublicKey \
            and path == rsa_private_key_path_cache:
                return rsa_private_key_cache
        except NameError:
            pass
    if not os.path.exists(path):
        raise FileNotFoundError("No RSA private key file")
    with open(path, 'rb') as file:
        rsa_private_key_cache = file.read()
    rsa_private_key_cache = rsa.PrivateKey.load_pkcs1(rsa_private_key_cache)
    rsa_private_key_path_cache = path
    return rsa_private_key_cache


def deletePath(path: str) -> None:
    if not os.path.exists(path):
        return
    if os.path.isfile(path):
        os.remove(path)
        return
    shutil.rmtree(path)


def prepareTmpFolder(path: str, *, forceDelete: bool = False) -> None:
    if os.path.exists(path):
        if forceDelete:
            deletePath(path)
        else:
            raise FileExistsError("Temporary folder is required but folder " +
                                  "with this name already exists")
    os.mkdir(path)


def isPathAvailable(path: str, deleteIfExists: bool = False) -> None:
    if not os.path.exists(path):
        return
    if not deleteIfExists:
        raise FileExistsError(f'File: {path} already exists')
    deletePath(path)


def symeticEncrypt(path: str, dstFolder: str, *,
        keyPath: str | None = None, manifestFileName: str | None = None,
        archivePartSize: int = 512*1024*1024, createManifestFile: bool = False,
        createKeyFile: bool = False, keySrc: bytes | None = None,
        override: bool = False) -> (bytes, list[str]):
    ans = list()
    if createManifestFile and manifestFileName is None:
        manifestFileName = \
        os.path.normpath(f'{dstFolder}/{os.path.basename(path)}.manifest')
    elif type(manifestFileName) is str:
        manifestFileName = os.path.normpath(f'{dstFolder}/{manifestFileName}')
    if manifestFileName is not None:
        createManifestFile = True
        isPathAvailable(manifestFileName, override)
        ans.append(manifestFileName)
    if createKeyFile and keyPath is None:
        keyPath = f'{dstFolder}/{os.path.basename(path)}.key'
    key = keySrc
    if key is None:
        key = Fernet.generate_key()
    if keyPath is not None:
        isPathAvailable(keyPath, override)
        ans.append(os.path.normpath(keyPath))
        with open(keyPath, 'wb') as file:
            file.write(key)
    fernet = Fernet(key)
    with open(path, 'rb') as file:
        content = file.read(archivePartSize)
        filename = os.path.basename(path)
        i = 0
        while len(content) != 0:
            ans.append(os.path.normpath(f"{dstFolder}/{filename}.{i}"))
            isPathAvailable(ans[-1], override)
            with open(ans[-1], 'wb') as output:
                output.write(fernet.encrypt(content))
            content = file.read(archivePartSize)
            i += 1
    if createManifestFile:
        with open(manifestFileName, 'w') as file:
            for x in ans[1:]:
                file.write(f'{os.path.basename(x)}\n')
    return key, ans


def symeticDecrypt(path: str | list[str], dstPath: str, *,
        keySrc: bytes | str | None = None,
        pathToFiles: str | None = None) -> (str, int):
    if type(path) is list[str] and keySrc is None:
        raise Exception('No key provided')
    if type(path) is str:
        srcDir = os.path.dirname(path)
        with open(path, 'r') as file:
            lines = [line.strip() for line in file.readlines()]
        if keySrc is None:
            keySrc = f'{srcDir}/{lines[0]}'
        path = list()
        for line in lines[1:]:
            if pathToFiles is not None:
                path.append(f'{pathToFiles}/{line}')
            else:
                path.append(f'{srcDir}/{line}')
    if type(keySrc) is str:
        with open(keySrc, 'rb') as file:
            key = file.read()
    elif type(keySrc) is bytes:
        key = keySrc
    fernet = Fernet(key)
    with open(dstPath, 'wb') as outputFile:
        for part in path:
            with open(part, 'rb') as partFile:
                content = partFile.read()
                print(fernet.extract_timestamp(content))
                outputFile.write(fernet.decrypt(content))
    return dstPath


def asyncEncrypt(path: str, rsaKey: rsa.PublicKey,
                    output: str | None = None) -> str:
    with open(path, 'rb') as file:
        content = file.read()
    content = rsa.encrypt(content, rsaKey)
    if output is None:
        output = path
    with open(output, 'wb') as file:
        file.write(content)
    return os.path.normpath(output)


def asyncDecrypt(path: str, rsaKey: rsa.PrivateKey,
                    output: str | None = None) -> str:
    with open(path, 'rb') as file:
        content = file.read()
    content = rsa.decrypt(content, rsaKey)
    if output is None:
        output = path
    with open(output, 'wb') as file:
        file.write(content)
    return os.path.normpath(output)


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
        raise FileExistsError(f"File with name: {output} already exists")
    prepareTmpFolder(tmpFolderName, forceDelete=override)
    os.mkdir(f'{tmpFolderName}/content')
    _, files = symeticEncrypt(path, keyPath=f'{tmpFolderName}/key',
                dstFolder=f'{tmpFolderName}/content', archivePartSize=archivePartSize,
                manifestFileName='manifest')
    asyncEncrypt(files[1], rsaPublicKey)
    try:
        d = os.path.dirname(output)
        if d != '':
            os.makedirs(d)
    except FileExistsError:
        pass
    locations = ['/content/' for _ in files]
    locations[0] = locations[0].removeprefix('/content')
    locations[1] = locations[1].removeprefix('/content')
    if archivePassword is None:
        compression = zipfile.ZIP_DEFLATED
        if noCompression:
            compression = zipfile.ZIP_STORED
        with zipfile.ZipFile(output, 'w',
            compression=compression, compresslevel=compressionLevel) as file:
            for p, q in zip(files, locations):
                file.write(p, q)
    else:
        pyminizip.compress_multiple(
            files,
            locations,
            output,
            archivePassword,
            compressionLevel
        )
    deletePath(tmpFolderName)


def decryptFile(path: str, rsaPrivateKey: rsa.PrivateKey,
                output: str | None = None, *,
                tmpFolderName: str = 'tmp', override: bool = False,
                archivePassword: str | None = None) -> None:
    if output is None:
        output = os.path.dirname(path)
    if not override and os.path.exists(output):
        raise FileExistsError(f"File with name: {output} already exists")
    prepareTmpFolder(tmpFolderName)
    with zipfile.ZipFile(path) as file:
        file.setpassword(bytes(archivePassword, 'utf-8'))
        file.extractall(tmpFolderName)
    asyncDecrypt(f'{tmpFolderName}/key', rsaPrivateKey)
    symeticDecrypt(f'{tmpFolderName}/manifest', output,
                   pathToFiles=f'{tmpFolderName}/content')
    deletePath(tmpFolderName)


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
    if output is None:
        output = path
    if not override and os.path.exists(output):
        return False
    path = os.path.normpath(path)
    fileTree = getFileTree(path)
    prepareTmpFolder(tmpFolderName, forceDelete=override)
    wrapperFile = f"{tmpFolderName}/{wrapperName}"
    with zipfile.ZipFile(wrapperFile, 'w',
        compression=zipfile.ZIP_DEFLATED, compresslevel=compressionLevel) as file:
        for p in fileTree:
            file.write(p, p.removeprefix(os.path.dirname(path)))
    encryptFile(wrapperFile, rsaPublicKey, output, tmpFolderName=f"{tmpFolderName}/0",
                archivePassword=archivePassword,
                compressionLevel=compressionLevel,
                noCompression=noCompression, override=override,
                archivePartSize=archivePartSize)
    deletePath(tmpFolderName)
    return True


def decrypt(path: str, rsaPrivateKey: rsa.PrivateKey,
                output: str | None = None, *,
                tmpFolderName: str = 'tmp',
                override: bool = False, archivePassword: str | None = None) -> bool:
    if output is None:
        output = os.path.dirname(os.path.abspath(path))
    if not os.path.isfile(path):
        raise Exception('Not a file')
    prepareTmpFolder(tmpFolderName)
    decryptFile(path, rsaPrivateKey, f'{tmpFolderName}/wrapper',
                tmpFolderName=f'{tmpFolderName}/0',
                override=override, archivePassword=archivePassword)
    with zipfile.ZipFile(f'{tmpFolderName}/wrapper') as file:
        file.setpassword(bytes(archivePassword, 'utf-8'))
        file.extractall(output)
    deletePath(tmpFolderName)
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
