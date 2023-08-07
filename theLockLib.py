import os
import rsa                              # pip install rsa
from cryptography.fernet import Fernet  # pip install cryptography
import pyminizip                        # pip install pyminizip
import shutil
import zipfile
import sys
import multiprocessing
from typing import Tuple
from enum import Enum


# Results
class SymmertricEncryptResult:
    key: bytes
    createdFilesList: list[str]
    manifestFile: str | None
    keyFile: str | None

    def __init__(self, key: bytes, createdFilesList: list[str], *,
                 manifestFile: str | None = None, keyFile: str | None = None):
        self.key = key
        self.createdFilesList = createdFilesList
        self.keyFile = keyFile
        self.manifestFile = manifestFile


class SymmetricDecryptResult:
    outputFile: str
    encryptionTime: int

    def __init__(self, outputFile: str, encryptionTime: int) -> None:
        self.encryptionTime = encryptionTime
        self.outputFile = outputFile


class ResultCode(Enum):
    DONE = 0
    EXISTS = 1
    EXTENSION_SKIP = 2
    NO_DECRYPTION_KEY = 3


class EncryptedFile:
    filename: str
    code: ResultCode

    def __init__(self, filename: str, code: ResultCode = ResultCode.DONE) -> None:
        self.filename = filename
        self.code = code


class EncryptionResult:
    sourceFiles: list[str]
    filename: str
    code: ResultCode

    def __init__(self, sourceFiles: list[str], filename: str,
                 code: ResultCode = ResultCode.DONE) -> None:
        self.code = code
        self.sourceFiles = sourceFiles
        self.filename = filename


class DecryptedFile:
    filename: str
    code: ResultCode

    def __init__(self, filename: str, code: ResultCode = ResultCode.DONE) -> None:
        self.filename = filename
        self.code = code


class DecryptionResult:
    sourceFile: str
    fileList: list[DecryptedFile]
    encryptionTime: int | None
    code: ResultCode

    def __init__(self, sourceFile: str, encryptionTime: int | None = None, *,
                 code: ResultCode = ResultCode.DONE) -> None:
        self.encryptionTime = encryptionTime
        self.fileList = list()
        self.sourceFile = sourceFile
        self.code = code

    def addFile(self, file: DecryptedFile) -> None:
        self.fileList.append(file)
    


# Exceptions
class NonASCIIStringError(Exception):
    pass

class NotAFileError(Exception):
    pass

class NoSymmetricKeyError(Exception):
    pass



# Actual source

if getattr(sys, 'frozen', False):
    multiprocessing.freeze_support()


def genRSAKeyToFiles(size: int = 2048, *, public_key_file: str | None = None,
                private_key_file: str | None = None, override: bool = False
                ) -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
    pub, priv = rsa.newkeys(size, poolsize=os.cpu_count())
    if private_key_file is not None:
        if os.path.exists(private_key_file) and not override:
            raise FileExistsError(f"File {private_key_file} already exists")
        with open(private_key_file, 'wb') as file:
            file.write(rsa.PrivateKey.save_pkcs1(priv))
    if public_key_file is not None:
        if os.path.exists(public_key_file) and not override:
            raise FileExistsError(f"File {public_key_file} already exists")
        with open(public_key_file, 'wb') as file:
            file.write(rsa.PublicKey.save_pkcs1(pub))
    return pub, priv


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
            raise FileExistsError(f"Temporary folder ({path}) is required but folder " +
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
        override: bool = False) -> SymmertricEncryptResult:
    ans = list()
    if createManifestFile and manifestFileName is None:
        manifestFileName = \
        os.path.normpath(f'{dstFolder}/{os.path.basename(path)}.manifest')
    elif type(manifestFileName) is str:
        manifestFileName = os.path.normpath(f'{dstFolder}/{manifestFileName}')
    if manifestFileName is not None:
        createManifestFile = True
        isPathAvailable(manifestFileName, override)
    if createKeyFile and keyPath is None:
        keyPath = f'{dstFolder}/{os.path.basename(path)}.key'
    key = keySrc
    if key is None:
        key = Fernet.generate_key()
    if keyPath is not None:
        isPathAvailable(keyPath, override)
        keyPath = os.path.normpath(keyPath)
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
            file.write(f'{os.path.basename(keyPath)}\n')
            for x in ans:
                file.write(f'{os.path.basename(x)}\n')
    return SymmertricEncryptResult(key, ans,
                manifestFile=manifestFileName,keyFile=keyPath)


def symeticDecrypt(path: str | list[str], dstPath: str, *,
        keySrc: bytes | str | None = None,
        pathToFiles: str | None = None) -> SymmetricDecryptResult:
    if type(path) is list[str] and keySrc is None:
        raise NoSymmetricKeyError('No key provided')
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
    time = sys.maxsize
    with open(dstPath, 'wb') as outputFile:
        for part in path:
            with open(part, 'rb') as partFile:
                content = partFile.read()
                time = min(fernet.extract_timestamp(content), time)
                outputFile.write(fernet.decrypt(content))
    return SymmetricDecryptResult(dstPath, time)


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


def encryptFile(path: str, rsaPublicKey: rsa.PublicKey | None = None,
                output: str | None = None, *,
                tmpFolderName: str = 'tmp', override: bool = False,
                archivePassword: str | None = None, compressionLevel: int = 9,
                noCompression: bool = False,
                archivePartSize: int = 512*1024*1024) -> EncryptedFile:
    if archivePassword is not None and \
        (any(ord(c) > 127 for c in path) or any(ord(c) > 127 for c in output)):
        raise NonASCIIStringError(
            "Path or output contain non ascii character and the password is not None")
    if output is None:
        output = path
    if not override and os.path.exists(output):
        # raise FileExistsError(f"File with name: {output} already exists")
        return EncryptedFile(output, ResultCode.EXISTS)
    prepareTmpFolder(tmpFolderName, forceDelete=override)
    os.mkdir(f'{tmpFolderName}/content')
    result = symeticEncrypt(path, keyPath=f'{tmpFolderName}/key',
                dstFolder=f'{tmpFolderName}/content', archivePartSize=archivePartSize,
                manifestFileName='manifest')
    try:
        d = os.path.dirname(output)
        if d != '':
            os.makedirs(d)
    except FileExistsError:
        pass
    if rsaPublicKey is None:
        if not override and os.path.exists(f'{output}.key'):
            raise FileExistsError(f'File: {output}.key, already exists')
        rsaPublicKey, _ = genRSAKeyToFiles(override=override,
                                           private_key_file=f'{output}.priv')
    asyncEncrypt(result.keyFile, rsaPublicKey)
    result.createdFilesList.append(result.keyFile)
    result.createdFilesList.append(result.manifestFile)
    locations = ['/content/' for _ in result.createdFilesList]
    locations[-1] = locations[-1].removeprefix('/content')
    locations[-2] = locations[-2].removeprefix('/content')
    if archivePassword is None:
        compression = zipfile.ZIP_DEFLATED
        if noCompression:
            compression = zipfile.ZIP_STORED
        with zipfile.ZipFile(output, 'w',
            compression=compression, compresslevel=compressionLevel) as file:
            for p, q in zip(result.createdFilesList, locations):
                file.write(p, f'{q}{os.path.basename(p)}')
    else:
        pyminizip.compress_multiple(
            result.createdFilesList,
            locations,
            output,
            archivePassword,
            compressionLevel
        )
    deletePath(tmpFolderName)
    return EncryptedFile(output, ResultCode.DONE)


def decryptFile(path: str, rsaPrivateKey: rsa.PrivateKey | None = None,
                output: str | None = None, *,
                tmpFolderName: str = 'tmp', override: bool = False,
                archivePassword: str | None = None) -> SymmetricDecryptResult:
    if output is None:
        output = os.path.dirname(path)
    if not override and os.path.exists(output):
        raise FileExistsError(f"File with name: {output} already exists")
    prepareTmpFolder(tmpFolderName)
    with zipfile.ZipFile(path) as file:
        if archivePassword is not None:
            file.setpassword(bytes(archivePassword, 'utf-8'))
        file.extractall(tmpFolderName)
    if rsaPrivateKey is None:
        rsaPrivateKey = getRsaPrivateKeyFromFile(f'{file}.priv')
    asyncDecrypt(f'{tmpFolderName}/key', rsaPrivateKey)
    ans = symeticDecrypt(f'{tmpFolderName}/manifest', output,
                   pathToFiles=f'{tmpFolderName}/content')
    deletePath(tmpFolderName)
    return ans


def getFileTree(path: str) -> list[str]:
    if not os.path.exists(path):
        raise FileNotFoundError(f'File {os.path.normpath(path)} not found')
    if os.path.isfile(path):
        return [os.path.normpath(path)]
    ans = list()
    files = os.listdir(path)
    for file in files:
        ans.extend(getFileTree(os.path.normpath(f"{path}/{file}")))
    return ans


def encrypt(paths: list[str], rsaPublicKey: rsa.PublicKey | None = None,
                output: str | None = None, *,
                tmpFolderName: str = 'tmp',
                wrapperName: str = 'wrapper',
                override: bool = False, archivePassword: str | None = None,
                compressionLevel: int = 9, noCompression: bool = False,
                archivePartSize: int = 512*1024*1024) -> EncryptionResult:
    if output is None:
        output = paths[0]
    if not override and os.path.exists(output):
        return EncryptionResult(paths, output, ResultCode.EXISTS)
    prepareTmpFolder(tmpFolderName, forceDelete=override)
    wrapperFile = f"{tmpFolderName}/{wrapperName}"
    with zipfile.ZipFile(wrapperFile, 'w',
        compression=zipfile.ZIP_DEFLATED, compresslevel=compressionLevel) as file:
        for path in paths:
            path = os.path.normpath(path)
            fileTree = getFileTree(path)
            for p in fileTree:
                file.write(p, p.removeprefix(os.path.dirname(path)))
    _ = encryptFile(wrapperFile, rsaPublicKey, output,
                tmpFolderName=f"{tmpFolderName}/0",
                archivePassword=archivePassword,
                compressionLevel=compressionLevel,
                noCompression=noCompression, override=override,
                archivePartSize=archivePartSize)
    deletePath(tmpFolderName)
    return EncryptionResult(paths, output, ResultCode.DONE)


def decrypt(path: str, rsaPrivateKey: rsa.PrivateKey | None = None,
                output: str | None = None, *,
                tmpFolderName: str = 'tmp',
                override: bool = False,
                archivePassword: str | None = None
                ) -> DecryptionResult:
    if output is None:
        output = os.path.dirname(os.path.abspath(path))
    if not os.path.isfile(path):
        raise NotAFileError(f'{path} is not a file')
    prepareTmpFolder(tmpFolderName)
    result = decryptFile(path, rsaPrivateKey, f'{tmpFolderName}/wrapper',
                tmpFolderName=f'{tmpFolderName}/0',
                override=override, archivePassword=archivePassword)
    ans = DecryptionResult(path, result.encryptionTime)
    with zipfile.ZipFile(f'{tmpFolderName}/wrapper') as file:
        if archivePassword is not None:
            file.setpassword(bytes(archivePassword, 'utf-8'))
        filelist = list()
        for f in file.namelist():
            if override or not os.path.exists(f'{output}/{f}'):
                filelist.append(f)
                ans.addFile(DecryptedFile(f, ResultCode.DONE))
            else:
                ans.addFile(DecryptedFile(f, ResultCode.EXISTS))
        file.extractall(output, filelist)
    deletePath(tmpFolderName)
    return ans


def encryptRecursively(path: str, rsaPublicKey: rsa.PublicKey | None = None,
                        output: str | None = None, *, tmpFolderName: str = 'tmp',
                        outputExtension: str = '.encrypted',
                        override: bool = False, archivePassword: str | None = None,
                        compressionLevel: int = 9, noCompression: bool = False,
                        archivePartSize: int = 512*1024*1024,
                        extensionsToSkip: list[str] | None = None
                        ) -> list[EncryptionResult]:
    fileTree = getFileTree(path)
    if output is None:
        output = path
    ans = list()
    for file in fileTree:
        fileRelative = file.removeprefix(os.path.normpath(path))
        target = os.path.normpath(f"{output}/{fileRelative}{outputExtension}")
        if extensionsToSkip is not None and \
            any(e == file[-len(e):] for e in extensionsToSkip):
            ans.append(EncryptionResult(file, target, ResultCode.EXTENSION_SKIP))
            continue
        ans.append(encrypt([file], rsaPublicKey, target,
                archivePassword=archivePassword,override=override,
                compressionLevel=compressionLevel, noCompression=noCompression,
                archivePartSize=archivePartSize, tmpFolderName=tmpFolderName))
    return ans


def decryptRecursively(path: str, rsaPrivateKey: rsa.PrivateKey | None = None,
                        output: str | None = None, *, tmpFolderName: str = 'tmp',
                        encryptedFilesExtension: str = '.encrypted',
                        override: bool = False, archivePassword: str | None = None
                        ) -> list[DecryptionResult]:
    fileTree = getFileTree(path)
    if output is None:
        output = path
    ans = list()
    for file in fileTree:
        fileRelative = file.removeprefix(os.path.normpath(path))
        target = os.path.normpath(f"{output}/{fileRelative}")
        if encryptedFilesExtension != file[-len(encryptedFilesExtension):]:
            ans.append(DecryptionResult(file, None, code=ResultCode.EXTENSION_SKIP))
            continue
        target = target[:-len(encryptedFilesExtension)]
        rsaKey = rsaPrivateKey
        try:
            decryptedFiles = decrypt(file, rsaKey, os.path.dirname(target),
                archivePassword=archivePassword, override=override,
                tmpFolderName=tmpFolderName)
            ans.append(decryptedFiles)
        except FileNotFoundError:
            ans.append(DecryptionResult(file, None, code=ResultCode.NO_DECRYPTION_KEY))
    return ans
