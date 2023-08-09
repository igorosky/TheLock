import os
import sys
import multiprocessing
import shutil
import zipfile
from typing import Iterator, Tuple
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet                      # pip install cryptography
import pyminizip                                            # pip install pyminizip


HASHING_ALGORITHM = hashes.SHA512()


# Results
class SymmertricEncryptResult:
    key: bytes
    createdEncryptedFilesList: list[str]
    createdSignaturesList: list[str] | None
    manifestFile: str | None
    keyFile: str | None

    def __init__(self, key: bytes, createdFilesList: list[str], *,
                 manifestFile: str | None = None, keyFile: str | None = None,
                 createdSignaturesList: list[str] | None = None):
        self.key = key
        self.createdEncryptedFilesList = createdFilesList
        self.keyFile = keyFile
        self.manifestFile = manifestFile
        self.createdSignaturesList = createdSignaturesList


class ResultCode(Enum):
    DONE = 0
    EXISTS = 1
    EXTENSION_SKIP = 2
    NO_DECRYPTION_KEY = 3


class SignatureStatus(Enum):
    OK = 0
    INVALID = 1
    NOT_CHECKED = 2
    NOT_SIGNED = 3


class SymmetricDecryptResult:
    outputFile: str
    encryptionTime: int
    signatureStatus: SignatureStatus

    def __init__(self, outputFile: str, encryptionTime: int,
                 signatureStatus: SignatureStatus) -> None:
        self.encryptionTime = encryptionTime
        self.outputFile = outputFile
        self.signatureStatus = signatureStatus


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
    signatureStatus: SignatureStatus

    def __init__(self, sourceFile: str, encryptionTime: int | None = None,
                 signatureStatus: SignatureStatus = SignatureStatus.NOT_CHECKED, *,
                 code: ResultCode = ResultCode.DONE) -> None:
        self.encryptionTime = encryptionTime
        self.fileList = list()
        self.sourceFile = sourceFile
        self.code = code
        self.signatureStatus = signatureStatus

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
                private_key_file: str | None = None, override: bool = False,
                password: bytes | None = None
                ) -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=size)
    pub = priv.public_key()
    if private_key_file is not None:
        if os.path.exists(private_key_file) and not override:
            raise FileExistsError(f"File {private_key_file} already exists")
        encryptionAlgorithm = serialization.NoEncryption()
        if password is not None:
            encryptionAlgorithm = serialization.BestAvailableEncryption(password)
        with open(private_key_file, 'wb') as file:
            file.write(priv.private_bytes(encoding=serialization.Encoding.PEM,
                encryption_algorithm=encryptionAlgorithm,
                format=serialization.PrivateFormat.PKCS8))
    if public_key_file is not None:
        if os.path.exists(public_key_file) and not override:
            raise FileExistsError(f"File {public_key_file} already exists")
        with open(public_key_file, 'wb') as file:
            file.write(pub.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return pub, priv


def getRsaPublicKeyFromFile(path: str, cache: bool = True) -> rsa.RSAPublicKey:
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
        rsa_public_key_cache = serialization.load_pem_public_key(file.read())
    rsa_public_key_path_cache = path
    return rsa_public_key_cache


def getRsaPrivateKeyFromFile(path: str, cache: bool = False,
                             password: bytes | None = None) -> rsa.RSAPrivateKey:
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
        rsa_private_key_cache = serialization.load_pem_private_key(file.read(),
                                    password=password)
    rsa_private_key_path_cache = path
    return rsa_private_key_cache


def changeRsaPrivateKeyPassword(path: str, password: bytes | None,
                                newPassword: bytes | None) -> None:
    with open(path, 'rb') as file:
        rsa_key = serialization.load_pem_private_key(file.read(),
                                    password=password)
    encryptionAlgorithm = serialization.NoEncryption()
    if newPassword is not None:
        encryptionAlgorithm = serialization.BestAvailableEncryption(newPassword)
    with open(path, 'wb') as file:
        file.write(rsa_key.private_bytes(encoding=serialization.Encoding.PEM,
                encryption_algorithm=encryptionAlgorithm,
                format=serialization.PrivateFormat.PKCS8))
        

def genRSAPublicKeyFromRSAPrivateFiles(path: str, password: bytes | None, output: str
                                       ) -> None:
    with open(path, 'rb') as file:
        rsa_key = serialization.load_pem_private_key(file.read(),
                                    password=password)
    with open(output, 'wb') as file:
        file.write(rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, 
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))


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


def signFile(path: str, rsaKey: rsa.RSAPrivateKey,
             output: str | None = None) -> str:
    if output is None:
        output = f'{path}.signature'
    with open(path, 'rb') as file:
        content = file.read()
    hasher = hashes.Hash(HASHING_ALGORITHM)
    hasher.update(content)
    content = rsaKey.sign(hasher.finalize(), padding.PSS(
        mgf=padding.MGF1(HASHING_ALGORITHM),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    HASHING_ALGORITHM)
    with open(output, 'wb') as file:
        file.write(content)
    return os.path.normpath(output)


def signatureVerify(filePath: str, signaturePath: str, rsaKey: rsa.RSAPublicKey
                    ) -> bool:
    with open(filePath, 'rb') as file:
        content = file.read()
    with open(signaturePath, 'rb') as file:
        signature = file.read()
    hasher = hashes.Hash(HASHING_ALGORITHM)
    hasher.update(content)
    digest = hasher.finalize()
    try:
        rsaKey.verify(signature, digest, padding.PSS(
            mgf=padding.MGF1(HASHING_ALGORITHM),
            salt_length=padding.PSS.MAX_LENGTH
        ), HASHING_ALGORITHM)
    except InvalidSignature:
        return False
    return True


def symeticEncrypt(path: str, dstDir: str, *,
        keyPath: str | None = None, manifestFileName: str | None = None,
        archivePartSize: int = 512*1024*1024, createManifestFile: bool = False,
        createKeyFile: bool = False, keySrc: bytes | None = None,
        override: bool = False, signingKey: rsa.RSAPrivateKey | None = None,
        signatureDir: str | None = None) -> SymmertricEncryptResult:
    if signingKey is not None and signatureDir is None:
        signatureDir = dstDir
    if createManifestFile and manifestFileName is None:
        manifestFileName = \
        os.path.normpath(f'{dstDir}/{os.path.basename(path)}.manifest')
    elif type(manifestFileName) is str:
        manifestFileName = os.path.normpath(f'{dstDir}/{manifestFileName}')
    if manifestFileName is not None:
        createManifestFile = True
        isPathAvailable(manifestFileName, override)
    if createKeyFile and keyPath is None:
        keyPath = f'{dstDir}/{os.path.basename(path)}.key'
    key = keySrc
    if key is None:
        key = Fernet.generate_key()
    if keyPath is not None:
        isPathAvailable(keyPath, override)
        keyPath = os.path.normpath(keyPath)
        with open(keyPath, 'wb') as file:
            file.write(key)
    encryptedFiles = list()
    signatures = None
    if signingKey is not None:
        signatures = list()
    fernet = Fernet(key)
    with open(path, 'rb') as file:
        content = file.read(archivePartSize)
        filename = os.path.basename(path)
        i = 0
        while len(content) != 0:
            encryptedFiles.append(os.path.normpath(f"{dstDir}/{filename}.{i}"))
            isPathAvailable(encryptedFiles[-1], override)
            with open(encryptedFiles[-1], 'wb') as output:
                output.write(fernet.encrypt(content))
            if signingKey is not None:
                signatureDst = \
                f'{signatureDir}/{os.path.basename(encryptedFiles[-1])}.signature'
                hasher = hashes.Hash(HASHING_ALGORITHM)
                hasher.update(content)
                signature = signingKey.sign(hasher.finalize(), padding.PSS(
                    mgf=padding.MGF1(HASHING_ALGORITHM),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                HASHING_ALGORITHM)
                with open(signatureDst, 'wb') as signatureFile:
                    signatureFile.write(signature)
                signatures.append(signatureDst)
            content = file.read(archivePartSize)
            i += 1
    if createManifestFile:
        with open(manifestFileName, 'w') as file:
            if signingKey is None:
                file.write('0\n')
                file.write(f'{os.path.basename(keyPath)}\n')
                for x in encryptedFiles:
                    file.write(f'{os.path.basename(x)}\n')
            else:
                file.write('1\n')
                file.write(f'{os.path.basename(keyPath)}\n')
                for x, y in zip(encryptedFiles, signatures):
                    file.write(f'{os.path.basename(x)}\n')
                    file.write(f'{os.path.basename(y)}\n')
    return SymmertricEncryptResult(key, encryptedFiles,
                manifestFile=manifestFileName, keyFile=keyPath,
                createdSignaturesList=signatures)


def symeticDecrypt(path: str | list[str], dstPath: str, *,
        keySrc: bytes | str | None = None,
        pathToFiles: str | None = None, verificationKey: rsa.RSAPublicKey | None = None,
        pathToSignatures: str | None = None
        ) -> SymmetricDecryptResult:
    if type(path) is list[str] and keySrc is None:
        raise NoSymmetricKeyError('No key provided')
    if type(path) is str:
        srcDir = os.path.dirname(path)
        with open(path, 'r') as file:
            lines = [line.strip() for line in file.readlines()]
        signatureStatus = SignatureStatus.NOT_SIGNED
        areFilesSigned = lines[0] == '1'
        if areFilesSigned:
            if verificationKey is None:
                signatureStatus = SignatureStatus.NOT_CHECKED
            else:
                signatureStatus = SignatureStatus.OK
        if keySrc is None:
            keySrc = f'{srcDir}/{lines[1]}'
        path = list()
        signatures = list()
        signature = False
        for line in lines[2:]:
            if signature:
                if pathToSignatures is not None:
                    signatures.append(f'{pathToSignatures}/{line}')
                else:
                    signatures.append(f'{srcDir}/{line}')
                signature = False
                continue
            signature = True
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
    time = 0
    with open(dstPath, 'wb') as outputFile:
        for (i, part) in enumerate(path):
            with open(part, 'rb') as partFile:
                content = partFile.read()
                time = max(fernet.extract_timestamp(content), time)
                content = fernet.decrypt(content)
                if signatureStatus == SignatureStatus.OK:
                    with open(signatures[i], 'rb') as file:
                        signature = file.read()
                    hasher = hashes.Hash(HASHING_ALGORITHM)
                    hasher.update(content)
                    digest = hasher.finalize()
                    try:
                        verificationKey.verify(signature, digest, padding.PSS(
                            mgf=padding.MGF1(HASHING_ALGORITHM),
                            salt_length=padding.PSS.MAX_LENGTH
                        ), HASHING_ALGORITHM)
                    except InvalidSignature:
                        signatureStatus = SignatureStatus.INVALID
                outputFile.write(content)
    return SymmetricDecryptResult(dstPath, time, signatureStatus)


def asyncEncrypt(path: str, rsaKey: rsa.RSAPublicKey,
                    output: str | None = None) -> str:
    with open(path, 'rb') as file:
        content = file.read()
    content = rsaKey.encrypt(content, padding.OAEP(
                                mgf=padding.MGF1(HASHING_ALGORITHM),
                                algorithm=HASHING_ALGORITHM,
                                label=None))
    if output is None:
        output = path
    with open(output, 'wb') as file:
        file.write(content)
    return os.path.normpath(output)


def asyncDecrypt(path: str, rsaKey: rsa.RSAPrivateKey,
                    output: str | None = None) -> str:
    with open(path, 'rb') as file:
        content = file.read()
    content = rsaKey.decrypt(content, padding.OAEP(
                                mgf=padding.MGF1(HASHING_ALGORITHM),
                                algorithm=HASHING_ALGORITHM,
                                label=None))
    if output is None:
        output = path
    with open(output, 'wb') as file:
        file.write(content)
    return os.path.normpath(output)


def encryptFile(path: str, rsaPublicKey: rsa.RSAPublicKey | None = None,
                output: str | None = None, *, tmpFolderName: str = 'tmp',
                override: bool = False, archivePassword: bytes | None = None,
                compressionLevel: int = 9, noCompression: bool = False,
                archivePartSize: int = 512*1024*1024,
                rsaKeyPassword: bytes | None = None,
                signingKey: rsa.RSAPrivateKey | None = None) -> EncryptedFile:
    if archivePassword is not None and \
        (any(ord(c) > 127 for c in path) or any(ord(c) > 127 for c in output)):
        raise NonASCIIStringError(
            "Path or output contain non ascii character and the password is not None")
    if output is None:
        output = path
    if not override and os.path.exists(output):
        return EncryptedFile(output, ResultCode.EXISTS)
    prepareTmpFolder(tmpFolderName, forceDelete=override)
    os.mkdir(f'{tmpFolderName}/content')
    if signingKey is not None:
        os.mkdir(f'{tmpFolderName}/signatures')
    result = symeticEncrypt(path, keyPath=f'{tmpFolderName}/key',
                dstDir=f'{tmpFolderName}/content', archivePartSize=archivePartSize,
                manifestFileName='manifest', signingKey=signingKey,
                signatureDir=f'{tmpFolderName}/signatures')
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
                                           private_key_file=f'{output}.priv',
                                           password=rsaKeyPassword)
    asyncEncrypt(result.keyFile, rsaPublicKey)
    result.createdEncryptedFilesList.append(result.keyFile)
    result.createdEncryptedFilesList.append(result.manifestFile)
    locations = ['/content/' for _ in result.createdEncryptedFilesList]
    locations[-1] = locations[-1].removeprefix('/content')
    locations[-2] = locations[-2].removeprefix('/content')
    if result.createdSignaturesList is not None:
        locations.extend(['/signatures/' for _ in result.createdSignaturesList])
        result.createdEncryptedFilesList.extend(result.createdSignaturesList)
    if archivePassword is None:
        compression = zipfile.ZIP_DEFLATED
        if noCompression:
            compression = zipfile.ZIP_STORED
        with zipfile.ZipFile(output, 'w',
            compression=compression, compresslevel=compressionLevel) as file:
            for p, q in zip(result.createdEncryptedFilesList, locations):
                file.write(p, f'{q}{os.path.basename(p)}')
    else:
        pyminizip.compress_multiple(
            result.createdEncryptedFilesList,
            locations,
            output,
            archivePassword.decode('utf-8'),
            compressionLevel
        )
    deletePath(tmpFolderName)
    return EncryptedFile(output, ResultCode.DONE)


def decryptFile(path: str, rsaPrivateKey: rsa.RSAPrivateKey | None = None,
                output: str | None = None, *, tmpFolderName: str = 'tmp',
                override: bool = False, archivePassword: bytes | None = None,
                rsaKeyPassword: bytes | None = None,
                verificationKey: rsa.RSAPublicKey | None = None
                ) -> SymmetricDecryptResult:
    if output is None:
        output = os.path.dirname(path)
    if not override and os.path.exists(output):
        raise FileExistsError(f"File with name: {output} already exists")
    prepareTmpFolder(tmpFolderName)
    with zipfile.ZipFile(path) as file:
        if archivePassword is not None:
            file.setpassword(archivePassword)
        file.extractall(tmpFolderName)
    if rsaPrivateKey is None:
        rsaPrivateKey = getRsaPrivateKeyFromFile(f'{path}.priv',
                            password=rsaKeyPassword)
    asyncDecrypt(f'{tmpFolderName}/key', rsaPrivateKey)
    ans = symeticDecrypt(f'{tmpFolderName}/manifest', output,
                   pathToFiles=f'{tmpFolderName}/content',
                   verificationKey=verificationKey,
                   pathToSignatures=f'{tmpFolderName}/signatures')
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


def encrypt(paths: list[str], rsaPublicKey: rsa.RSAPublicKey | None = None,
                output: str | None = None, *, tmpFolderName: str = 'tmp',
                wrapperName: str = 'wrapper', override: bool = False,
                archivePassword: bytes | None = None, compressionLevel: int = 9,
                noCompression: bool = False, archivePartSize: int = 512*1024*1024,
                rsaKeyPassword: bytes | None = None,
                signingKey: rsa.RSAPrivateKey | None = None) -> EncryptionResult:
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
                archivePartSize=archivePartSize, rsaKeyPassword=rsaKeyPassword,
                signingKey=signingKey)
    deletePath(tmpFolderName)
    return EncryptionResult(paths, output, ResultCode.DONE)


def decrypt(path: str, rsaPrivateKey: rsa.RSAPrivateKey | None = None,
            output: str | None = None, *, tmpFolderName: str = 'tmp',
            override: bool = False, archivePassword: bytes | None = None,
            rsaKeyPassword: bytes | None = None,
            verificationKey: rsa.RSAPublicKey | None = None) -> DecryptionResult:
    if output is None:
        output = os.path.dirname(os.path.abspath(path))
    if not os.path.isfile(path):
        raise NotAFileError(f'{path} is not a file')
    prepareTmpFolder(tmpFolderName)
    result = decryptFile(path, rsaPrivateKey, f'{tmpFolderName}/wrapper',
                tmpFolderName=f'{tmpFolderName}/0',
                override=override, archivePassword=archivePassword,
                rsaKeyPassword=rsaKeyPassword, verificationKey=verificationKey)
    ans = DecryptionResult(path, result.encryptionTime, result.signatureStatus)
    with zipfile.ZipFile(f'{tmpFolderName}/wrapper') as file:
        if archivePassword is not None:
            file.setpassword(archivePassword)
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


def encryptRecursively(path: str, rsaPublicKey: rsa.RSAPublicKey | None = None,
                        output: str | None = None, *, tmpFolderName: str = 'tmp',
                        outputExtension: str = '.encrypted', override: bool = False,
                        archivePassword: bytes | None = None, compressionLevel: int = 9,
                        noCompression: bool = False,
                        archivePartSize: int = 512*1024*1024,
                        extensionsToSkip: list[str] | None = None,
                        rsaKeyPassword: bytes | None = None,
                        signingKey: rsa.RSAPrivateKey | None = None
                        ) -> Iterator[EncryptionResult]:
    fileTree = getFileTree(path)
    if output is None:
        output = path
    for file in fileTree:
        fileRelative = file.removeprefix(os.path.normpath(path))
        target = os.path.normpath(f"{output}/{fileRelative}{outputExtension}")
        if extensionsToSkip is not None and \
            any(e == file[-len(e):] for e in extensionsToSkip):
            yield EncryptionResult(file, target, ResultCode.EXTENSION_SKIP)
            continue
        yield encrypt([file], rsaPublicKey, target,archivePassword=archivePassword,
                override=override, compressionLevel=compressionLevel,
                noCompression=noCompression, archivePartSize=archivePartSize,
                tmpFolderName=tmpFolderName, rsaKeyPassword=rsaKeyPassword,
                signingKey=signingKey)


def decryptRecursively(path: str, rsaPrivateKey: rsa.RSAPrivateKey | None = None,
                        output: str | None = None, *, tmpFolderName: str = 'tmp',
                        encryptedFilesExtension: str = '.encrypted',
                        override: bool = False, archivePassword: bytes | None = None,
                        rsaKeyPassword: bytes | None = None,
                        verificationKey: rsa.RSAPublicKey | None = None
                        ) -> Iterator[DecryptionResult]:
    fileTree = getFileTree(path)
    if output is None:
        output = path
    for file in fileTree:
        fileRelative = file.removeprefix(os.path.normpath(path))
        target = os.path.normpath(f"{output}/{fileRelative}")
        if encryptedFilesExtension != file[-len(encryptedFilesExtension):]:
            yield DecryptionResult(file, None, code=ResultCode.EXTENSION_SKIP)
            continue
        target = target[:-len(encryptedFilesExtension)]
        rsaKey = rsaPrivateKey
        try:
            decryptedFiles = decrypt(file, rsaKey, os.path.dirname(target),
                archivePassword=archivePassword, override=override,
                tmpFolderName=tmpFolderName, rsaKeyPassword=rsaKeyPassword,
                verificationKey=verificationKey)
            yield decryptedFiles
        except FileNotFoundError:
            deletePath(tmpFolderName)
            yield DecryptionResult(file, None, code=ResultCode.NO_DECRYPTION_KEY)
