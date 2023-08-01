import os
import sys
import rsa              # pip install rsa
import multiprocessing


if getattr(sys, 'frozen', False):
    multiprocessing.freeze_support()


def genKey(size: int, public_key_file: str, private_key_file: str) -> None:
    (pub, priv) = rsa.newkeys(size, poolsize=os.cpu_count())
    with open(private_key_file, 'wb') as file:
        file.write(rsa.PrivateKey.save_pkcs1(priv))
    with open(public_key_file, 'wb') as file:
        file.write(rsa.PublicKey.save_pkcs1(pub))


def input_int(msg: str, default: int = None) -> int:
    if default is not None:
        msg += f" (default: {default})"
    msg += ": "
    inp: str = input(msg).strip()
    while not inp.isdecimal() and (default is None or inp != ''):
        inp = input("Invalid input, try again: ")
    if inp == '':
        return default
    return int(inp)


def input_str(msg: str, default: str = None) -> str:
    if default is not None:
        msg += f" (default: {default})"
    msg += ": "
    inp: str = input(msg).strip()
    if inp == '':
        return default
    return inp


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="RSA key pair generator")
    parser.add_argument(
        "-s",
        "--size",
        type=int,
        required=False,
        action='store'
    )
    parser.add_argument(
        '-pub',
        "--publicKeyOutput",
        type=str, required=False,
        action='store',
        dest='pub'
    )
    parser.add_argument(
        '-priv',
        "--privateKeyOutput",
        type=str,
        required=False,
        action='store',
        dest='priv'
    )
    args = parser.parse_args()
    if args.size is None:
        args.size = input_int('Key Size', 2048)
    if args.pub is None:
        args.pub = input_str("Public key output", "key.pub")
    if args.priv is None:
        args.priv = input_str("Private key output", "key.priv")
    genKey(args.size, args.pub, args.priv)


if __name__ == "__main__":
    main()
