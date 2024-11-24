import argparse
import datetime
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed448, x448
from cryptography.x509.oid import NameOID

from common.custom_cryptography import Customx509
from admin.config import *

parser = argparse.ArgumentParser('crypt2chat admin-panel')

subparsers = parser.add_subparsers(title='actions', dest='action', help='actions')

ed448_parser = subparsers.add_parser('ed448', help="Create ed448 keys")
ed448_parser.add_argument('-n', '--name', default="ed448", help="Name override. (default: ed448)")
ed448_parser.add_argument('-p', '--password', default=None, help="Password of private key (default : None)")
ed448_parser.add_argument('-y', action="store_true", help="Bypass confirmation")

x448_parser = subparsers.add_parser('x448', help="Create x448 keys")
x448_parser.add_argument('-n', '--name', default="x448", help="Name override. (default: x448)")
x448_parser.add_argument('-p', '--password', default=None, help="Password of private key (default : None)")
x448_parser.add_argument('-y', action="store_true", help="Bypass confirmation")

rsa_parser = subparsers.add_parser('rsa', help="Create rsa keys")
rsa_parser.add_argument('-n', '--name', default="rsa", help="Name override. (default: rsa)")
rsa_parser.add_argument('-pe', '--public_exponent', default="65537", help="Value of public exponent (default : 65537)")
rsa_parser.add_argument('-ks', '--key_size', default="8192", help="Key size (in bits) (default : 8192)")
rsa_parser.add_argument('-p', '--password', default=None, help="Password of private key (default : None)")
rsa_parser.add_argument('-y', action="store_true", help="Bypass confirmation")

sign_parser = subparsers.add_parser('sign', help='Sign certificate')
sign_parser.add_argument('-in', '--issuer_name', default="root", help='Common name of issuer (default: root)')
sign_parser.add_argument('-sn', '--subject_name', default=False, help='Common name of subject')
sign_parser.add_argument('-ipk', '--issuer_private_key', help='Issuer PEM private key path')
sign_parser.add_argument('-spk', '--subject_public_key', help='Subject PEM public key path')
sign_parser.add_argument('-p', '--password', default=None, help="Password of issuer private key (default : None)")
sign_parser.add_argument('-nvb', '--not_valid_before', default="0", help="Not valid before (relative to now in days) (default : 0)")
sign_parser.add_argument('-nva', '--not_valid_after', default="365", help="Not valid after (relative to now in days) (default : 365)")
sign_parser.add_argument('-y', action="store_true", help="Bypass confirmation")

verify_parser = subparsers.add_parser('verify', help="Verify certificate")
verify_parser.add_argument('-in', '--issuer_name', default="root", help='Common name of issuer (default: root)')
verify_parser.add_argument('-ipk', '--issuer_public_key', default=False, help='Issuer PEM public key path')
verify_parser.add_argument('-sn', '--subject_name', default=False, help='Common name of subject')
verify_parser.add_argument('-f', '--file', default=False, help="PEM Certificate path")

args = parser.parse_args()

match args.action:
    case "ed448" | "x448" | "rsa":
        if not args.y:
            res = False
            while res is False:
                _input = input("Warning, this will erase old keys with same name. Confirm [y/n] ")
                if _input == "y":
                    res = True
                elif _input == "n":
                    print("Abortion...")
                    sys.exit()
                else:
                    print("Incorrect entry...")

        match args.action:
            case "ed448":
                private_key = ed448.Ed448PrivateKey.generate()
            case "x448":
                private_key = x448.X448PrivateKey.generate()
            case "rsa":
                private_key = rsa.generate_private_key(
                    public_exponent=int(args.public_exponent),
                    key_size=int(args.key_size),
                    backend=default_backend()
                )
            case _:
                raise ValueError("Unsupported algorithm")
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() if args.password is None else serialization.BestAvailableEncryption(
                args.password.encode())
        )
        with open(privkey(args.name), "wb") as file:
            file.write(private_key_pem)
        with open(pubkey(args.name), "wb") as file:
            file.write(public_key_pem)

    case "sign":
        if args.subject_name:
            subject_cn = args.subject_name
        else:
            subject_cn = input("Common name of subject: ")

        try:
            with open(args.subject_public_key, "rb") as file:
                subject_puk = file.read()
        except:
            print(f"{args.subject_public_key} not found !")
            sys.exit()

        try:
            with open(args.issuer_private_key, "rb") as file:
                issuer_prk = file.read()
        except:
            print(f"{args.issuer_private_key} not found !")
            sys.exit()

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.issuer_name)])

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            serialization.load_pem_public_key(
                subject_puk,
                backend=default_backend()
            )
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=float(args.not_valid_before))
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=float(args.not_valid_after))
        )

        issuer_private_key = serialization.load_pem_private_key(
            issuer_prk,
            password=args.password.encode() if args.password else None,
            backend=default_backend()
        )

        subject_certificate = builder.sign(
            private_key=issuer_private_key, algorithm=hashes.SHA512(), backend=default_backend()
        ).public_bytes(
            encoding=serialization.Encoding.PEM
        )

        with open(cert(subject_cn), "wb") as file:
            file.write(subject_certificate)

    case "verify":
        try:
            with open(args.file, "rb") as file:
                certificate_pem = file.read()
        except:
            print(f"{args.file} not found !")
            sys.exit()

        authorized_issuers = {}
        try:
            with open(args.issuer_public_key, "rb") as file:
                authorized_issuers[args.issuer_name] = file.read()
        except:
            print("Failed to load issuer public key !")

        auth = Customx509.verify_certificate(certificate_pem=certificate_pem, authorized_issuers=authorized_issuers)
        print(auth)
    case _:
        raise NotImplementedError

print("Successful !!!")