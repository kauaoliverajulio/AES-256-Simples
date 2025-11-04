from __future__ import annotations

import argparse
import base64
import os
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32


class AESCipherError(Exception):
    pass


@dataclass(frozen=True)
class EncryptedMessage:
    nonce: bytes
    tag: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        return self.nonce + self.tag + self.ciphertext

    def to_base64(self) -> str:
        return base64.urlsafe_b64encode(self.to_bytes()).decode("ascii")

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedMessage":
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise AESCipherError("Dados de entrada muito curtos para AES-GCM")
        nonce = data[:NONCE_SIZE]
        tag = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
        ciphertext = data[NONCE_SIZE + TAG_SIZE:]
        return cls(nonce=nonce, tag=tag, ciphertext=ciphertext)

    @classmethod
    def from_base64(cls, data: str) -> "EncryptedMessage":
        try:
            raw = base64.urlsafe_b64decode(data.encode("ascii"))
        except Exception as exc:
            raise AESCipherError("Base64 inválido") from exc
        return cls.from_bytes(raw)


def generate_key() -> bytes:
    return get_random_bytes(KEY_SIZE)


def encrypt(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> EncryptedMessage:
    if len(key) != KEY_SIZE:
        raise ValueError("A chave precisa ter 32 bytes (256 bits)")

    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if associated_data:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return EncryptedMessage(nonce=nonce, tag=tag, ciphertext=ciphertext)


def decrypt(message: EncryptedMessage | bytes | str, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("A chave precisa ter 32 bytes (256 bits)")

    if isinstance(message, str):
        message = EncryptedMessage.from_base64(message)
    elif isinstance(message, bytes):
        message = EncryptedMessage.from_bytes(message)
    elif not isinstance(message, EncryptedMessage):
        raise TypeError("Tipo de mensagem desconhecido")

    cipher = AES.new(key, AES.MODE_GCM, nonce=message.nonce)
    if associated_data:
        cipher.update(associated_data)
    try:
        plaintext = cipher.decrypt_and_verify(message.ciphertext, message.tag)
    except ValueError as exc:
        raise AESCipherError("Falha ao verificar autenticidade") from exc
    return plaintext


def _save_key(path: str, key: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY  # type: ignore[attr-defined]
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as key_file:
            key_file.write(key)
        os.chmod(path, 0o600)
        fd = -1
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def caesar_cipher(text: str, shift: int) -> str:
    shift = shift % 26
    result: list[str] = []
    for char in text:
        if "a" <= char <= "z":
            base = ord("a")
            result.append(chr(base + ((ord(char) - base + shift) % 26)))
        elif "A" <= char <= "Z":
            base = ord("A")
            result.append(chr(base + ((ord(char) - base + shift) % 26)))
        else:
            result.append(char)
    return "".join(result)


def caesar_encrypt(message: str, shift: int) -> str:
    return caesar_cipher(message, shift)


def caesar_decrypt(message: str, shift: int) -> str:
    return caesar_cipher(message, -shift)


def _load_key(path: str) -> bytes:
    key = open(path, "rb").read()
    if len(key) != KEY_SIZE:
        raise ValueError("A chave precisa ter 32 bytes (256 bits)")
    return key


def _cmd_generate_key(args: argparse.Namespace) -> None:
    key = generate_key()
    if args.output:
        _save_key(args.output, key)
    else:
        os.write(1, key)


def _cmd_encrypt(args: argparse.Namespace) -> None:
    key = _load_key(args.key)
    associated_data = args.associated_data.encode("utf-8") if args.associated_data else None
    message = encrypt(args.message.encode("utf-8"), key, associated_data)
    print(message.to_base64())


def _cmd_decrypt(args: argparse.Namespace) -> None:
    key = _load_key(args.key)
    associated_data = args.associated_data.encode("utf-8") if args.associated_data else None
    plaintext = decrypt(args.message, key, associated_data)
    print(plaintext.decode("utf-8"))


def _cmd_caesar_encrypt(args: argparse.Namespace) -> None:
    result = caesar_encrypt(args.message, args.shift)
    print(result)


def _cmd_caesar_decrypt(args: argparse.Namespace) -> None:
    result = caesar_decrypt(args.message, args.shift)
    print(result)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AES-256 simples em modo GCM")
    subparsers = parser.add_subparsers(required=True)

    gen_parser = subparsers.add_parser("generate-key", help="Gerar uma nova chave AES-256")
    gen_parser.add_argument("output", nargs="?", help="Arquivo para salvar a chave (padrão: stdout binário)")
    gen_parser.set_defaults(func=_cmd_generate_key)

    enc_parser = subparsers.add_parser("encrypt", help="Criptografar uma mensagem de texto")
    enc_parser.add_argument("key", help="Arquivo contendo a chave de 32 bytes")
    enc_parser.add_argument("message", help="Mensagem em texto puro")
    enc_parser.add_argument("--associated-data", help="Dados associados para autenticação opcional")
    enc_parser.set_defaults(func=_cmd_encrypt)

    dec_parser = subparsers.add_parser("decrypt", help="Descriptografar uma mensagem criptografada")
    dec_parser.add_argument("key", help="Arquivo contendo a chave de 32 bytes")
    dec_parser.add_argument("message", help="Mensagem codificada em Base64")
    dec_parser.add_argument("--associated-data", help="Dados associados usados na criptografia")
    dec_parser.set_defaults(func=_cmd_decrypt)

    caesar_enc_parser = subparsers.add_parser(
        "caesar-encrypt",
        help="Criptografar mensagem usando cifra de César",
    )
    caesar_enc_parser.add_argument("message", help="Mensagem em texto puro")
    caesar_enc_parser.add_argument(
        "--shift",
        type=int,
        default=3,
        help="Deslocamento da cifra (padrão: 3)",
    )
    caesar_enc_parser.set_defaults(func=_cmd_caesar_encrypt)

    caesar_dec_parser = subparsers.add_parser(
        "caesar-decrypt",
        help="Descriptografar mensagem usando cifra de César",
    )
    caesar_dec_parser.add_argument("message", help="Mensagem criptografada")
    caesar_dec_parser.add_argument(
        "--shift",
        type=int,
        default=3,
        help="Deslocamento usado na cifragem (padrão: 3)",
    )
    caesar_dec_parser.set_defaults(func=_cmd_caesar_decrypt)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
