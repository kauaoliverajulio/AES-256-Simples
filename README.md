# AES-256 Simples

Pequeno utilitário em Python que demonstra como gerar uma chave de 256 bits e
criptografar/descriptografar mensagens usando AES em modo GCM (autenticado).

Além da cifra baseada em AES, o utilitário também inclui comandos para aplicar
uma cifra de César simples em textos curtos, útil para fins educacionais.

## Requisitos

- Python 3.9+
- [PyCryptodome](https://pycryptodome.readthedocs.io) (`pip install -r requirements.txt`)

## Uso rápido

```bash
# gerar uma nova chave binária (permissões restritas 0o600)
python simple_aes.py generate-key chave.bin

# criptografar uma mensagem (saída em Base64 URL-safe)
python simple_aes.py encrypt chave.bin "mensagem secreta" > mensagem.enc

# descriptografar
python simple_aes.py decrypt chave.bin "$(cat mensagem.enc)"

# cifra de César
python simple_aes.py caesar-encrypt "Ataque ao amanhecer" --shift 5
python simple_aes.py caesar-decrypt "Fyfvpj ft frfs mjhwj" --shift 5
```

Também é possível usar as funções diretamente em Python:

```python
from simple_aes import (
    generate_key,
    encrypt,
    decrypt,
    caesar_encrypt,
    caesar_decrypt,
)

key = generate_key()
message = encrypt(b"olá mundo", key)
print(message.to_base64())
print(decrypt(message, key).decode())

print(caesar_encrypt("ola", 3))
print(caesar_decrypt("rod", 3))
```
