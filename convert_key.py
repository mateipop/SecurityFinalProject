import sys
from cryptography.hazmat.primitives import serialization

if len(sys.argv) != 4:
    print(f"Usage: python {sys.argv[0]} <private|public> <pem_file> <output_file>")
    sys.exit(1)

key_type, pem_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]
KEY_BYTES = 128

with open(pem_file, "rb") as f:
    pem_data = f.read()

if key_type == "public":
    key = serialization.load_pem_public_key(pem_data)
    numbers = key.public_numbers()
    modulus = numbers.n
    exponent = numbers.e
else: # private
    key = serialization.load_pem_private_key(pem_data, password=None)
    numbers = key.private_numbers()
    modulus = numbers.public_numbers.n
    exponent = numbers.d

with open(out_file, "wb") as f:
    f.write(modulus.to_bytes(KEY_BYTES, 'big'))
    f.write(exponent.to_bytes(KEY_BYTES, 'big'))

print(f"Successfully converted {pem_file} to {out_file}")