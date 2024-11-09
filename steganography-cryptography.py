from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import numpy as np

def menu():
    print("\nMenu de Opções:")
    print("(1) Embutir texto em uma imagem usando Steganography")
    print("(2) Recuperar texto de uma imagem alterada por Steganography")
    print("(3) Gerar hash das imagens para verificar alterações")
    print("(4) Encriptar mensagem com chave pública e privada e embutir na imagem")
    print("(5) Decriptar mensagem de uma imagem alterada por Steganography")
    print("(S ou s) Sair")

def embed_text_in_image(image_path, message, output_path):
    image = Image.open(image_path)
    binary_message = ''.join([format(ord(i), "08b") for i in message]) + '1111111111111110'
    pixels = np.array(image)
    binary_index = 0

    for row in range(pixels.shape[0]):
        for col in range(pixels.shape[1]):
            for color in range(3):
                if binary_index < len(binary_message):
                    pixel_bin = list(format(pixels[row, col, color], "08b"))
                    pixel_bin[-1] = binary_message[binary_index]
                    pixels[row, col, color] = int("".join(pixel_bin), 2)
                    binary_index += 1

    encoded_image = Image.fromarray(pixels)
    encoded_image.save(output_path)

def retrieve_text_from_image(image_path):
    image = Image.open(image_path)
    pixels = np.array(image)
    binary_message = ""
    for row in range(pixels.shape[0]):
        for col in range(pixels.shape[1]):
            for color in range(3):
                binary_message += format(pixels[row, col, color], "08b")[-1]

    message = ""
    for i in range(0, len(binary_message), 8):
        char = chr(int(binary_message[i:i+8], 2))
        if char == "þ":
            break
        message += char

    return message

def generate_image_hash(image_path):
    with open(image_path, "rb") as img_file:
        img_data = img_file.read()
    return hashlib.sha256(img_data).hexdigest()

def encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_message)

def decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

while True:
    menu()
    choice = input("Digite a opção desejada: ").strip().lower()

    if choice == "1":
        image_path = input("Caminho da imagem original: ")
        message = input("Texto a ser embutido: ")
        output_path = input("Caminho para salvar a imagem modificada: ")
        embed_text_in_image(image_path, message, output_path)
        print("Texto embutido com sucesso na imagem.")

    elif choice == "2":
        image_path = input("Caminho da imagem alterada: ")
        message = retrieve_text_from_image(image_path)
        print("Texto recuperado da imagem:", message)

    elif choice == "3":
        image_path_original = input("Caminho da imagem original: ")
        image_path_modified = input("Caminho da imagem modificada: ")
        original_hash = generate_image_hash(image_path_original)
        modified_hash = generate_image_hash(image_path_modified)
        print("Hash da imagem original:", original_hash)
        print("Hash da imagem modificada:", modified_hash)
        if original_hash != modified_hash:
            print("As imagens são diferentes.")
        else:
            print("As imagens são idênticas.")

    elif choice == "4":
        message = input("Texto a ser encriptado: ")
        encrypted_message = encrypt_message(message, public_key)
        image_path = input("Caminho da imagem original: ")
        output_path = input("Caminho para salvar a imagem modificada: ")
        embed_text_in_image(image_path, encrypted_message.decode(), output_path)
        print("Mensagem encriptada e embutida com sucesso na imagem.")

    elif choice == "5":
        image_path = input("Caminho da imagem alterada: ")
        encrypted_message = retrieve_text_from_image(image_path)
        decrypted_message = decrypt_message(encrypted_message.encode(), private_key)
        print("Mensagem decriptada da imagem:", decrypted_message)

    elif choice == "s":
        print("Saindo do programa.")
        break

    else:
        print("Opção inválida. Tente novamente.")
