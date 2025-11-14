from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

class FNV1:
    @staticmethod
    def hash(text: str) -> int:
        h = 0x811c9dc5
        fnv_prime = 0x01000193
        for char in text:
            h = h * fnv_prime
            h = h ^ ord(char)
            h = h & 0xffffffff
        return h

class RLE:
    @staticmethod
    def compress(text: str) -> str:
        if not text:
            return ""

        result = []
        count = 1

        for i in range(1, len(text)):
            if text[i] == text[i - 1]:
                count += 1
            else:
                result.append(text[i - 1] + str(count))
                count = 1

        result.append(text[-1] + str(count))
        return "".join(result)

    @staticmethod
    def decompress(text: str) -> str:
        if not text:
            return ""

        result = []
        char = ""
        count = ""

        for c in text:
            if c.isdigit():
                count += c
            else:
                if char:
                    result.append(char * int(count))
                char = c
                count = ""

        if char:
            result.append(char * int(count))

        return "".join(result)

class RSAHandler:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generar_claves(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def firmar(self, data: bytes) -> bytes:
        return self.private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    def verificar(self, data: bytes, firma: bytes, public_key) -> bool:
        try:
            public_key.verify(
                firma,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


mensaje_original = ""
hash_mensaje = None
mensaje_comprimido = ""
firma_digital = None
public_key_enviada = None
rsa_handler = RSAHandler()

def menu():
    global mensaje_original, hash_mensaje, mensaje_comprimido
    global firma_digital, public_key_enviada

    while True:
        print("\n===============================")
        print("   SISTEMA DE MENSAJES SEGUROS")
        print("===============================")
        print("1. Ingresar mensaje")
        print("2. Calcular hash FNV-1")
        print("3. Comprimir mensaje (RLE)")
        print("4. Firmar hash con RSA")
        print("5. Simular envío")
        print("6. Descomprimir y verificar firma")
        print("7. Salir")

        opcion = input("Seleccione una opción: ")

        # 1. Ingresar mensaje
        if opcion == "1":
            mensaje_original = input("Ingrese el mensaje: ")
            print("Mensaje guardado.")

        # 2. Hash
        elif opcion == "2":
            if not mensaje_original:
                print("Primero ingrese un mensaje.")
                continue

            hash_mensaje = FNV1.hash(mensaje_original)
            print(f"Hash FNV-1: {hash_mensaje}")

        # 3. Compresión
        elif opcion == "3":
            if not mensaje_original:
                print("Ingrese un mensaje primero.")
                continue

            print(f"Tamaño original: {len(mensaje_original)} caracteres")
            mensaje_comprimido = RLE.compress(mensaje_original)
            print(f"Mensaje comprimido: {mensaje_comprimido}")
            print(f"Tamaño comprimido: {len(mensaje_comprimido)} caracteres")

        # 4. Firma digital
        elif opcion == "4":
            if hash_mensaje is None:
                print("Debe calcular el hash primero.")
                continue

            rsa_handler.generar_claves()
            firma_digital = rsa_handler.firmar(str(hash_mensaje).encode())

            print("Claves RSA generadas.")
            print("Clave pública:")
            print(
                rsa_handler.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            )
            print(f"Firma digital: {firma_digital.hex()}")

        # 5. Envío simulado
        elif opcion == "5":
            if not mensaje_comprimido or not firma_digital:
                print("Debe comprimir y firmar primero.")
                continue

            public_key_enviada = rsa_handler.public_key
            print("Mensaje, firma y clave pública enviados (simulado).")

        # 6. Recepción y verificación
        elif opcion == "6":
            if not public_key_enviada:
                print("No hay datos enviados.")
                continue

            # Descomprimir
            recibido_descomprimido = RLE.decompress(mensaje_comprimido)
            print(f"Mensaje recibido descomprimido: {recibido_descomprimido}")

            # Nuevo hash
            nuevo_hash = FNV1.hash(recibido_descomprimido)

            # Verificación
            valido = rsa_handler.verificar(str(nuevo_hash).encode(), firma_digital, public_key_enviada)

            if valido and nuevo_hash == hash_mensaje:
                print("✔ Mensaje auténtico y no modificado")
            else:
                print("✘ Mensaje alterado o firma no válida")
                
        elif opcion == "7":
            print("Saliendo...")
            break

        else:
            print("Opción inválida.")


if __name__ == "__main__":
    menu()
