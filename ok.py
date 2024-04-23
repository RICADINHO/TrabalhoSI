import os
import hashlib
import hmac
import random

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend





#-----------------------------------------------HASH---HMAC-----------------------------------------------
# abre os ficheiros e calcula o HMAC e HASH, usa a mesma key que foi usada na encriptacao do file original
def calc_hash_hmac(file_path,key):
    with open(file_path, "rb") as f:
        chunk_size = 4096
        hasher = hashlib.sha256()
        hmac_hasher = hmac.new(key, digestmod=hashlib.sha256)
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            hmac_hasher.update(chunk)
    
    return [hasher.hexdigest(),hmac_hasher.hexdigest()]





#-----------------------------------------------ENCRYPTAR-----------------------------------------------
# encripta o file original (a.txt) com chaves random, guarda as chaves random no chaves.bin e encrypta-o 
# , gera o PIN de 4 digitos para o user tentar decryptar depois
# METER FILE ENCRIPTADO NA PASTA FALL... E METER O chaves.bin NOUTRO SITIO NS ONDE---------------------------------------------------
def encrypt(input_file, output_file, key):

    # Gera o pin random de 4 digitos
    pin = str(random.randint(1000,9999))
    print("PINNNN --------" +pin)

    # dar padding ao pin para ter caracteres suficientes para a key e iv
    pin_byte = pin.encode()
    key2 = pin_byte + b'=' * (32 - len(pin_byte))
    iv2 = pin_byte + b'=' * (16 - len(pin_byte))

    # calcular iv random, key no final vai tar aqui
    iv = os.urandom(16)

    # ler o file que se quer encryptar
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # da padding ao texto do ficheiro para ser multiplo do bloco e n dar erro
    padder = padding.PKCS7(algorithms.AES256.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # encrypta o ficheiro com AES256
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # METER CHAVES E TEXTO EM FILES SEPARADOS
    with open(output_file, 'wb') as f:
        f.write(ciphertext)
    with open("chaves.bin", 'wb') as f:
        f.write(iv + key)

    # calcular o hash e hmac do chaves original
    hmac_hash = calc_hash_hmac("chaves.bin",key)

    # meter o hash e hmac no chaves
    with open("chaves.bin", 'wb') as f:
        f.write(str.encode(hmac_hash[0]) + str.encode(hmac_hash[1]) + iv + key)

    # abrir o chaves.bin para encryptar as keys
    with open("chaves.bin", 'rb') as f:
        plaintext2 = f.read()
    

    #print(hmac_hash[0])
    #print(hmac_hash[1])
    

    # padding ao texto do chaves.bin
    padder = padding.PKCS7(algorithms.AES256.block_size).padder()
    padded_plaintext = padder.update(plaintext2) + padder.finalize()

    # encrypta o chaves.bin com o AES256, o iv e key tem o valor do PIN
    cipher = Cipher(algorithms.AES256(key2), modes.CBC(iv2), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # meter as keys encryptadas noutro .bin (n é uma boa soluçao, depois mudar e fazer algo com o hash e hmac para comprar)
    with open("chaves.bin", 'wb') as f:
        f.write(ciphertext)

    '''
    x1 = calc_hash_hmac("chaves.bin",key2)
    x2 = calc_hash_hmac("chaves2.bin",key2)
    print("hash chaves: "+x1[0])
    print("hmac chaves: "+x1[1])
    print("hash chaves2: "+x2[0])
    print("hmac chaves2: "+x2[1])
    '''
    print("criptei o chaves e o original")





#-----------------------------------------------DECRYPTAR-----------------------------------------------
# pede ao user o PIN para decryptar, se o user errar 3 vezes apaga o ficheiro original e das chaves,
# se acertar o PIN decrypta o chaves.bin e usa as chaves la dentro para decryptar o ficheiro original
def decrypt(input_file, output_file):
    contador = 3 # tentativas

    while(contador > 0):
        pin = input("diz o pin para dar decrypt (tens mais "+str(contador)+" tentativas): ")

        # Fazer a mesma coisa com o pin la em cima, se o pin for o mesmo vai decryptar bem o ficheiro 
        # se nao vai dar erro e o try/catch vai apanhar diminuindo o numero de tentativas do pin
        pin_byte = pin.encode()
        key2 = pin_byte + b'=' * (32 - len(pin_byte))
        iv2 = pin_byte + b'=' * (16 - len(pin_byte))

        try:
            # tentar decryptar o ficheiro das chaves encryptadas e o ficheiro do texto encryptado
            with open("chaves.bin", 'rb') as f:
                ciphertext2 = f.read()

            # decifrar o chave com o AES256 e o PIN introduzido pelo user
            cipher = Cipher(algorithms.AES256(key2), modes.CBC(iv2), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext2) + decryptor.finalize()

            # tirar o padding que metemos no inicio
            unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
            plaintext2 = unpadder.update(padded_plaintext) + unpadder.finalize()

            # abrir o chaves.bin para meter la o texto decriptado
            with open("chaves.bin", 'wb') as f:
                f.write(plaintext2)

            # ler chave,in,hash,hmac e mete-los em variaveis
            with open("chaves.bin", 'rb') as f:
                chaves_hash = f.read(64)
                chaves_hmac = f.read(64)
                iv = f.read(16)
                key = f.read(32)

            # meter no chaves apenas o iv e key para ficar igual ao original
            with open("chaves.bin", 'wb') as f:
                f.write(iv + key)

            # comparar o hash e hmac do chaves antigo com o chaves agr para ver se sao iguais
            Nchaves = calc_hash_hmac("chaves.bin",key)
            if((Nchaves[0] == chaves_hash.decode("utf-8")) and (Nchaves[1] == chaves_hmac.decode("utf-8"))):
                print("deu")


            # Decriptar o ficheiro original
            with open(input_file, 'rb') as f:
                ciphertext = f.read()

            # decriptar o ficheiro que queremos com as chaves que foram buscadas ao decriptar o chaves
            cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # tirar o padding outravez
            unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            # meter o texto decryptado no ficheiro 
            with open(output_file, 'wb') as f:
                f.write(plaintext)


            # FAZER UM CHECK AQUI PARA VER A INTEGRIDADE DO FILE ANTIGO E NOVO----------------------------------------------------------------------
            # Caso tenha acertado o contador fica a -4 pra no final fazer o check de apagar o ficheiro
            contador = -4
        
        except: # try/catch ativa e tira uma tentativa
            contador = contador - 1
            print("PIN errado")
    
    if(contador == 0): # 0 tentativas apaga o ficheir
        print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nAcabaram as tentativas, apaguei o ficheiro")
        #os.remove("a.txt")
    else:
        print("decriptei o ficheiro")
        # depois apagar o chaves.bin do ficheiro correspondente e tirar esse ficheiro do FALL-INTO-OBLIVION

    



#-----------------------------------------------TESTES/MAIN-----------------------------------------------
key = os.urandom(32) # a key ta aqui para testes, no final vai ser criada no mesmo sitio que o iv
print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
while(True): # criar o ficheiro a.txt e meter algo la dentro pra testar
    option = input("escreve 'e' para encryptar e 'd' para decryptar: ")
    if option == 'e':
        print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
        encrypt("a.txt", "Ea.txt", key) 
        '''
        x = calc_hash_hmac("a.txt",key)
        x2 = calc_hash_hmac("Ea.txt",key)
        print("Hash a.txt: "+x[0])
        print("Hmac a.txt: "+x[1])
        print("Hash Ea.txt: "+x2[0])
        print("Hmac Ea.txt: "+x2[1])
        '''
    elif option == 'd':
        print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
        decrypt("Ea.txt", "Da.txt")
        '''
        x3 = calc_hash_hmac("Ea.txt",key)
        x4 = calc_hash_hmac("Da.txt",key)
        print("Hash Ea.txt: "+x3[0])
        print("Hmac Ea.txt: "+x3[1])
        print("Hash Da.txt: "+x4[0])
        print("Hmac Da.txt: "+x4[1])
        '''


