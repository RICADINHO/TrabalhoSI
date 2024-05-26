import os
import hashlib
import hmac
import random
import time

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# IMPORTS ASSINATURA DIGITAL
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
# Preciso meter uma variável para evitar conflitos com o padding importado em cima
from cryptography.hazmat.primitives.asymmetric import padding as as_padding
from cryptography.hazmat.primitives import serialization

from pathlib import Path



#-----------------------------------------------ENCRYPTAR-----------------------------------------------
def encrypt(input_file, output_file, key, cipher_choice, key_length_choice, hash_choice, hasher_choice):

    # Calcular hmac e hash do ficheiro original
    hmac_hashFO = calc_hash_hmac(input_file, key, hasher_choice)
    
    # Gerar a Chaves Privada e Assinatura, guardadas na variável file_sign
    file_sign = dig_sig(input_file, hash_choice)

    # ------------ PIN ------------
    # Gerar o pin aleatório de 3 a 4 digitos
    pin = str(random.randint(100,9999))
    print("PIN ("+input_file+") -> " +pin)

    # Dar padding ao pin para ter caracteres suficientes para a key e iv
    pin_byte = pin.encode()
    key2 = pin_byte + b'=' * (int(key_length_choice) - len(pin_byte))
    iv2 = pin_byte + b'=' * (16 - len(pin_byte))

    # ------------ FICHEIRO ------------
    # Calcular iv aleatório
    iv = os.urandom(16)
    
    # Ler o file que se quer cifrar em formato binário
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Dar padding ao texto do ficheiro para ser múltiplo do bloco e não dar erro
    padder = padding.PKCS7(cipher_choice.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Cifrar o ficheiro com a cifra escolhida em modo Cipher-Block Chaining
    cipher = Cipher(cipher_choice(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Escrever o ficheiro cifrado
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

    # ------------ CHAVE ------------
    # Escrever a chave e iv num ficheiro binário (.bin)
    chave = output_file+".bin"
    with open(chave, 'wb') as f:
        f.write(iv + key)

    # Calcular o hash e hmac do .bin
    hmac_hash = calc_hash_hmac(chave, key, hasher_choice)
    
    # Trasformar a private key em bytes para ser escrita no .bin
    pkey_bytes = file_sign[0].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Colocar o hash e hmac das chaves, hash e hmac do ficheiro original, signature e private key no .bin
    with open(chave, 'wb') as f:
        f.write(str.encode(hmac_hash[0]) + str.encode(hmac_hash[1]) + iv + key)
        f.write(str.encode(hmac_hashFO[0]) + str.encode(hmac_hashFO[1]))
        f.write(file_sign[1])
        f.write(pkey_bytes)

    # Abrir o .bin para cifrar o conteudo adicionado
    with open(chave, 'rb') as f:
        plaintext2 = f.read()
    

    # Padding ao texto do .bin
    padder = padding.PKCS7(cipher_choice.block_size).padder()
    padded_plaintext = padder.update(plaintext2) + padder.finalize()

    # Cifrar o conteudo do .bin com a cifra escolhida em modo Cipher-Block Chaining
    cipher = Cipher(cipher_choice(key2), modes.CBC(iv2), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Colocar o conteudo cifrado no .bin
    with open(chave, 'wb') as f:
        f.write(ciphertext)

    # Mover o ficheiro já cifrado para a pasta FALL-INTO-OBLIVION    
    os.rename(output_file, "./FALL-INTO-OBLIVION/"+output_file)
    # Mover o .bin já cifrado para a pasta de Chaves
    os.rename(chave, "./Chaves/"+chave)





#-----------------------------------------------DECRYPTAR-----------------------------------------------
# Pede ao user o PIN para decifrar, se o user errar 3 vezes apaga o ficheiro original e o .bin,
# Se acertar o PIN decifra o .bin e usa o seu conteudo para decifrar e verificar o ficheiro original
def decrypt(input_file, output_file, cipher_choice, key_length_choice, hash_choice, hasher_choice):
    # Nº de Tentativas
    contador = 3

    # Enquanto tiver tentativas restantes continua o programa
    while(contador > 0):

        # ------------ PIN ------------
        pin = input("\nDecrypt PIN ("+str(contador)+" Tentativas): ")

        # Dar padding ao pin para ter caracteres suficientes para a key e iv.  
        pin_byte = pin.encode()
        key2 = pin_byte + b'=' * (int(key_length_choice) - len(pin_byte))
        iv2 = pin_byte + b'=' * (16 - len(pin_byte))

        # Se o pin for o mesmo, decifra bem o ficheiro
        # Caso contrário, o try/catch vai acionar, diminuindo o numero de tentativas do pin
        try:
            # ------------ CHAVE ------------

            chave = "./Chaves/"+input_file+".bin"

            # Abrir o .bin para decifrar o conteudo
            with open(chave, 'rb') as f:
                ciphertext2 = f.read()

            # Decifrar o conteudo do .bin com a cifra escolhida em CBC, com o PIN introduzido pelo user (inserido na key2 e iv2)
            cipher = Cipher(cipher_choice(key2), modes.CBC(iv2), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext2) + decryptor.finalize()

            # Tirar o padding colocado no inicio
            unpadder = padding.PKCS7(cipher_choice.block_size).unpadder()
            plaintext2 = unpadder.update(padded_plaintext) + unpadder.finalize()

            # Abrir o .bin para colocar o texto decifrado
            with open(chave, 'wb') as f:
                f.write(plaintext2)

            # Ler chave,iv,hash,hmac das chaves e ficheiro original e guarda-los em variaveis
            with open(chave, 'rb') as f:
                chaves_hash = f.read(64)
                chaves_hmac = f.read(64)
                iv = f.read(16)
                key = f.read(int(key_length_choice))
                ficheiro_hash = f.read(64)
                ficheiro_hmac = f.read(64)
                ficheiro_sign = f.read(256)
                ficheiro_pkey_encoded = f.read()
                # Transformar a chave privada em objeto do tipo RSA Private Key
                ficheiro_pkey = serialization.load_pem_private_key(
                                    ficheiro_pkey_encoded,
                                    password=None
                                )

            # Meter o hash e hmac do ficheiro original num array para comparar com os do ficheiro decifrado   
            FO_hash = [ficheiro_hash.decode("utf-8"), ficheiro_hmac.decode("utf-8")]     

            # Meter no .bin apenas o iv e key para ficar igual ao original
            with open(chave, 'wb') as f:
                f.write(iv + key)

            # Comparar o hash e hmac do .bin antigo com o .bin novo para verificar se são iguais
            Nchaves = calc_hash_hmac(chave, key, hasher_choice)
            if((Nchaves[0] == chaves_hash.decode("utf-8")) and (Nchaves[1] == chaves_hmac.decode("utf-8"))):
                print("Ficheiro .bin íntegro")

            # ------------ FICHEIRO ------------
            # Abrir e ler o ficheiro cifrado e guardar o conteúdo em ciphertext
            with open("./Recuperacao/"+input_file, 'rb') as f:
                ciphertext = f.read()

            # Decifrar o conteúdo do ficheiro
            cipher = Cipher(cipher_choice(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Tirar o padding colocado no inicio
            unpadder = padding.PKCS7(cipher_choice.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            # Colocar o texto decifrado no ficheiro 
            with open(output_file, 'wb') as f:
                f.write(plaintext)

            # Verificar se já existe um ficheiro com o mesmo nome no "Decifrados", que caso exista será apagado
            for a in os.scandir("Decifrados"): 
                if str(a).split("'")[1] == output_file:
                    os.remove(a)
                    print("removi "+output_file)
            
            # Caso tenha acertado o contador fica a -4 para no final fazer o check de apagar o ficheiro
            contador = -4
        
        except: # Try/catch aciona e tira uma tentativa
            contador = contador - 1
            print("PIN Errado")
    
    if(contador == 0): # 0 tentativas -> Apaga o ficheiro
        print("\nEsgotou Tentativas -> Ficheiro Apagado\n")
        # Eliminar o .bin dedicado ao output_file
        os.remove(chave)
    else: # ACERTOU O PIN

        # Calcular o hmac e hash value do ficheiro decifrado
        hmac_hashFD = calc_hash_hmac(output_file, key, hasher_choice)

        # Verificar a Assinatura do ficheiro de Output/Decifrado
        if( ver_sig(output_file, ficheiro_pkey, ficheiro_sign, hash_choice) ):
            print("\nFicheiro com Assinatura Válida")
        else:
            print("\nFicheiro com Assinatura Inválida")

        if hmac_hashFD == FO_hash: # Se o valor hash do ficheiro original for igual ao do ficheiro decifrado, os ficheiros não sofreram alteração
            print("Ficheiro Decifrado -> Diretoria Decifrado")
        else: # Se o valor hash do ficheiro original for diferente ao do ficheiro decifrado, os ficheiros sofreram alteração
            print("Ficheiro Decifrado PORÉM Alterado -> Diretoria Decifrado")
            
        # Eliminar o .bin dedicada ao output_file
        os.remove(chave)
        # Colocar o output_file para a pasta dos decifrados
        os.rename(output_file, "./Decifrados/"+output_file)


#-----------------------------------------------HASH---HMAC-----------------------------------------------
# Abrir os ficheiros e calcular o HMAC e HASH, usar a mesma key que foi usada na encriptação do ficheiro original
def calc_hash_hmac(file_path, key, hasher_choice):
    with open(file_path, "rb") as f:
        chunk_size = 4096
        # Inicializar um Hash
        hasher = hasher_choice()
        # Inicializar um HMAC com a key dada como input
        hmac_hasher = hmac.new(key, digestmod=hasher_choice)
        # Dar update ao Hash e ao Hmac consoante os chunks que lê, até chegar ao fim
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            hmac_hasher.update(chunk)
    
    # Devolver os valores do Hash e HMAC em hexadecimal na forma de array de tamanho 2
    return [hasher.hexdigest(), hmac_hasher.hexdigest()]


#-----------------------------------------------Dig. Signature-----------------------------------------------
def dig_sig(input_file, hash_choice):

    # Gerar uma chave privada com public_exponent e tamanho recomendados pela documentação
    priv_k = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Abrir o ficheiro que se quer assinar em formato binário e guardar o seu conteúdo na variável plaintext
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    signature = priv_k.sign(
        plaintext,
        # PSS -> Padding recomendado
        as_padding.PSS(
            # Mask Generation Function -> Gera uma máscara quando é dado o padding ao ficheiro usando a função de hash escolhida
            mgf = as_padding.MGF1(hash_choice()),
            # Indica o tamanha máxima permitido no padding -> Neste caso é o máximo que o PSS permite
            salt_length = as_padding.PSS.MAX_LENGTH
        ),
        # Algoritmo e valor de hash resultado do uso do algoritmo para a encriptação necessária para a produção da Assinatura
        hash_choice()
    )

    # Devolver a private key e a assinatura
    return [priv_k, signature]


#-----------------------------------------------Verificar Signature-----------------------------------------------
def ver_sig(input_file, priv_k, signature, hash_choice):

    # Gerar uma chave pública a partir da chave privada gerada anteriormente
    pk = priv_k.public_key()
    
    # Abrir o ficheiro que se quer verificar em formato binário e guardar o seu conteúdo na variável plaintext
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    try:
        pk.verify(
            signature,
            plaintext,
            as_padding.PSS(
                # Mask Generation Function -> Gera uma máscara quando é dado o padding ao ficheiro usando a função de hash escolhida
                mgf = as_padding.MGF1(hash_choice()),
                # Indica o tamanha máxima permitido no padding -> Neste caso é o máximo que o PSS permite
                salt_length = as_padding.PSS.MAX_LENGTH
            ),
            # Algoritmo e valor de hash resultado do uso do algoritmo para a encriptação necessária para a produção da Assinatura anteriormente
            hash_choice()
        )
        # Verificou e as assinaturas são iguais
        return True
    except: # Se a assinatura não corresponder
        return False

#-----------------------------------------------CHECKS-----------------------------------------------
def check_ficheiros():
    ficheiros = os.scandir(os.getcwd())

    pastas = []
    files = ["FALL-INTO-OBLIVION","Chaves","Decifrados","Recuperacao","Repetidos"]

    for i in ficheiros: # Guardar todas as pastas da diretoria atual
        if i.is_dir():
            pastas.append(str(i.name))
    
    for i in files: # Verificar se alguma pasta é uma das pastas que o programa necessita
        if i in pastas:
            if os.listdir(i): # Se já existir, ver se contém algo. Se sim, apaga
                for i2 in os.scandir(i):
                    os.remove(i2)
        else:
            os.mkdir(i) # Se nao tiver a pasta presente, criar uma nova

def check_pastas(nome): # Retornar apenas os ficheiros que não sao pastas
    pastas = os.scandir(nome)
    e = []

    for i in pastas:
        if i.is_dir() == False:
            e.append(str(i.name))
    
    return e
    


#-----------------------------------------------TESTES/MAIN-----------------------------------------------
# Variável a usar nas terminações de ficheiros
extension = ".txt"
# Bool para determinar se a cifra já foi escolhida
choice_bool = True

# Verificar se o programa esta em condicoes de executar
check_ficheiros()

e = input("\n-----Caso queira recorrer ao manual carregue em H/h-----\n-----Caso queira prosseguir carregue em P/p-----\n\nEscolha: ")
escolha = e.upper()

# Array de ficheiros cifrados
fc = []
# Array de ficheiros para cifrar
fpc = []

# Loop para o programa
while(True):
    match escolha:
        case "H":
            print("\n-----Help----\nO Programa consiste numa Reciclagem de um sistema operativo normal alterada, ao eliminar os ficheiros (Move-los para a pasta FALL-INTO-OBLIVION) é lhe dado um PIN correspondente ao ficheiro que enviou.\nPara recuperar o ficheiro terá de movê-lo outra vez para a pasta Recuperação e terá três tentativas para inserir esse código PIN.\nCaso não acerte o PIN nas três tentativas dadas o ficheiro é eliminado permanentemente do seu sistema, caso acerte é verificada a integridade do ficheiro de modo a saber se foi alterado ou corrompido no processo todo.\nPor fim, caso tenha acertado o PIN terá o ficheiro recuperado na pasta Decifrados.\nNo processo de recuperação é lhe informada a integridade.")
            # CANCELAR O LOOP
            escolha = "C"
        case "P":
            e = check_pastas("./FALL-INTO-OBLIVION")
            d = os.listdir("./Recuperacao")   
            
            # Se a cifra, tamanho de chave e hash ainda não tenham sido escolhidos (choice_bool=True), pede ao utilizador para os escolher
            if(choice_bool):
                cipher_choice = input("Escolha a cifra a utilizar:\nA) AES \nB) Camellia\n> ")
            
                # Escolha da cifra
                if cipher_choice.upper() == "A":
                    cipher_choice = algorithms.AES
                    extension = ".aes-cbc"
                elif cipher_choice.upper() == "B":
                    cipher_choice = algorithms.Camellia
                    extension = ".camellia-cbc"
                else:
                    cipher_choice = algorithms.AES
                    extension = ".aes-cbc"
                    print("Escolha inválida, AES escolhida por defeito") 
                     
                # Escolha do tamanho da chave
                key_length_choice = input("Escolha o tamanho da chave:\nA) 32 bytes \nB) 24 bytes \nC) 16 bytes \n> ")
                
                if key_length_choice.upper() == "A":
                    key_length_choice = "32"
                elif key_length_choice.upper() == "B":
                    key_length_choice = "24"
                elif key_length_choice.upper() == "C":
                    key_length_choice = "16"                        
                else:
                    key_length_choice = "32"
                    print("Escolha inválida, 32 bytes escolhida por defeito")  
                                    
                # Escolha do algoritmo de hash
                hash_choice = input("Escolha o algoritmo de hash a utilizar:\nA) SHA2_256 \nB) SHA3_256 \n> ")
                hasher_choice = hashlib.sha256
                
                if hash_choice.upper() == "A":
                    hash_choice = hashes.SHA256
                    hasher_choice = hashlib.sha256
                elif hash_choice.upper() == "B":
                    hash_choice = hashes.SHA3_256
                    hasher_choice = hashlib.sha3_256
                else:
                    hash_choice = hashes.SHA256
                    print("Escolha inválida, SHA256 escolhida por defeito")
                                
                # Gera uma chave aleatória para a cifra
                key = os.urandom(int(key_length_choice))
                # Determina que a cifra já foi escolhida
                choice_bool = False

            # Se a diretoria FALL-INTO-OBLIVION tiver algum ficheiro, irá invocar a função de encriptação
            if len(e) > 0:
                for i in e:
                    # File for Encryption
                    ffenc = "./FALL-INTO-OBLIVION/"+i
                    # Caso haja um ficheiro que foi introduzido na FALL... com o mesmo nome de um ficheiro que já foi cifrado anteriormente,
                    # esse ficheiro introduzido assume-se como Erro e é movido para a pasta Repetidos
                    if i in fpc:
                        # Mover para a pasta Repetidos
                        os.rename("./FALL-INTO-OBLIVION/"+i, "./Repetidos/"+i)
                    # Se houver um ficheiro na pasta que não tenha sido cifrado anteriormente (Não se encontre no array de ficheiros cifrados)
                    if os.path.exists(ffenc) and not(i in fc) and not(i in fpc):
                        # Adicionar o nome original (antes de cifrar) do ficheiro ao array de ficheiros para cifrar
                        fpc.append(i)
                        # Invocar a função encrypt com o ficheiro como input e devolver um ficheiro cifrado com a cifra escolhida
                        encrypt(ffenc, i+extension, key, cipher_choice, key_length_choice, hash_choice, hasher_choice)
                        # Adicionar o nome do ficheiro que já foi cifrado ao array
                        fc.append(i+extension)
                        # Após cifrar o ficheiro, remover o ficheiro original da pasta FALL-INTO-OBLIVION (Plaintext)
                        os.remove(ffenc)

            # Se a diretoria Recuperacao tiver algum ficheiro com a extensão de encriptado, irá invocar a função de desencriptação
            if len(d) > 0:
                for i in d:
                    if i.endswith(extension):
                        # Invocar a função decrypt com o ficheiro cifrado como input e devolver um ficheiro decifrado para a pasta de Decifrados após a inserção do pin correto
                        decrypt(os.path.splitext(i)[0]+extension, os.path.splitext(i)[0], cipher_choice, key_length_choice, hash_choice, hasher_choice)
                        # Após decifrar o ficheiro, remove o criptograma da pasta de Recuperacao
                        os.remove("./Recuperacao/"+os.path.splitext(i)[0]+extension)
                        # Remover o ficheiro já decifrado do array dos ficheiros para cifrar e do array dos ficheiros cifrados
                        fc.remove(os.path.splitext(i)[0]+extension)
                        fpc.remove(os.path.splitext(i)[0])
            
            #Verificar as pastas a cada segundo
            time.sleep(1)
        case _:
            e = input("\n-----Caso queira recorrer ao manual carregue em H/h-----\n-----Caso queira prosseguir carregue em P/p-----\n\nEscolha: ")
            escolha = e.upper()