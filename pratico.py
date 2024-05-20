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



#-----------------------------------------------ENCRYPTAR-----------------------------------------------
# Cifra o file original com chaves random, guarda as chaves random no chaves.bin e cifra-o 
# Gera o PIN de 3 a 4 digitos para o user tentar decifrar depois
# METER FILE CIFRADO NA PASTA FALL... E METER O chaves.bin NOUTRO SITIO NS ONDE---------------------------------------------------
def encrypt(input_file, output_file, key, cipher_choice, key_length_choice):

    # HMAC E HASH VALUE DO FICHEIRO ORIGINAL
    # Obrigatório ser do tipo global para poder verificar o valor da mesma no Decrypt
    global hmac_hashFO 
    hmac_hashFO = calc_hash_hmac(input_file, key)
    
    # Gera as Chaves Privada e Pública, devolve a Chave Privada e a Assinatura
    global file_sign
    # Na criação de variáveis em separado, corria a função duas vezes, gerava duas assinaturas diferentes
    file_sign = dig_sig(input_file)

    # Gera o pin random de 3 a 4 digitos
    pin = str(random.randint(100,9999))
    print("PIN ("+input_file+") -> " +pin)

    # Dar padding ao pin para ter caracteres suficientes para a key e iv
    pin_byte = pin.encode()
    key2 = pin_byte + b'=' * (int(key_length_choice) - len(pin_byte))
    iv2 = pin_byte + b'=' * (16 - len(pin_byte))

    # Calcular iv random, key no final vai tar aqui
    iv = os.urandom(16)

    # Ler o file que se quer cifrar em formato binário
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Dá padding ao texto do ficheiro para ser múltiplo do bloco e não dar erro
    padder = padding.PKCS7(cipher_choice.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Cifra o ficheiro com AES256 em modo Cipher-Block Chaining
    cipher = Cipher(cipher_choice(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # METER CHAVES E TEXTO EM FILES SEPARADOS
    with open(output_file, 'wb') as f:
        f.write(ciphertext)
    with open("chaves.bin", 'wb') as f:
        f.write(iv + key)

    # Calcular o hash e hmac do chaves original
    hmac_hash = calc_hash_hmac("chaves.bin", key)

    # Meter o hash e hmac no chaves
    with open("chaves.bin", 'wb') as f:
        f.write(str.encode(hmac_hash[0]) + str.encode(hmac_hash[1]) + iv + key)

    # Abrir o chaves.bin para cifrar as keys
    with open("chaves.bin", 'rb') as f:
        plaintext2 = f.read()
    

    #print(hmac_hash[0])
    #print(hmac_hash[1])
    

    # Padding ao texto do chaves.bin
    padder = padding.PKCS7(cipher_choice.block_size).padder()
    padded_plaintext = padder.update(plaintext2) + padder.finalize()

    # Cifra o chaves.bin com o AES256 em modo CBC, o iv e key tem o valor do PIN
    cipher = Cipher(cipher_choice(key2), modes.CBC(iv2), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Meter as keys cifradas noutro .bin (n é uma boa soluçao, depois mudar e fazer algo com o hash e hmac para comprar)
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
    print("Chave e Ficheiro Cifrados")





#-----------------------------------------------DECRYPTAR-----------------------------------------------
# Pede ao user o PIN para decifrar, se o user errar 3 vezes apaga o ficheiro original e das chaves,
# Se acertar o PIN decifra o chaves.bin e usa as chaves la dentro para decifrar o ficheiro original
def decrypt(input_file, output_file, cipher_choice, key_length_choice):
    
    # Nº de Tentativas
    contador = 3

    # Enquanto tiver tentativas restantes continua o programa
    while(contador > 0):

        pin = input("\nDecrypt PIN ("+str(contador)+" Tentativas): ")

        # Fazer a mesma coisa com o pin la em cima, se o pin for o mesmo vai decifrar bem o ficheiro 
        # Se nao vai dar erro e o try/catch vai apanhar diminuindo o numero de tentativas do pin
        pin_byte = pin.encode()
        key2 = pin_byte + b'=' * (int(key_length_choice) - len(pin_byte))
        iv2 = pin_byte + b'=' * (16 - len(pin_byte))

        try:
            # Tentar decifrar o ficheiro das chaves cifradas e o ficheiro do texto cifrado
            with open("chaves.bin", 'rb') as f:
                ciphertext2 = f.read()

            # Decifrar o chave com o AES256 em CBC e o PIN introduzido pelo user
            cipher = Cipher(cipher_choice(key2), modes.CBC(iv2), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext2) + decryptor.finalize()

            # Tirar o padding que metemos no inicio
            unpadder = padding.PKCS7(cipher_choice.block_size).unpadder()
            plaintext2 = unpadder.update(padded_plaintext) + unpadder.finalize()

            # Abrir o chaves.bin para meter la o texto decifrado
            with open("chaves.bin", 'wb') as f:
                f.write(plaintext2)

            # Ler chave,in,hash,hmac e mete-los em variaveis
            with open("chaves.bin", 'rb') as f:
                chaves_hash = f.read(64)
                chaves_hmac = f.read(64)
                iv = f.read(16)
                key = f.read(32)

            # Meter no chaves apenas o iv e key para ficar igual ao original
            with open("chaves.bin", 'wb') as f:
                f.write(iv + key)

            # Comparar o hash e hmac do chaves antigo com o chaves agr para ver se sao iguais
            Nchaves = calc_hash_hmac("chaves.bin",key)
            if((Nchaves[0] == chaves_hash.decode("utf-8")) and (Nchaves[1] == chaves_hmac.decode("utf-8"))):
                print("DEU")


            # Decifrar o ficheiro original
            with open(input_file, 'rb') as f:
                ciphertext = f.read()

            # Decifrar o ficheiro que queremos com as chaves que foram buscadas ao decifrar o chaves
            cipher = Cipher(cipher_choice(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Tirar o padding outra vez
            unpadder = padding.PKCS7(cipher_choice.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            # Meter o texto decifrado no ficheiro 
            with open(output_file, 'wb') as f:
                f.write(plaintext)


            # Caso tenha acertado o contador fica a -4 pra no final fazer o check de apagar o ficheiro
            contador = -4
        
        except: # try/catch ativa e tira uma tentativa
            contador = contador - 1
            print("PIN Errado")
    
    if(contador == 0): # 0 tentativas -> Apaga o ficheiro
        print("\nEsgotou Tentativas -> Ficheiro Apagado\n")
    else:

        # Calcula o HMAC E HASH VALUE DO FICHEIRO DECIFRADO
        hmac_hashFD = calc_hash_hmac(output_file, key)

        # Verificar a Assinatura do ficheiro de Output/Decifrado
        if( ver_sig(output_file, file_sign[0], file_sign[1]) ):
            print("\nFicheiro com Assinatura Válida")
        else:
            print("\nFicheiro com Assinatura Inválida")

        if hmac_hashFD == hmac_hashFO: # Se o valor hash do message authenticator do ficheiro original for igual do ficheiro decifrado, os ficheiros não sofreram alteração
            print("Ficheiro Decifrado -> Diretoria Decifrado")
            # Apagar o chaves.bin do ficheiro correspondente
        else: # Se o valor hash do message authenticator do ficheiro original for diferente do ficheiro decifrado, os ficheiros sofreram alteração
            print("Ficheiro Decifrado PORÉM Alterado -> Diretoria Decifrado")

    



#-----------------------------------------------HASH---HMAC-----------------------------------------------
# Abre os ficheiros e calcula o HMAC e HASH, usa a mesma key que foi usada na encriptacao do file original
def calc_hash_hmac(file_path, key):
    with open(file_path, "rb") as f:
        chunk_size = 4096
        # Inicializa um Hash com o Algoritmo AES256
        hasher = hashlib.sha256()
        # Inicializa um HMAC com a key dada como input
        hmac_hasher = hmac.new(key, digestmod=hashlib.sha256)
        # Vai dando update ao Hash e ao Hmac consoante os chunks q lê até chegar ao fim
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            hmac_hasher.update(chunk)
    
    # Dá return com os valores do Hash(AES256) e HMAC em hexadecimal na forma de array de tamanho 2
    return [hasher.hexdigest(), hmac_hasher.hexdigest()]





#-----------------------------------------------Dig. Signature-----------------------------------------------
def dig_sig(input_file):

    # Para poder verificar a assinatura com a assinutura resultante desta função
    global signature

    # Gera uma chave privada com public_exponent e tamanho recomendados pela documentação
    priv_k = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    signature = priv_k.sign(
        plaintext,
        # PSS -> Padding recomendado
        as_padding.PSS(
            # Mask Generation Function -> Gera uma máscara quando é dado o padding ao ficheiro usando a função SHA256
            mgf = as_padding.MGF1(hashes.SHA256()),
            # Indica o tamanha máxima permitido no padding -> Neste caso é o máximo que o PSS permite
            salt_length = as_padding.PSS.MAX_LENGTH
        ),
        # Algoritmo e valor de hash resultado do uso do algoritmo para a encriptação necessária para a produção da Assinatura
        hashes.SHA256()
    )

    return [priv_k, signature]





#-----------------------------------------------Verificar Signature-----------------------------------------------
def ver_sig(input_file, priv_k, signature):

    # Gera uma chave pública a partir da chave privada gerada anteriormente
    pk = priv_k.public_key()
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    try:
        pk.verify(
            signature,
            plaintext,
            as_padding.PSS(
                # Mask Generation Function -> Gera uma máscara quando é dado o padding ao ficheiro usando a função SHA256
                mgf = as_padding.MGF1(hashes.SHA256()),
                # Indica o tamanha máxima permitido no padding -> Neste caso é o máximo que o PSS permite
                salt_length = as_padding.PSS.MAX_LENGTH
            ),
            # Algoritmo e valor de hash resultado do uso do algoritmo para a encriptação necessária para a produção da Assinatura anteriormente
            hashes.SHA256()
        )
        # Verificou e as assinaturas são iguais
        return True
    except: # Se a assinatura não corresponder
        return False



#-----------------------------------------------TESTES/MAIN-----------------------------------------------
 # A key ta aqui para testes, no final vai ser criada no mesmo sitio que o iv
 
 # Variável a usar nas temrinações de ficheiros
extension = ".txt"
# Bool para determinar se a cifra já foi escolhida
choice_bool = True

e = input("\n-----Caso queira recorrer ao manual carregue em H/h-----\n-----Caso queira prosseguir carregue em P/p-----\n\nEscolha: ")
escolha = e.upper()

# Array de ficheiros cifrados
fc = []
# Array de ficheiros para cifrar
fpc = []

# PARA TESTAR: Criar um ficheiro (de preferência fora da FALL...), mover o ficheiro para a FALL-INTO-OBLIVION, mover de seguida para o Recuperacao e meter o PIN
while(True):
    match escolha:
        case "H":
            print("\n-----Help----\nO Programa consiste numa Reciclagem de um sistema operativo normal alterada, ao eliminar os ficheiros (Move-los para a pasta FALL-INTO-OBLIVION) é lhe dado um PIN correspondente ao ficheiro que enviou.\nPara recuperar o ficheiro terá de movê-lo outra vez para a pasta Recuperação e terá três tentativas para inserir esse código PIN.\nCaso não acerte o PIN nas três tentativas dadas o ficheiro é eliminado permanentemente do seu sistema, caso acerte é verificada a integridade do ficheiro de modo a saber se foi alterado ou corrompido no processo todo.\nPor fim, caso tenha acertado o PIN terá o ficheiro recuperado na pasta Decifrados.\nNo processo de recuperação é lhe informada a integridade.")
            # CANCELAR O LOOP
            escolha = "C"
        case "P":
            e = os.listdir("./FALL-INTO-OBLIVION")
            d = os.listdir("./Recuperacao")   
            
            # Se a cifra ainda não foi escolhida (choice_bool=True), pede ao utilizador para escolher a cifra e o tamanho da chave
            if(choice_bool):
                cipher_choice = input("Escolha a cifra a utilizar:\nA) AES \nB) Camellia\n> ")
            
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
                                
                # Gera uma chave random para a cifra
                key = os.urandom(int(key_length_choice))
                # Determina que a cifra já foi escolhida
                choice_bool = False

            # Se a diretoria FALL-INTO-OBLIVION tiver algum ficheiro com a extensão de texto (txt), irá invocar a função de encriptação
            if len(e) > 0:
                for i in e:
                    # File for Encryption
                    ffenc = "./FALL-INTO-OBLIVION/"+i
                    # Caso haja um ficheiro que foi introduzido na FALL... com o mesmo nome de um ficheiro que já foi cifrado anteriormente
                    # Esse ficheiro introduzido assume-se como Erro e é movido para a pasta Repetidos
                    if i in fpc:
                        # Mover para a pasta Repetidos
                        os.rename("./FALL-INTO-OBLIVION/"+i, "./Repetidos/"+i)
                    # Se houver um ficheiro na pasta que não tenha sido cifrado anteriormente (Não se encontre no array de ficheiros cifrados)
                    if os.path.exists(ffenc) and not(i in fc) and not(i in fpc):
                        # Adicionar o nome original (antes de cifrar) do ficheiro ao array de ficheiros para cifrar
                        fpc.append(i)
                        # Invoca a função encrypt com o ficheiro como input e devolve um ficheiro cifrado com a cifra escolhida
                        encrypt(ffenc, "./FALL-INTO-OBLIVION/"+i+extension, key, cipher_choice, key_length_choice)
                        # Junta o nome do ficheiro que já foi cifrado ao array
                        fc.append(i+extension)
                        # Após cifrar o ficheiro, remove o ficheiro original da pasta FALL-INTO-OBLIVION (Plaintext)
                        os.remove(ffenc)

            # Se a diretoria Recuperacao tiver algum ficheiro com a extensão de texto (aes256-cbc), irá invocar a função de desencriptação
            if len(d) > 0:
                for i in d:
                    if i.endswith(extension):
                        # Invoca a função decrypt com o ficheiro cifrado como input e devolve um ficheiro decifrado para a pasta de Decifrados após a inserção do pin correto
                        decrypt("./Recuperacao/"+os.path.splitext(i)[0]+extension, "./Decifrados/"+os.path.splitext(i)[0]+".txt", cipher_choice, key_length_choice)
                        # Após decifrar o ficheiro, remove o criptograma da pasta de Recuperacao
                        os.remove("./Recuperacao/"+os.path.splitext(i)[0]+extension)
            
            #Verifica as pastas a cada segundo
            time.sleep(1)
        case _:
            e = input("\n-----Caso queira recorrer ao manual carregue em H/h-----\n-----Caso queira prosseguir carregue em P/p-----\n\nEscolha: ")
            escolha = e.upper()