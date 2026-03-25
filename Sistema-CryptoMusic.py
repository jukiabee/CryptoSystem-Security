import time
import os
import numpy as np
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

os.chdir(os.path.dirname(__file__))

# LOG
def registrar_log(msg):
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write(time.strftime("%H:%M:%S") + " - " + msg + "\n")

# ESCOLHER ARQUIVO
def escolher_arquivo():
    print("\nArquivos disponíveis na pasta:")
    arquivos = os.listdir()
    for a in arquivos:
        print("-", a)
    return input("\nDigite o nome do arquivo: ")

# CRIAR TXT
def criar_txt():
    nome = input("Nome do arquivo: ")
    texto = input("Digite o conteúdo: ")
    with open(nome + ".txt", "w") as f:
        f.write(texto)
    print("[OK] Arquivo criado")
    registrar_log("Arquivo criado " + nome + ".txt")

# AES
def criptografar_aes():
    nome = escolher_arquivo()
    base = os.path.splitext(nome)[0]
    inicio = time.time()
    chave = get_random_bytes(32)
    cifra = AES.new(chave, AES.MODE_EAX)
    with open(nome, "rb") as f:
        dados = f.read()
    criptografado, tag = cifra.encrypt_and_digest(dados)
    arquivo_saida = base + "_AES.enc"
    arquivo_chave = base + "_AES.key"
    with open(arquivo_saida, "wb") as f:
        f.write(cifra.nonce)
        f.write(tag)
        f.write(criptografado)
    with open(arquivo_chave, "wb") as f:
        f.write(chave)
    tempo = round(time.time() - inicio, 4)
    tamanho = os.path.getsize(nome)
    print("[OK] Arquivo criptografado:", arquivo_saida)
    registrar_log("AES | arquivo:" + nome +
        " | tamanho:" + str(tamanho) +
        " | tempo:" + str(tempo))

# AES DECRYPT
def descriptografar_aes():
    nome = escolher_arquivo()
    base = nome.replace("_AES.enc", "")
    inicio = time.time()
    with open(base + "_AES.key", "rb") as f:
        chave = f.read()
    with open(nome, "rb") as f:
        nonce = f.read(16)
        tag = f.read(16)
        criptografado = f.read()
    cifra = AES.new(chave, AES.MODE_EAX, nonce)
    dados = cifra.decrypt(criptografado)
    arquivo_saida = base + "_RECUPERADO.txt"
    with open(arquivo_saida, "wb") as f:
        f.write(dados)
    tempo = round(time.time() - inicio, 4)
    print("[OK] Arquivo recuperado")
    registrar_log("AES decrypt | arquivo:" + nome +
        " | tempo:" + str(tempo))

# RSA KEYS
def gerar_chaves_rsa():
    inicio = time.time()
    chave = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(chave.export_key())
    with open("public.pem", "wb") as f:
        f.write(chave.publickey().export_key())
    tempo = round(time.time() - inicio, 4)
    print("[OK] Chaves RSA geradas")
    registrar_log("RSA keys | tempo:" + str(tempo))

# CRIPTOGRAFIA HÍBRIDA
def criptografia_hibrida():
    nome = escolher_arquivo()
    base = os.path.splitext(nome)[0]
    inicio = time.time()
    chave_aes = get_random_bytes(32)
    cifra = AES.new(chave_aes, AES.MODE_EAX)
    with open(nome, "rb") as f:
        dados = f.read()
    criptografado, tag = cifra.encrypt_and_digest(dados)
    with open(base + "_HIBRIDO.enc", "wb") as f:
        f.write(cifra.nonce)
        f.write(tag)
        f.write(criptografado)
    with open("public.pem", "rb") as f:
        chave_publica = RSA.import_key(f.read())
    rsa = PKCS1_OAEP.new(chave_publica)
    chave_protegida = rsa.encrypt(chave_aes)
    with open(base + "_HIBRIDO.key", "wb") as f:
        f.write(chave_protegida)
    tempo = round(time.time() - inicio, 4)
    tamanho = os.path.getsize(nome)
    print("[OK] Criptografia híbrida concluída")
    registrar_log("HIBRIDO encrypt | " + nome +
        " | tamanho:" + str(tamanho) +
        " | tempo:" + str(tempo))

def descriptografia_hibrida():
    nome = escolher_arquivo()
    base = nome.replace("_HIBRIDO.enc", "")
    inicio = time.time()
    with open("private.pem", "rb") as f:
        chave_privada = RSA.import_key(f.read())
    rsa = PKCS1_OAEP.new(chave_privada)
    with open(base + "_HIBRIDO.key", "rb") as f:
        chave_aes = rsa.decrypt(f.read())
    with open(nome, "rb") as f:
        nonce = f.read(16)
        tag = f.read(16)
        criptografado = f.read()
    cifra = AES.new(chave_aes, AES.MODE_EAX, nonce)
    dados = cifra.decrypt(criptografado)
    with open(base + "_HIBRIDO_REC.txt", "wb") as f:
        f.write(dados)
    tempo = round(time.time() - inicio, 4)
    print("[OK] Arquivo recuperado")
    registrar_log("HIBRIDO decrypt | " + nome +
        " | tempo:" + str(tempo))

# ESTEGANOGRAFIA
def esteganografia():
    audio = input("Nome do WAV base: ")
    segredo = escolher_arquivo()
    base_audio = os.path.splitext(audio)[0]
    inicio = time.time()
    with open(audio, "rb") as f:
        audio_bytes = np.frombuffer(f.read(), dtype=np.uint8).copy()
    with open(segredo, "rb") as f:
        segredo_bytes = f.read()
    extensao = os.path.splitext(segredo)[1].encode()
    tamanho = len(segredo_bytes)
    dados = extensao + b'|' + tamanho.to_bytes(4, "big") + segredo_bytes
    bits = np.unpackbits(np.frombuffer(dados, dtype=np.uint8))
    if len(bits) > len(audio_bytes):
        print("Arquivo muito grande")
        return
    audio_bytes[:len(bits)] = (audio_bytes[:len(bits)] & 0xFE) | bits
    saida = base_audio + "_ESTEG.wav"
    with open(saida, "wb") as f:
        f.write(audio_bytes.tobytes())
    tempo = round(time.time() - inicio, 4)
    print("[OK] Arquivo escondido:", saida)
    registrar_log("ESTEG | " + segredo +
        " | tamanho:" + str(tamanho) +
        " | tempo:" + str(tempo))

def desteganografar():
    audio = input("Arquivo STEG: ")
    inicio = time.time()
    with open(audio, "rb") as f:
        audio_bytes = np.frombuffer(f.read(), dtype=np.uint8)
    bits = (audio_bytes & 1).astype(np.uint8)
    dados = np.packbits(bits).tobytes()
    separador = dados.find(b'|')
    extensao = dados[:separador].decode()
    tamanho = int.from_bytes(dados[separador + 1:separador + 5], "big")
    inicio_dados = separador + 5
    arquivo = dados[inicio_dados:inicio_dados + tamanho]
    saida = "arquivo_recuperado" + extensao
    with open(saida, "wb") as f:
        f.write(arquivo)
    tempo = round(time.time() - inicio, 4)
    print("[OK] Arquivo recuperado:", saida)
    registrar_log("DESTEG | " + audio +
        " | tempo:" + str(tempo))

# MENU
while True:
    print("\n==== Sistema CryptoMusic ====")
    print("1 Criar arquivo TXT")
    print("\n--- Criptografia Simétrica ---")
    print("2 Criptografar com AES")
    print("3 Descriptografar AES")
    print("\n--- Criptografia Assimétrica ---")
    print("4 Gerar chaves RSA")
    print("\n--- Criptografia Híbrida ---")
    print("5 Criptografar arquivo grande")
    print("6 Descriptografar arquivo")
    print("\n--- Esteganografia ---")
    print("7 Esconder arquivo em áudio")
    print("8 Separar arquivo esteganografado")
    print("\n0 Sair")
    op = input("Escolha: ")

    if op == "1":
        criar_txt()
    elif op == "2":
        criptografar_aes()
    elif op == "3":
        descriptografar_aes()
    elif op == "4":
        gerar_chaves_rsa()
    elif op == "5":
        criptografia_hibrida()
    elif op == "6":
        descriptografia_hibrida()
    elif op == "7":
        esteganografia()
    elif op == "8":
        desteganografar()
    elif op == "0":
        break
