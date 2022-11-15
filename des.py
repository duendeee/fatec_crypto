import argparse
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from itertools import product
from gc import collect


# TODO: Suportar outros modos classicos (CFB, CTR, OFB): https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#
# TODO: Suportar crypt/decrypt de arquivos inteiror.
# TODO: Multiprocessing/threading para speed-up brute-force, gen/test key;
# TODO: Aprimorar filtro para crib, receber chars individuais e substrings;


def show_banner():
    print("""\n
    #  ██████╗ ███████╗███████╗    ██████╗  ██████╗  ██████╗
    #  ██╔══██╗██╔════╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
    #  ██║  ██║█████╗  ███████╗    ██████╔╝██║   ██║██║     
    #  ██║  ██║██╔══╝  ╚════██║    ██╔═══╝ ██║   ██║██║     
    #  ██████╔╝███████╗███████║    ██║     ╚██████╔╝╚██████╗
    #  ╚═════╝ ╚══════╝╚══════╝    ╚═╝      ╚═════╝  ╚═════╝
    #  [*] Desafio Criptografia - Prof. Leonardo.                                                     
        \n""")


def set_des_mode(des_mode):
    match des_mode:
        case 'ecb': return DES.MODE_ECB
        case 'cbc': return DES.MODE_CBC
        case 'cfb': return DES.MODE_CFB
        case 'ctr': return DES.MODE_CTR
        case 'ofb': return DES.MODE_OFB


def save_results(key, msg, file):
    with open(file, 'a') as file:
        file.write(f"Possivel chave: {key} -- Possivel mensagem: {msg}\n")


def encrypt(key, plain_msg, des_mode):
    chipher = DES.new(key, des_mode)
    chipher_msg = chipher.encrypt(pad(plain_msg, DES.block_size))
    return chipher_msg


def decrypt(key, chipher_msg, des_mode):
    plain_msg = ''
    if des_mode == 1:
        chipher = DES.new(key, des_mode)
        plain_msg = chipher.decrypt(chipher_msg.decode('unicode-escape').encode('raw_unicode_escape'))
    return plain_msg


def brute_force(chipher_msg, crib=None):
    """ brute-force p/ alfabeto minusculo, maiusculo e numeros"""

    chars = [chr(i) for i in range(97, 123)]  # minusculas
    chars += [chr(i) for i in range(65, 91)]  # maiusculas
    chars += [chr(i) for i in range(48, 58)]  # numeros
    # chars = string.ascii_letters + string.digits ---> MAIS RAPIDO!

    for i in product(chars, repeat=8):
        key_test = ''.join(i)
        plain_msg = decrypt(key=bytes(key_test, 'utf-8'), chipher_msg=bytes(
            configs['msg'], 'utf-8'), des_mode=set_des_mode(configs['dm']))

        print(f"[*] Chave: {key_test} -- Mensagem: {plain_msg.decode('latin-1')}")

        try:
            # melhorar perfomance, isso é lixo!
            if crib is not None and crib in plain_msg.decode():
                save_results(key_test, plain_msg, file="crack_crib.txt")
            else: save_results(key_test, plain_msg, file="crack_all.txt")
        except Exception as err: pass
        finally:
            collect() # Garantir(?) limpeza de memoria p/ excecoes..


def make_configs():
    # Create the parser and add arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--option', dest='opt', type=int,
                        default=0,
                        help="Opção: (1) encrypt; (2) decrypt; (3) brute force.")

    parser.add_argument('-msg', '--message', dest='msg', type=str,
                        default='texto123',
                        help="Mensagem: string a ser manuseada.")

    parser.add_argument('-k', '--key', dest='key', type=str,
                        default='chave123',
                        help="Chave secreta: Tamanho 8(bytes).")

    parser.add_argument('-c', '--crib', dest='crib', type=str,
                        default=None,
                        help="Pedaço de texto conhecido.", )

    parser.add_argument('-dm', '--des-mode', dest='dm', type=str,
                        default='ecb',
                        help="Modo de operação DES (ecb, cbc).")

    return vars(parser.parse_args())


def test(key, msg, des_mode):
    print("[*] TESTE BASE: Usando configs padrao....\n")
    chipher_msg = encrypt(key=key, plain_msg=msg, des_mode=des_mode)
    # DEBUG
    print("[*] CRIPTOGRAFANDO...")
    print(f"[*] Usando chave: {configs['key']}")
    print(f"[*] Mensagem original: {configs['msg']}")
    print(f"[*] Mensagem encryptada em bytes: {chipher_msg}")
    print(f"[*] Mensagem encryptada em hex: {chipher_msg.hex()}\n")

    plain_msg = decrypt(key=key, chipher_msg=chipher_msg, des_mode=des_mode)
    # DEBUG
    print("[*] DESCRIPTOGRAFANDO...")
    print(f"[*] Usando chave: {configs['key']}")
    print(f"[*] Mensagem decryptada em bytes: {plain_msg}")
    print(f"[*] Mensagem decryptada em hex: {plain_msg.hex()}")
    print(f"[*] Mensagem original: {plain_msg.decode()}\n")


if __name__ == '__main__':
    show_banner()
    configs = make_configs()

    match configs['opt']:
        case 0: test(key=bytes(configs['key'], 'utf-8'), msg=bytes(configs['msg'], 'utf-8'), des_mode=set_des_mode(configs['dm']))           
        case 1: 
            chipher_msg = encrypt(key=bytes(configs['key'], 'utf-8'), plain_msg=bytes(configs['msg'], 'utf-8'), des_mode=set_des_mode(configs['dm']))
            print("[*] CRIPTOGRAFANDO...")
            print(f"[*] Usando chave: {configs['key']}")
            print(f"[*] Mensagem original: {configs['msg']}")
            print(f"[*] Mensagem encryptada em bytes: {chipher_msg}")
            print(f"[*] Mensagem encryptada em hex: {chipher_msg.hex()}\n")
        case 2: 
            plain_msg = decrypt(key=bytes(configs['key'], 'utf-8'), chipher_msg=bytes(configs['msg'], 'utf-8'), des_mode=set_des_mode(configs['dm']))
            print("[*] DESCRIPTOGRAFANDO...")
            print(f"[*] Usando chave: {configs['key']}")
            print(f"[*] Mensagem decryptada em bytes: {plain_msg}")
            print(f"[*] Mensagem decryptada em hex: {plain_msg.hex()}")
            print(f"[*] Mensagem original: {plain_msg.decode()}\n")
        case 3: brute_force(chipher_msg=bytes(configs['msg'], 'utf-8'), crib=configs['crib'])
