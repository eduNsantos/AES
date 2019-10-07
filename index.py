import random
import binascii

# Caracteres para gerar a chave 128 bits
hex_chars = '0123456789'
hex_chars += 'abcdef'

def str_to_bin(val):
    hex_password = bytes(val, 'ascii')
    hex_password = binascii.hexlify(hex_password)
    hex_password = int(hex_password, 16)
    hex_password = bin(hex_password)

    return hex_password

def bin_to_hex(val):
    hex_password = binascii.unhexlify(val)

    return hex_password

def generate_key():
    key = []
    # Número de linhas para gerar a cifra
    for row in range(4):
        # Cria uma lista vazia para guardar o hexadecimal
        new_hex = []
        # Número de colunas para gerar cifra
        for column in range(4):
            # Seta o novo valor da posição atual da cifra como vazio
            new_val = ''
            # Escolhe aleatoriamente a chave hexadecimal
            for hex in range(2):
                new_val += random.choice(hex_chars)
            # Adiciona o hexadecimal escolhido na lista
            new_hex.append(new_val)
        # Adiciona o hexadecimal na la lista de cifra
        key.append(new_hex)
    return key

def str_to_matrix(str):
    matrix = []
    column = 0
    for x in range(4):
        row = []
        while column < len(phrase):
            row.append(str[column])
            column += 1
            if (column % 4 == 0):
                break
        matrix.append(row)
    return matrix

# is_valid = False

# while not is_valid:
#     password = input("Digite a senha deseja criptografar em AES:")

#     if len(password) < 8:
#         print('Digite no mínimo 8 caracteres!')
#     elif len(password) > 63:
#         print('Digite no máximo 63 caracteres!')
#     else:
#         is_valid = True

# password = generate_hex_password('Eduaraisod123')

phrase = 'buy me some potato chips please'
key = 'keys are boring1'


matrix_phrase = str_to_matrix(phrase) 
matrix_key = str_to_matrix(key)

for column in range(4):
    for letter in range(4):
        bin_phrase_letter = matrix_phrase[column][letter]
        bin_key_letter = matrix_key[column][letter]

        bin_phrase_letter = str_to_bin(bin_phrase_letter)
        bin_key_letter = str_to_bin(bin_key_letter)

        # print(bin_phrase_letter)
a = str_to_bin('04')
print(a)
print(str(a, 'ascii'))
print(str_to_bin('a0'))
# teste = binascii.hexlify(bytes(teste, 'ascii'))
# teste = binascii.unhexlify(int(teste, 2))
# print(teste)