import copy

class AES:
    def __init__(self, password, key):
        self.key = key
        self.password = password

        self.s_box = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        )

        self.galois_field = [
            [2, 3, 1, 1],
            [1, 2, 3, 1],
            [1, 2, 2, 3],
            [1, 1, 3, 2]
        ]

        self.encode()

    def encode(self):
        # Cria a matrix da senha e da chave
        self.password_matrix = self.make_matrix(password)
        self.key_matrix = self.make_matrix(key)
        # Transforma matrix em base 16
        self.password_matrix = self.matrix_to_base_16(self.password_matrix)
        self.key_matrix = self.matrix_to_base_16(self.key_matrix)

        self.shift_rows(self.password_matrix)
        # Testando mix columns conforme o vídeo

        sub_bytes = self.sub_bytes()
        self.mix_columns(sub_bytes)
        # print(self.mix_columns(sub_bytes))
        # print(self.password_matrix)
        # print(self.key_matrix)

        return

    def g_mul(self, a, b):
        p = 0
        cont = 0
        while cont < 8:  # 8 porque se trata de rodar 1 byte
            if (b & 1) != 0:  # Sempre que esbarrar com um bit 1 xor com a (sendo que a está sendo misturado)
                p ^= a  # simples xor de p com o valor de a
            hiBitSet = (a & 0x80) != 0  # Verificar se "a" vai passar do limite de 1 byte
            a <<= 1  # Aumenta a
            if hiBitSet:  # Se "a" for passar um byte
                a ^= 0x11B  # Faz xor com polinômio fixo (dizem que esse é um bom polinômio)
            # print(bin(a))

            b >>= 1  # Diminui um valor no bit de b para verificar o próximo bit
            # print(bin(b))
            cont += 1  # simples contador
        return p  # Retorna o valor de p que foi feito até 8 vezes xor com "a" sempre que b == 1, sendo que "a" aumenta até "a" completar 8 bits então, quando "a" completa 8 bits é reduzido assim: a xor 11b

    # -------- Incompleto
    def mix_columns(self, target_matrix):
        for row in range(4):
            galois_field_row = self.galois_field[row]
            current_row = target_matrix[row]

            for column in range(4):
                column_in_base_16 = int(current_row[column], 16)

                final_val = 0
                for x in range(len(galois_field_row)):
                    print(str(galois_field_row[x]) + ' * ' + str(column_in_base_16))
                    final_val ^= self.g_mul(galois_field_row[x], column_in_base_16)
                print(hex(final_val))
                break
        return target_matrix

    def shift_rows(self, target_matrix):
        matrix_with_shifted_rows = copy.deepcopy(target_matrix)

        # Desloca as colunas para esquerda <==
        for row in range(1, 4):
            current_row = matrix_with_shifted_rows[row]
            columns_to_shift_left = len(current_row) - row

            for column_to_shift_left in range(columns_to_shift_left):
                current_row[column_to_shift_left] = current_row[column_to_shift_left + row]

            # Desloca as colunas para direita ==>
            columns_to_shift_right = len(current_row) - column_to_shift_left
            for column_to_shift_right in range(1, columns_to_shift_right):
                current_row[column_to_shift_left + column_to_shift_right] = target_matrix[row][column_to_shift_right - 1]
    
        return

    def sub_bytes(self):
        message = [
            [0x19, 0xa0, 0x9a, 0xe9],
            [0x3d, 0xf4, 0xc6, 0xf8],
            [0xe3, 0xe2, 0x8d, 0x48],
            [0xbe, 0x2b, 0x2a, 0x08],
        ]

        for row in range(4):
            for char in range(4):
                current_char = message[row][char]
                hex_val = hex(current_char).replace('0x', '')

                if len(hex_val) == 1:
                    first = hex(0)
                    second = hex_val[0]
                else:
                    first = hex_val[0]
                    second = hex_val[1]

                first_pos = self.search_x(int(first, 16))
                second_pos = self.search_y(int(second, 16))
                message[row][char] = hex(self.s_box[first_pos + second_pos])

        return message

    def search_x(self, search_hex):
        position_hex = 0
        cont = 0
        while position_hex <= 256:
            if cont == search_hex:
                break
            position_hex += 16
            cont += 1

        return position_hex

    
    def search_y(self, search_hex):
        position_hex = 0
        cont = 0
        while position_hex <= 16:
            if cont == search_hex:
                break
            position_hex += 1
            cont += 1

        return position_hex
    
    # Incompleto
    # def add_round_key(self):
    #     for row in range(4):
    #         for char in range(4):
    #             self.round_key = self.password_matrix[row][char] ^ self.key_matrix[row][char]

        # return

    def matrix_to_base_16(self, target_matrix, return_hex = False):

        for row in range(4):
            if return_hex:
                for char in range(4):
                    target_matrix[row][char] = hex(self.str_to_base_16(target_matrix[row][char]))
            else:
                for char in range(4):
                    target_matrix[row][char] = self.str_to_base_16(target_matrix[row][char])

        return target_matrix


    def str_to_base_16(self, string):
        string = string.encode('utf-8')

        return int(string.hex(), 16)

    def make_matrix(self, string):
        matrix = []
        column = 0

        while len(string) < 16:
            string += ' '

        for x in range(4):
            row = []
            while column < len(string):
                row.append(string[column])
                column += 1
                if (column % 4 == 0):
                    break
            matrix.append(row)
        return matrix

    def xor(self, str_1: int, str_2: int):
        xor = str_1 ^ str_2

        return xor

password = 'eu sou eduardo'        
key = 'keys are boring1'

aes = AES(password, key)
# Xor em prática funcionando
# print(hex(0x04 ^ 0xa0))
