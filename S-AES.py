import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import numpy as np
from typing import List, Tuple, Dict
import itertools

class SAES:
    def __init__(self):
        # S盒和逆S盒
        self.S_BOX = [
            [0x9, 0x4, 0xA, 0xB],
            [0xD, 0x1, 0x8, 0x5],
            [0x6, 0x2, 0x0, 0x3],
            [0xC, 0xE, 0xF, 0x7]
        ]

        self.INV_S_BOX = [
            [0xA, 0x5, 0x9, 0xB],
            [0x1, 0x7, 0x8, 0xF],
            [0x6, 0x0, 0x2, 0x3],
            [0xC, 0x4, 0xD, 0xE]
        ]

        # 列混淆矩阵和逆矩阵
        self.MIX_MATRIX = [[1, 4], [4, 1]]
        self.INV_MIX_MATRIX = [[9, 2], [2, 9]]

        # RCON常数
        self.RCON = [0x80, 0x30]

    def gf_mult(self, a: int, b: int) -> int:
        """在GF(2^4)上的乘法"""
        result = 0
        for _ in range(4):
            if b & 1:
                result ^= a
            hi_bit_set = a & 0x8
            a <<= 1
            a &= 0xF
            if hi_bit_set:
                a ^= 0x3
            b >>= 1
        return result

    def sub_nibbles(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """半字节替换"""
        s_box = self.INV_S_BOX if inverse else self.S_BOX
        new_state = [[0, 0], [0, 0]]
        for i in range(2):
            for j in range(2):
                nibble = state[i][j]
                row = (nibble >> 2) & 0x3
                col = nibble & 0x3
                new_state[i][j] = s_box[row][col]
        return new_state

    def shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """行移位"""
        return [[state[0][0], state[0][1]],
                [state[1][1], state[1][0]]]

    def inv_shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """逆行移位"""
        return self.shift_rows(state)

    def mix_columns(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """列混淆"""
        matrix = self.INV_MIX_MATRIX if inverse else self.MIX_MATRIX
        new_state = [[0, 0], [0, 0]]

        for i in range(2):
            for j in range(2):
                for k in range(2):
                    new_state[i][j] ^= self.gf_mult(matrix[i][k], state[k][j])
                new_state[i][j] &= 0xF
        return new_state

    def key_expansion(self, key: int) -> List[int]:
        """密钥扩展"""
        # 将16位密钥分成两个8位字
        w0 = (key >> 8) & 0xFF
        w1 = key & 0xFF

        def g(word: int, rcon: int) -> int:
            # 循环左移4位
            rotated = ((word & 0xF) << 4) | ((word >> 4) & 0xF)
            # 半字节替换
            subbed = 0
            for i in range(2):
                nibble = (rotated >> (4 * (1 - i))) & 0xF
                row = (nibble >> 2) & 0x3
                col = nibble & 0x3
                sub_nibble = self.S_BOX[row][col]
                subbed |= (sub_nibble << (4 * (1 - i)))
            return subbed ^ rcon

        w2 = w0 ^ g(w1, self.RCON[0])
        w3 = w2 ^ w1
        w4 = w2 ^ g(w3, self.RCON[1])
        w5 = w4 ^ w3

        # 组合成轮密钥
        k0 = (w0 << 8) | w1
        k1 = (w2 << 8) | w3
        k2 = (w4 << 8) | w5

        return [k0, k1, k2]

    def add_round_key(self, state: List[List[int]], key: int) -> List[List[int]]:
        """轮密钥加"""
        new_state = [[0, 0], [0, 0]]
        key_nibbles = []

        # 将16位密钥转换为4个半字节
        for i in range(4):
            nibble = (key >> (12 - 4 * i)) & 0xF
            key_nibbles.append(nibble)

        key_matrix = [[key_nibbles[0], key_nibbles[1]],
                     [key_nibbles[2], key_nibbles[3]]]

        for i in range(2):
            for j in range(2):
                new_state[i][j] = state[i][j] ^ key_matrix[i][j]

        return new_state

    def int_to_state(self, value: int) -> List[List[int]]:
        """将16位整数转换为状态矩阵"""
        nibbles = []
        for i in range(4):
            nibble = (value >> (12 - 4 * i)) & 0xF
            nibbles.append(nibble)
        return [[nibbles[0], nibbles[1]], [nibbles[2], nibbles[3]]]

    def state_to_int(self, state: List[List[int]]) -> int:
        """将状态矩阵转换为16位整数"""
        value = 0
        value |= (state[0][0] << 12)
        value |= (state[0][1] << 8)
        value |= (state[1][0] << 4)
        value |= state[1][1]
        return value

    def encrypt(self, plaintext: int, key: int) -> int:
        """加密16位数据"""
        round_keys = self.key_expansion(key)
        state = self.int_to_state(plaintext)

        # 第0轮
        state = self.add_round_key(state, round_keys[0])

        # 第1轮
        state = self.sub_nibbles(state)
        state = self.shift_rows(state)
        state = self.mix_columns(state)
        state = self.add_round_key(state, round_keys[1])

        # 第2轮
        state = self.sub_nibbles(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, round_keys[2])

        return self.state_to_int(state)

    def decrypt(self, ciphertext: int, key: int) -> int:
        """解密16位数据"""
        round_keys = self.key_expansion(key)
        state = self.int_to_state(ciphertext)

        # 第2轮逆
        state = self.add_round_key(state, round_keys[2])
        state = self.inv_shift_rows(state)
        state = self.sub_nibbles(state, inverse=True)

        # 第1轮逆
        state = self.add_round_key(state, round_keys[1])
        state = self.mix_columns(state, inverse=True)
        state = self.inv_shift_rows(state)
        state = self.sub_nibbles(state, inverse=True)

        # 第0轮逆
        state = self.add_round_key(state, round_keys[0])

        return self.state_to_int(state)

    def ascii_encrypt(self, text: str, key: int) -> str:
        """ASCII字符串加密"""
        result = []
        # 填充文本使其长度为偶数
        if len(text) % 2 != 0:
            text += ' '

        for i in range(0, len(text), 2):
            # 将两个字符组合成16位数据
            block = (ord(text[i]) << 8) | ord(text[i + 1])
            encrypted = self.encrypt(block, key)
            # 将加密结果拆分成两个字符
            result.append(chr((encrypted >> 8) & 0xFF))
            result.append(chr(encrypted & 0xFF))

        return ''.join(result)

    def ascii_decrypt(self, text: str, key: int) -> str:
        """ASCII字符串解密"""
        result = []

        for i in range(0, len(text), 2):
            # 将两个字符组合成16位数据
            block = (ord(text[i]) << 8) | ord(text[i + 1])
            decrypted = self.decrypt(block, key)
            # 将解密结果拆分成两个字符
            result.append(chr((decrypted >> 8) & 0xFF))
            result.append(chr(decrypted & 0xFF))

        return ''.join(result).rstrip()

    def double_encrypt(self, plaintext: int, key: int) -> int:
        """双重加密"""
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        return self.encrypt(self.encrypt(plaintext, k1), k2)

    def double_decrypt(self, ciphertext: int, key: int) -> int:
        """双重解密"""
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        return self.decrypt(self.decrypt(ciphertext, k2), k1)

    def triple_encrypt_32bit(self, plaintext: int, key: int) -> int:
        """三重加密（32位密钥）"""
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        return self.encrypt(self.decrypt(self.encrypt(plaintext, k1), k2), k1)

    def triple_decrypt_32bit(self, ciphertext: int, key: int) -> int:
        """三重解密（32位密钥）"""
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        return self.decrypt(self.encrypt(self.decrypt(ciphertext, k1), k2), k1)

    def triple_encrypt_48bit(self, plaintext: int, key: int) -> int:
        """三重加密（48位密钥）"""
        k1 = (key >> 32) & 0xFFFF
        k2 = (key >> 16) & 0xFFFF
        k3 = key & 0xFFFF
        return self.encrypt(self.decrypt(self.encrypt(plaintext, k1), k2), k3)

    def triple_decrypt_48bit(self, ciphertext: int, key: int) -> int:
        """三重解密（48位密钥）"""
        k1 = (key >> 32) & 0xFFFF
        k2 = (key >> 16) & 0xFFFF
        k3 = key & 0xFFFF
        return self.decrypt(self.encrypt(self.decrypt(ciphertext, k3), k2), k1)

    def cbc_encrypt(self, plaintext: str, key: int, iv: int) -> List[int]:
        """CBC模式加密"""
        blocks = []
        # 填充文本使其长度为偶数
        if len(plaintext) % 2 != 0:
            plaintext += ' '

        previous = iv
        for i in range(0, len(plaintext), 2):
            # 将两个字符组合成16位数据
            block = (ord(plaintext[i]) << 8) | ord(plaintext[i + 1])
            # XOR with previous ciphertext
            block ^= previous
            encrypted = self.encrypt(block, key)
            blocks.append(encrypted)
            previous = encrypted

        return blocks

    def cbc_decrypt(self, ciphertext_blocks: List[int], key: int, iv: int) -> str:
        """CBC模式解密"""
        result = []
        previous = iv

        for block in ciphertext_blocks:
            decrypted = self.decrypt(block, key)
            # XOR with previous ciphertext
            plaintext_block = decrypted ^ previous
            result.append(chr((plaintext_block >> 8) & 0xFF))
            result.append(chr(plaintext_block & 0xFF))
            previous = block

        return ''.join(result).rstrip()

    def meet_in_the_middle_attack(self, plaintext: int, ciphertext: int, max_keys: int = 1000) -> List[Tuple[int, int]]:
        """
        中间相遇攻击
        找到可能的密钥对(K1, K2)使得 E_K2(E_K1(plaintext)) = ciphertext
        """
        print("开始中间相遇攻击...")

        # 存储所有可能的中间值
        intermediate_values = {}
        possible_keys = []

        # 第一阶段：从明文开始加密，存储所有可能的中间值
        print("第一阶段：正向加密...")
        for k1 in range(65536):  # 遍历所有16位密钥
            if k1 % 10000 == 0:
                print(f"处理进度: {k1}/65536")

            intermediate = self.encrypt(plaintext, k1)
            if intermediate not in intermediate_values:
                intermediate_values[intermediate] = []
            intermediate_values[intermediate].append(k1)

            if len(intermediate_values) > 1000000:  # 内存限制
                break

        print(f"生成 {len(intermediate_values)} 个中间值")

        # 第二阶段：从密文开始解密，查找匹配的中间值
        print("第二阶段：反向解密...")
        matches_found = 0
        for k2 in range(65536):
            if k2 % 10000 == 0:
                print(f"处理进度: {k2}/65536")

            intermediate = self.decrypt(ciphertext, k2)
            if intermediate in intermediate_values:
                for k1 in intermediate_values[intermediate]:
                    possible_keys.append((k1, k2))
                    matches_found += 1
                    if matches_found >= max_keys:
                        print(f"找到 {matches_found} 个可能的密钥对，达到上限")
                        return possible_keys

        print(f"攻击完成，找到 {len(possible_keys)} 个可能的密钥对")
        return possible_keys

    def optimized_meet_in_the_middle(self, plaintexts: List[int], ciphertexts: List[int],
                                   max_keys: int = 100) -> List[Tuple[int, int]]:
        """
        优化的中间相遇攻击，使用多个明密文对
        """
        if len(plaintexts) != len(ciphertexts):
            raise ValueError("明密文对数量不匹配")

        print(f"开始优化的中间相遇攻击，使用 {len(plaintexts)} 个明密文对...")

        # 第一阶段：为第一个明密文对构建中间值表
        intermediate_tables = []

        for pair_idx in range(len(plaintexts)):
            intermediate_values = {}
            plaintext = plaintexts[pair_idx]

            print(f"构建中间值表 {pair_idx + 1}/{len(plaintexts)}...")
            for k1 in range(65536):
                if k1 % 20000 == 0:
                    print(f"  进度: {k1}/65536")

                intermediate = self.encrypt(plaintext, k1)
                if intermediate not in intermediate_values:
                    intermediate_values[intermediate] = []
                intermediate_values[intermediate].append(k1)

            intermediate_tables.append(intermediate_values)

        # 第二阶段：查找在所有明密文对中都有效的密钥
        print("查找有效密钥对...")
        possible_keys = []

        # 使用第一个表作为基础
        base_table = intermediate_tables[0]
        ciphertext = ciphertexts[0]

        tested_keys = 0
        for k2 in range(65536):
            if tested_keys >= 10000 and len(possible_keys) >= max_keys:
                break

            if k2 % 5000 == 0:
                print(f"测试K2进度: {k2}/65536, 找到 {len(possible_keys)} 个密钥对")

            intermediate = self.decrypt(ciphertext, k2)
            if intermediate in base_table:
                for k1 in base_table[intermediate]:
                    # 验证这个密钥对是否对其他明密文对也有效
                    valid = True
                    for i in range(1, len(plaintexts)):
                        test_cipher = self.encrypt(self.encrypt(plaintexts[i], k1), k2)
                        if test_cipher != ciphertexts[i]:
                            valid = False
                            break

                    if valid:
                        possible_keys.append((k1, k2))
                        tested_keys += 1
                        if len(possible_keys) >= max_keys:
                            break

        print(f"攻击完成，找到 {len(possible_keys)} 个有效的密钥对")
        return possible_keys


class SAESGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES加密解密系统")
        self.root.geometry("900x750")

        self.saes = SAES()

        self.create_widgets()

    def create_widgets(self):
        # 创建选项卡
        notebook = ttk.Notebook(self.root)

        # 第1关：基本测试
        tab1 = ttk.Frame(notebook)
        self.create_basic_test_tab(tab1)

        # 第2关：交叉测试
        tab2 = ttk.Frame(notebook)
        self.create_cross_test_tab(tab2)

        # 第3关：扩展功能
        tab3 = ttk.Frame(notebook)
        self.create_extension_tab(tab3)

        # 第4关：多重加密
        tab4 = ttk.Frame(notebook)
        self.create_multiple_encryption_tab(tab4)

        # 第5关：工作模式
        tab5 = ttk.Frame(notebook)
        self.create_working_mode_tab(tab5)

        notebook.add(tab1, text="基本测试")
        notebook.add(tab2, text="交叉测试")
        notebook.add(tab3, text="扩展功能")
        notebook.add(tab4, text="多重加密")
        notebook.add(tab5, text="工作模式")
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

    def create_basic_test_tab(self, parent):
        ttk.Label(parent, text="16位数据 (十六进制):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.data_entry = ttk.Entry(parent, width=20)
        self.data_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(parent, text="16位密钥 (十六进制):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.key_entry = ttk.Entry(parent, width=20)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(parent, text="加密", command=self.basic_encrypt).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(parent, text="解密", command=self.basic_decrypt).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(parent, text="结果:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.result_text = scrolledtext.ScrolledText(parent, width=60, height=10)
        self.result_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def create_cross_test_tab(self, parent):
        # 测试用例输入区域
        input_frame = ttk.LabelFrame(parent, text="测试用例输入")
        input_frame.grid(row=0, column=0, padx=5, pady=5, sticky='ew')

        ttk.Label(input_frame, text="测试用例1 - 明文:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.cross_plain1 = ttk.Entry(input_frame, width=10)
        self.cross_plain1.grid(row=0, column=1, padx=5, pady=2)
        self.cross_plain1.insert(0, "1234")

        ttk.Label(input_frame, text="密钥:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.cross_key1 = ttk.Entry(input_frame, width=10)
        self.cross_key1.grid(row=0, column=3, padx=5, pady=2)
        self.cross_key1.insert(0, "5678")

        ttk.Label(input_frame, text="测试用例2 - 明文:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.cross_plain2 = ttk.Entry(input_frame, width=10)
        self.cross_plain2.grid(row=1, column=1, padx=5, pady=2)
        self.cross_plain2.insert(0, "ABCD")

        ttk.Label(input_frame, text="密钥:").grid(row=1, column=2, padx=5, pady=2, sticky='w')
        self.cross_key2 = ttk.Entry(input_frame, width=10)
        self.cross_key2.grid(row=1, column=3, padx=5, pady=2)
        self.cross_key2.insert(0, "EF01")

        ttk.Button(input_frame, text="添加测试用例", command=self.add_test_case).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(input_frame, text="运行交叉测试", command=self.run_cross_test).grid(row=2, column=1, padx=5, pady=5)

        # 结果显示区域
        ttk.Label(parent, text="交叉测试结果:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.cross_test_text = scrolledtext.ScrolledText(parent, width=80, height=15)
        self.cross_test_text.grid(row=2, column=0, padx=5, pady=5)

        # 存储测试用例
        self.test_cases = []

    def create_extension_tab(self, parent):
        ttk.Label(parent, text="ASCII字符串:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.ascii_text = scrolledtext.ScrolledText(parent, width=50, height=5)
        self.ascii_text.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        ttk.Label(parent, text="16位密钥 (十六进制):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.ascii_key_entry = ttk.Entry(parent, width=20)
        self.ascii_key_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(parent, text="加密ASCII", command=self.ascii_encrypt).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(parent, text="解密ASCII", command=self.ascii_decrypt).grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(parent, text="结果:").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        self.ascii_result = scrolledtext.ScrolledText(parent, width=50, height=5)
        self.ascii_result.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    def create_multiple_encryption_tab(self, parent):
        notebook = ttk.Notebook(parent)

        # 双重加密
        double_tab = ttk.Frame(notebook)
        self.create_double_encryption_tab(double_tab)

        # 三重加密
        triple_tab = ttk.Frame(notebook)
        self.create_triple_encryption_tab(triple_tab)

        # 中间相遇攻击
        meet_middle_tab = ttk.Frame(notebook)
        self.create_meet_middle_tab(meet_middle_tab)

        notebook.add(double_tab, text="双重加密")
        notebook.add(triple_tab, text="三重加密")
        notebook.add(meet_middle_tab, text="中间相遇攻击")
        notebook.pack(expand=True, fill='both')

    def create_double_encryption_tab(self, parent):
        ttk.Label(parent, text="16位数据 (十六进制):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.double_data = ttk.Entry(parent, width=20)
        self.double_data.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(parent, text="32位密钥 (十六进制):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.double_key = ttk.Entry(parent, width=20)
        self.double_key.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(parent, text="双重加密", command=self.double_encrypt).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(parent, text="双重解密", command=self.double_decrypt).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(parent, text="结果:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.double_result = scrolledtext.ScrolledText(parent, width=50, height=5)
        self.double_result.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def create_triple_encryption_tab(self, parent):
        ttk.Label(parent, text="16位数据 (十六进制):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.triple_data = ttk.Entry(parent, width=20)
        self.triple_data.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(parent, text="密钥 (十六进制):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.triple_key = ttk.Entry(parent, width=20)
        self.triple_key.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(parent, text="三重加密(32位)", command=self.triple_encrypt_32).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(parent, text="三重解密(32位)", command=self.triple_decrypt_32).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(parent, text="三重加密(48位)", command=self.triple_encrypt_48).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(parent, text="三重解密(48位)", command=self.triple_decrypt_48).grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(parent, text="结果:").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        self.triple_result = scrolledtext.ScrolledText(parent, width=50, height=5)
        self.triple_result.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    def create_meet_middle_tab(self, parent):
        ttk.Label(parent, text="中间相遇攻击 - 双重加密破解", font=('Arial', 10, 'bold')).grid(row=0, column=0, columnspan=2, padx=5, pady=5)

        # 明密文对输入
        ttk.Label(parent, text="已知明密文对1:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        ttk.Label(parent, text="明文:").grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.mm_plain1 = ttk.Entry(parent, width=10)
        self.mm_plain1.grid(row=2, column=1, padx=5, pady=2)
        self.mm_plain1.insert(0, "1234")

        ttk.Label(parent, text="密文:").grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.mm_cipher1 = ttk.Entry(parent, width=10)
        self.mm_cipher1.grid(row=3, column=1, padx=5, pady=2)
        self.mm_cipher1.insert(0, "AABB")

        ttk.Label(parent, text="已知明密文对2:").grid(row=4, column=0, padx=5, pady=2, sticky='w')
        ttk.Label(parent, text="明文:").grid(row=5, column=0, padx=5, pady=2, sticky='w')
        self.mm_plain2 = ttk.Entry(parent, width=10)
        self.mm_plain2.grid(row=5, column=1, padx=5, pady=2)
        self.mm_plain2.insert(0, "5678")

        ttk.Label(parent, text="密文:").grid(row=6, column=0, padx=5, pady=2, sticky='w')
        self.mm_cipher2 = ttk.Entry(parent, width=10)
        self.mm_cipher2.grid(row=6, column=1, padx=5, pady=2)
        self.mm_cipher2.insert(0, "CCDD")

        ttk.Button(parent, text="执行中间相遇攻击", command=self.run_meet_middle).grid(row=7, column=0, columnspan=2, padx=5, pady=10)

        ttk.Label(parent, text="攻击结果:").grid(row=8, column=0, padx=5, pady=5, sticky='w')
        self.meet_middle_result = scrolledtext.ScrolledText(parent, width=70, height=10)
        self.meet_middle_result.grid(row=9, column=0, columnspan=2, padx=5, pady=5)

    def create_working_mode_tab(self, parent):
        ttk.Label(parent, text="明文:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.cbc_plaintext = scrolledtext.ScrolledText(parent, width=50, height=5)
        self.cbc_plaintext.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        ttk.Label(parent, text="16位密钥 (十六进制):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.cbc_key = ttk.Entry(parent, width=20)
        self.cbc_key.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(parent, text="初始向量IV (十六进制):").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.cbc_iv = ttk.Entry(parent, width=20)
        self.cbc_iv.grid(row=3, column=1, padx=5, pady=5)

        ttk.Button(parent, text="CBC加密", command=self.cbc_encrypt).grid(row=4, column=0, padx=5, pady=5)
        ttk.Button(parent, text="CBC解密", command=self.cbc_decrypt).grid(row=4, column=1, padx=5, pady=5)

        ttk.Label(parent, text="结果:").grid(row=5, column=0, padx=5, pady=5, sticky='w')
        self.cbc_result = scrolledtext.ScrolledText(parent, width=50, height=5)
        self.cbc_result.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

    def add_test_case(self):
        """添加测试用例"""
        if len(self.test_cases) < 4:  # 限制测试用例数量
            plain1 = self.cross_plain1.get()
            key1 = self.cross_key1.get()
            plain2 = self.cross_plain2.get()
            key2 = self.cross_key2.get()

            if plain1 and key1:
                self.test_cases.append((int(plain1, 16), int(key1, 16)))
            if plain2 and key2:
                self.test_cases.append((int(plain2, 16), int(key2, 16)))

            messagebox.showinfo("成功", f"已添加测试用例，当前共有 {len(self.test_cases)} 个测试用例")
        else:
            messagebox.showwarning("警告", "测试用例数量已达上限")

    def run_cross_test(self):
        """运行交叉测试"""
        if not self.test_cases:
            messagebox.showwarning("警告", "请先添加测试用例")
            return

        result = "交叉测试结果:\n\n"
        all_passed = True

        for i, (data, key) in enumerate(self.test_cases):
            encrypted = self.saes.encrypt(data, key)
            decrypted = self.saes.decrypt(encrypted, key)
            status = "通过" if data == decrypted else "失败"

            if status == "失败":
                all_passed = False

            result += f"测试用例 {i+1}:\n"
            result += f"  明文: {hex(data)}\n"
            result += f"  密钥: {hex(key)}\n"
            result += f"  密文: {hex(encrypted)}\n"
            result += f"  解密: {hex(decrypted)}\n"
            result += f"  状态: {status}\n\n"

        result += f"总体结果: {'所有测试通过' if all_passed else '部分测试失败'}"

        self.cross_test_text.delete(1.0, tk.END)
        self.cross_test_text.insert(tk.END, result)

    def run_meet_middle(self):
        """执行中间相遇攻击"""
        try:
            # 获取明密文对
            plain1 = int(self.mm_plain1.get(), 16)
            cipher1 = int(self.mm_cipher1.get(), 16)
            plain2 = int(self.mm_plain2.get(), 16)
            cipher2 = int(self.mm_cipher2.get(), 16)

            self.meet_middle_result.delete(1.0, tk.END)
            self.meet_middle_result.insert(tk.END, "开始中间相遇攻击...\n")
            self.meet_middle_result.update()

            # 使用优化的中间相遇攻击
            possible_keys = self.saes.optimized_meet_in_the_middle(
                [plain1, plain2], [cipher1, cipher2], max_keys=50
            )

            result = "中间相遇攻击完成！\n\n"
            result += f"使用明密文对:\n"
            result += f"  明文1: {hex(plain1)} -> 密文1: {hex(cipher1)}\n"
            result += f"  明文2: {hex(plain2)} -> 密文2: {hex(cipher2)}\n\n"
            result += f"找到 {len(possible_keys)} 个可能的密钥对:\n\n"

            for i, (k1, k2) in enumerate(possible_keys[:10]):  # 显示前10个
                full_key = (k1 << 16) | k2
                result += f"密钥对 {i+1}:\n"
                result += f"  K1 = {hex(k1)} ({k1})\n"
                result += f"  K2 = {hex(k2)} ({k2})\n"
                result += f"  完整密钥 = {hex(full_key)}\n"

                # 验证
                test_cipher1 = self.saes.double_encrypt(plain1, full_key)
                test_cipher2 = self.saes.double_encrypt(plain2, full_key)
                verified = (test_cipher1 == cipher1 and test_cipher2 == cipher2)
                result += f"  验证: {'通过' if verified else '失败'}\n\n"

            if len(possible_keys) > 10:
                result += f"... 还有 {len(possible_keys) - 10} 个密钥对未显示\n"

            self.meet_middle_result.delete(1.0, tk.END)
            self.meet_middle_result.insert(tk.END, result)

        except ValueError as e:
            messagebox.showerror("错误", "请输入有效的十六进制数")
        except Exception as e:
            messagebox.showerror("错误", f"攻击过程中发生错误: {str(e)}")

    # 其他方法保持不变（basic_encrypt, basic_decrypt, ascii_encrypt, ascii_decrypt等）
    def basic_encrypt(self):
        try:
            data = int(self.data_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            result = self.saes.encrypt(data, key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"明文: {hex(data)}\n密钥: {hex(key)}\n密文: {hex(result)}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def basic_decrypt(self):
        try:
            data = int(self.data_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            result = self.saes.decrypt(data, key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"密文: {hex(data)}\n密钥: {hex(key)}\n明文: {hex(result)}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def ascii_encrypt(self):
        try:
            text = self.ascii_text.get(1.0, tk.END).strip()
            key = int(self.ascii_key_entry.get(), 16)
            result = self.saes.ascii_encrypt(text, key)
            self.ascii_result.delete(1.0, tk.END)
            self.ascii_result.insert(tk.END, f"原始文本: {text}\n加密结果: {result}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制密钥")

    def ascii_decrypt(self):
        try:
            text = self.ascii_text.get(1.0, tk.END).strip()
            key = int(self.ascii_key_entry.get(), 16)
            result = self.saes.ascii_decrypt(text, key)
            self.ascii_result.delete(1.0, tk.END)
            self.ascii_result.insert(tk.END, f"加密文本: {text}\n解密结果: {result}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制密钥")

    def double_encrypt(self):
        try:
            data = int(self.double_data.get(), 16)
            key = int(self.double_key.get(), 16)
            result = self.saes.double_encrypt(data, key)
            self.double_result.delete(1.0, tk.END)
            self.double_result.insert(tk.END, f"明文: {hex(data)}\n密钥: {hex(key)}\n双重加密结果: {hex(result)}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def double_decrypt(self):
        try:
            data = int(self.double_data.get(), 16)
            key = int(self.double_key.get(), 16)
            result = self.saes.double_decrypt(data, key)
            self.double_result.delete(1.0, tk.END)
            self.double_result.insert(tk.END, f"密文: {hex(data)}\n密钥: {hex(key)}\n双重解密结果: {hex(result)}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def triple_encrypt_32(self):
        try:
            data = int(self.triple_data.get(), 16)
            key = int(self.triple_key.get(), 16)
            result = self.saes.triple_encrypt_32bit(data, key)
            self.triple_result.delete(1.0, tk.END)
            self.triple_result.insert(tk.END, f"明文: {hex(data)}\n密钥: {hex(key)}\n三重加密结果(32位): {hex(result)}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def triple_decrypt_32(self):
        try:
            data = int(self.triple_data.get(), 16)
            key = int(self.triple_key.get(), 16)
            result = self.saes.triple_decrypt_32bit(data, key)
            self.triple_result.delete(1.0, tk.END)
            self.triple_result.insert(tk.END, f"密文: {hex(data)}\n密钥: {hex(key)}\n三重解密结果(32位): {hex(result)}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def triple_encrypt_48(self):
        try:
            data = int(self.triple_data.get(), 16)
            key = int(self.triple_key.get(), 16)
            result = self.saes.triple_encrypt_48bit(data, key)
            self.triple_result.delete(1.0, tk.END)
            self.triple_result.insert(tk.END, f"明文: {hex(data)}\n密钥: {hex(key)}\n三重加密结果(48位): {hex(result)}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def triple_decrypt_48(self):
        try:
            data = int(self.triple_data.get(), 16)
            key = int(self.triple_key.get(), 16)
            result = self.saes.triple_decrypt_48bit(data, key)
            self.triple_result.delete(1.0, tk.END)
            self.triple_result.insert(tk.END, f"密文: {hex(data)}\n密钥: {hex(key)}\n三重解密结果(48位): {hex(result)}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def cbc_encrypt(self):
        try:
            text = self.cbc_plaintext.get(1.0, tk.END).strip()
            key = int(self.cbc_key.get(), 16)
            iv = int(self.cbc_iv.get(), 16)
            result = self.saes.cbc_encrypt(text, key, iv)
            self.cbc_result.delete(1.0, tk.END)
            self.cbc_result.insert(tk.END, f"明文: {text}\n密文块: {[hex(x) for x in result]}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def cbc_decrypt(self):
        try:
            text = self.cbc_plaintext.get(1.0, tk.END).strip()
            key = int(self.cbc_key.get(), 16)
            iv = int(self.cbc_iv.get(), 16)
            encrypted = self.saes.cbc_encrypt(text, key, iv)
            result = self.saes.cbc_decrypt(encrypted, key, iv)
            self.cbc_result.delete(1.0, tk.END)
            self.cbc_result.insert(tk.END, f"密文块: {[hex(x) for x in encrypted]}\n解密结果: {result}")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")


def main():
    root = tk.Tk()
    app = SAESGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()