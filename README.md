# S-AES
重庆大学大数据与软件学院信息安全导论作业2：S-AES算法实现

### 1. 算法实现

> 我们的S-AES算法实现在`S-AES.py`文件中，其中可以使用到S-AES算法的加密和解密两个函数。 

为了实现良好的代码封装，我们定义了一个SAES的加密类。

- 初始化函数为：`def __init__(self, key,
                 S_BOX=None,
                 S_BOX_INV=None,
                 RCON=None,
                 MixMatrix=None,
                 MixMatrix_INV=None
                 ):`
  - 其中`key`为16整数倍长度的加密密钥key（后续会讨论整数倍key的多重加密处理）
  - `S_BOX`为S盒，`S_BOX_INV`为S盒的逆，`RCON`为轮常数，`MixMatrix`为Mix矩阵，`MixMatrix_INV`为Mix矩阵的逆。
  - 我们设计中将教材中的S盒、轮常数、Mix矩阵等参数设做默认值，方便用户使用，所以在实验中我们可以不传入这部分参数。
- 定义了：`def key_expansion(self, key: int) -> List[int]):`函数，用于密钥扩展。
- 定义了：`def add_round_key(self, state: List[List[int]], key: int) -> List[List[int]]:`用于轮密钥加，将密钥与状态矩阵进行异或操作。
- 定义了：`def sub_nibbles(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:`用于S盒转换，进行半字节替换操作。如果inverse=True，则使用逆S盒。
- 定义了：`def shift_rows(self, state: List[List[int]]) -> List[List[int]]:`用于行移位，将矩阵的每一行左移不同的位数。
- 定义了：`def inv_shift_rows(self, state: List[List[int]]) -> List[List[int]]:`用于逆行移位，反向操作。
- 定义了：`def mix_columns(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:`用于列混淆，将矩阵的列与Mix矩阵进行混淆处理。如果inverse=True，则使用逆Mix矩阵。
- 定义了：`def gf_mult(self, a: int, b: int) -> int:`用于GF(2^4)域内的乘法。
- 定义了：`def gf_add(self, a: int, b: int) -> int:`用于GF(2^4)域内的加法。
- 定义了：`def _single_encrypt(self, plaintext: int) -> int:`单轮加密函数，输入16位明文，输出16位密文。
- 定义了：`def _single_decrypt(self, ciphertext: int) -> int:`单轮解密函数，输入16位密文，输出16位明文。
- 定义了：`def encrypt(self, plaintext: int, key: int) -> int:`多轮加密函数，输入明文和密钥，输出密文。支持16位整数倍密钥。
- 定义了：`def decrypt(self, ciphertext: int, key: int) -> int:`多轮解密函数，输入密文和密钥，输出明文。支持16位整数倍密钥。
- 定义了：`def ascii_encrypt(self, text: str, key: int) -> str:`用于加密ASCII字符串，支持多轮加密。
- 定义了：`def ascii_decrypt(self, text: str, key: int) -> str:`用于解密ASCII字符串，支持多轮解密。
- 定义了：`def cbc_encrypt(self, plaintext: str, key: int, iv: int) -> List[int]:`用于CBC模式的加密，输入明文、密钥和初始化向量（IV），输出加密后的密文块。
- 定义了：`def cbc_decrypt(self, ciphertext_blocks: List[int], key: int, iv: int) -> str:`用于CBC模式的解密，输入密文块、密钥和初始化向量（IV），输出解密后的明文。

故在使用中我们可以直接实例化SAES类，生成一个加密对象。

```shell
saes = SAES(key=0x1234)
```

对于这个加密类调用`encrypt`和`decrypt`函数就可以进行加密和解密操作（包括单轮加密以及多轮加密）。

```shell
ciphertext = saes.encrypt(plaintext=0xABCD, key=0x1234)
decrypted_text = saes.decrypt(ciphertext=ciphertext, key=0x1234)
```
这样，通过封装后的加密类，我们能够方便地进行加密解密操作，同时支持多种加密模式和密钥长度。

