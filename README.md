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

### 2. GUI设计
> - 我们为了设计一个交互良好的界面，使用了`PyQt`框架进行GUI设计。
> - 我们的GUI设计中，主要分为四个页面，分别是`基本测试`、`扩展功能`、`暴力破解`、`封闭测试`。

### 3. 安装与运行

#### 3.1 环境要求
Python 3.6+

#### 3.2 安装依赖

```shell
pip install PyQt4
```

#### 3.3 运行项目

- 使用 PyQt 界面（推荐用于更好的用户体验）
```shell
python S-AES/AES.py
```

### 4. 编程和测试要求

#### 4.1 第1关：基本测试

> 根据S-AES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是8bit的数据和10bit的密钥，输出是8bit的密文。
> - 具体详细测试代码请看[task1测试文件夹](https://github.com/y-yyyt/S-AES/tree/main/test/task1)。

##### 4.1.1 GUI界面中测试

输入可以是8bit的数据和10bit的密钥，输出是8bit的密文：

![BITFunction](README.assets/BITFunction.gif)

当输出不符合标准时，返回处理失败的错误：

![FalseFunction](README.assets/FalseFunction.gif)

##### 4.1.2 测试代码中测试

我们在`/test/task1`文件夹中提供了jupyter notebook的测试代码，可以直接打开task1测试文件夹中的[task1.ipynb文件](https://github.com/y-yyyt/S-AES/tree/main/test/task1/task1.ipynb)，即可看到测试结果。

#### 4.2 第2关：交叉测试

> 考虑到是"算法标准"，所有人在编写程序的时候需要使用相同算法流程和转换单元(替换盒、列混淆矩阵等)，以保证算法和程序在异构的系统或平台上都可以正常运行。设有A和B两组位同学(选择相同的密钥K)；则A、B组同学编写的程序对明文P进行加密得到相同的密文C；或者B组同学接收到A组程序加密的密文C，使用B组程序进行解密可得到与A相同的P。
> - 具体详细测试代码请看[task2测试文件夹](https://github.com/y-yyyt/S-AES/tree/main/test/task2)。

我们在该轮测试中与两个小组进行了交叉测试，验证了我们加密算法的正确性。


我们在`/test/task2`文件夹中提供了与两个小组测试的jupyter notebook测试代码，可以直接打开task2测试文件夹中的[task2.ipynb文件](https://github.com/y-yyyt/S-AES/tree/main/test/task2/task2.ipynb)，即可看到测试结果。

#### 4.3 第3关：扩展功能

> 考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为1 Byte)，对应地输出也可以是ACII字符串(很可能是乱码)。
> - 具体详细测试代码请看[task3测试文件夹](https://github.com/y-yyyt/S-AES/tree/main/test/task3)。

##### 4.3.1 GUI界面中测试

处理ASCII输入：

![ASCFunction](README.assets/ASCFunction.gif)

当输入不符合标准时，返回处理失败的错误：

![FalseFunction](README.assets/FalseFunction.gif)

##### 4.3.2 测试代码中测试

我们在`/test/task3`文件夹中提供了jupyter notebook的测试代码，可以直接打开task3测试文件夹中的[task3.ipynb文件](https://github.com/y-yyyt/S-AES/tree/main/test/task3/task3.ipynb)，即可看到测试结果。

##### 4.3.3 ASCII码加密时的处理

因为我们常用的字符集仅仅只是0-127位的ASCII码，所以我们在加密时对应的只剩下了7位bit，这并不符合SAES算法的加密要求，我们综合考虑多种方式之后选择了更为全面的Unicode字符集，选取前256作为我们的字符集。

同时ASCII字符在加密后往往会出现乱码或者无法显示的控制符（但是不影响解密，只要正确复制后即可正常解密）。
所以我们在加密ASCII码是采用了显示十六进制的加密结果，而不是对应的Unicode字符，避免了很多无法显示的结果与乱码。
在对应的解密阶段我们也采用了十六进制的解密方式，将十六进制的密文转换为对应的ASCII码，这样就可以避免乱码的出现。

#### 4.4 第4关：多重加密

> 在实验的这一部分，我们探讨了多重加密的概念，并通过多次迭代的方法，使用不同的密钥对数据进行加密，从而提高加密的安全性。
> - 具体详细测试代码请看[task4测试文件夹](https://github.com/y-yyyt/S-AES/tree/main/test/task4)。

##### 4.4.1 双重加密
我们扩展了S-AES算法，实现了双重加密。尽管分组长度仍为16 bits，但我们通过两次加密的方式将理论密钥空间扩展到了32 bits的密钥长度，其中包含两个16 bits的子密钥。

在我们建立加密类SAES的过程中,已经实现了多重加密的功能，定义在类方法中

```python
# 将key分割为16位长的元素
self.keys_list = [key[i:i + 16] for i in range(0, len(key), 16)]
```
在encrypt函数中的多重加密循环如下
```python
# 对每一个密钥进行加密操作
    for key in self.keys_list:
        self.key = key
        ciphertext = self._single_encrypt(ciphertext)
```
所以双重加密只需输入32bits拼接key即可，即
```python
# 拼接的32bits key
double_key = '10110011100110101101111011001101'
double_saes = SAES(key=double_key)
double_encrypted_ciphertext = double_saes.encrypt('替换明文')
```
- 具体详细实现请查看[task4测试文件夹](https://github.com/Fy-yyyt/S-AES/tree/main/test/task4)


##### 4.4.2 中间相遇攻击
> 对双重加密而言，中间相遇攻击是相当致命的

模拟中间相遇攻击我们需要遍历所有可能的密钥，然后用每一个可能的密钥进行解密操作，检查解密后的结果是否是预期的明文即可。

值得一提的是当我们只拥有一个明密文对时,可能有上万个密钥满足情况。而当我们掌握了2~3个明密文对的时候就完全能够锁定密钥（当明密文对的结构太过于相似时会出现两对明密文无法解密出正确的key）。

就结果来看，我们可以通过jupyter中代码框的运行时间来看到，我们的中间相遇攻击算法的运行时间基本在秒级，大多在5s就可以完成破解，并给出全部的可能的key。

我们在`/test/task4`文件夹中提供了单组明密文对和多组明密文对的中间相遇攻击模拟数据，可以直接打开task4测试文件夹中的[task4.ipynb文件](https://github.com/y-yyyt/S-AES/tree/main/test/task4/task4.ipynb)，即可看到模拟结果。

##### 4.4.3 三重加密
> (1)按照32 bits密钥Key(K1+K2)的模式进行三重加密解密,
> 
> (2)使用48bits(K1+K2+K3)的模式进行三重加解密
> 
> 考虑到我们在设计加密类时就已经考虑到了多重加密的情况,为了保持代码的连贯性我们选择第二种的模式

加解密的调用方法如下
```python
triple_key= '101100111001101011011110110011011011101000100111'
triple_saes = SAES(key=triple_key)
triple_encrypted_ciphertext = triple_saes.encrypt('替换明文')
triple_decrypted_plaintext = triple_saes.decrypt(triple_encrypted_ciphertext)
```
经过我们的加解密测试，多重加密的实现确认完成。完整的测试和实现请查看[task4测试文件夹](https://github.com/y-yyyt/S-AES/tree/main/test/task4)
#### 4.5 第5关：工作模式

基于S-AES算法，我们使用密码分组链(CBC)模式对较长的明文消息进行加密。特别注意到初始向量(16 bits)的生成是必要的，并需要在加解密双方之间共享。

在CBC模式下，加密明文后尝试对密文分组进行替换或修改。解密后，比较篡改密文前后的结果，以观察篡改的影响。

##### 4.5.1 CBC工作模式的实现

在这一小节，我们选定了以下测试用例：

- 明文： "Hello S-AES and CBC!"
- 密钥： "1101001110100101"
- 初始向量 (IV)： "0101101000001111"

##### 4.5.2 采用CBC模式的加密过程

`cbc_encrypt` 函数接收用户的字符输入 `plaintext`，约定的 `key`，以及 `iv` 初始向量。

加密后得到的密文为：{ciphertext}

##### 4.5.3 对CBC模式的解密过程

`cbc_decrypt` 函数接收16进制字符串，约定的 `key` 以及 `iv` 初始向量。

解密后得到的明文为：{decrypted_text}

#### 4.5.4 篡改密文组结果分析

在加密过程中对密文块block1末位进行字节篡改,得到结果:

`(kllo S-AES and CBC!`

篡改效果符合预期: CBC密码分组链效果并不明显，仅在更改的块中有影响。

得出结论：在没有其他安全措施的情况下，加密过程中的篡改作用域为自身,CBC将会直接篡改而不引发其他影响。要保证密文快生成的连续性或类似汉明码的检查机制。

在加密完成后对密文分组进行篡改，得到被篡改的解密结果:

`(klmo S-AES and CBC!`

发现密文在形成后的篡改会引起后一个块的更改。得出结论：在没有其他安全措施的情况下，这种篡改会引起后一个block的解密失效。

这为判断篡改与否带来便利: 在重要的信息后增加一个确认block。者能够在一定程度上增加CBC工作模式的安全性。

#### 4.5.4 针对CBC的攻击

尽管这种加密模式很好地隐藏了明文的统计特性，但是同样也暴露出了一个很严重的缺点: 可以通过CBC的加密特点改变明文内容，但是这种改变并不会引起其它明文块对应位的改变。这种攻击常用来绕过过滤器，提权（比如从guest变为admin）等。

1. 字节反转攻击

在CBC模式下，每一个密文块的解密结果会与上一个密文块进行XOR操作，这使得我们可以通过修改前一个密文块来控制当前明文块的解密结果，而不会影响其他块的解密。

在猜测出明文分组Pn的情况下，那么可以通过修改密文分组

```markdown
Ci-1 = Ci-1 XOR Pn XOR A，
```

这样篡改解密Pn将得到A。详细内容请前往[task5.ipynb文件](https://github.com/y-yyyt/S-AES/tree/main/test/task5/task5.ipynb)查看

#### 4.5.5 结果分析

经过5.2的实例和5.3的分析，我们得出以下结论：

- 没有其他安全措施的CBC工作模式容易受到篡改攻击和字节替换攻击。
- 对于5.2的内容，我们进一步做了形式化的数学论证，证明了CBC模式下的密文块替换对解密过程的影响。

---
**至此，我们完成了全部S-AES加密算法的实现、GUI界面的设计，以及要求中提到的五个任务。较好的完成了本次实验。**
