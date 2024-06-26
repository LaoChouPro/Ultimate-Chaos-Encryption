# Ultimate-Chaos-Encryption
- This is a python-based super encryption algorithm that combines Tent model, Logistic model and S-BOX. UI is developed based on PyQt5.
- 这是一个基于python的超级加密算法，结合了主流的S-BOX，和两种混沌数学模型 - Tent和Logistic。 UI基于PyQt5开发。

-------------------------- Ch Version ---------------------------

## 主要加密解密流程
1. 我使用了两个密钥，key1和key2，然后将它们使用 PBKDF2-HMAC-SHA256 函数生成基于它们SHA256值的参数 x0 和 mu，这两个参数将用于生成混沌序列。
2. 这两个参数将被分别使用在Tent map 和Logistic map中，将它们的结果结合出一个混沌序列，它是基于密钥生成的，具有唯一性。
3. 通过迭代生成期望长度的混沌序列。
4. 使用预设的S-BOX来对被加密数据进行替换，用于增强加密过程的非线性。
5. 使用密钥来影响数据：
  - 将 key1 和 key2 转换为字节数组，并进行扩展以匹配混沌序列的长度；
  - 计算两个密钥字节数组的模 256 之和，生成一个组合的密钥字节数组；
  - 将组合的密钥字节数组重复扩展以匹配混沌序列的长度；
  - 混沌序列与组合的密钥字节数组进行结合和 S-Box 替换，生成影响后的混沌序列。
6. 加密数据
  - 对数据进行异或操作，将影响后的混沌序列与明文数据进行逐字节异或，生成密文。
  - 使用 PBKDF2-HMAC-SHA256 函数和 key2 生成 HMAC 密钥。
  - 生成一个随机的初始化向量 (IV) 并计算 HMAC 校验码，用于验证数据完整性。
  - 将 IV、密文和 HMAC 校验码组合在一起，编码为 Base64 格式的最终密文。

## 关键函数
1. 参数派生: derive_parameters(key1, key2)
2. 混沌序列生成: generate_chaotic_sequence(length, x0, mu)
3. S-Box 替换: apply_s_box(byte)
4. 密钥影响: key_influence(sequence, key1, key2)
5. 数据加密: encrypt_round(data, key1, key2)
6. 加密过程: encrypt(plaintext, key1, key2, rounds, progress_callback)
7. 解密过程: decrypt(ciphertext, key1, key2, rounds, progress_callback)

-------------------------- En Version ---------------------------

## Main Encryption and Decryption Process

1. I used two keys, key1 and key2, and then utilized the PBKDF2-HMAC-SHA256 function to generate parameters x0 and mu based on their SHA256 values. These parameters will be used to generate the chaotic sequence.
2. These two parameters will be used respectively in the Tent map and Logistic map, combining their results to form a chaotic sequence, which is unique and based on the keys.
3. The desired length of the chaotic sequence is generated through iteration.
4. A predefined S-BOX is used to substitute the data to be encrypted, enhancing the non-linearity of the encryption process.
5. The keys are used to influence the data:
   - Convert key1 and key2 to byte arrays and expand them to match the length of the chaotic sequence;
   - Compute the sum of the two key byte arrays modulo 256 to generate a combined key byte array;
   - Repeat the combined key byte array to match the length of the chaotic sequence;
   - Combine the chaotic sequence with the combined key byte array and apply the S-Box substitution to generate the influenced chaotic sequence.
6. Encrypt the data:
   - Perform an XOR operation on the data, using the influenced chaotic sequence to XOR with the plaintext data byte by byte, generating the ciphertext.
   - Use the PBKDF2-HMAC-SHA256 function and key2 to generate an HMAC key.
   - Generate a random initialization vector (IV) and compute the HMAC digest for data integrity verification.
   - Combine the IV, ciphertext, and HMAC digest, then encode the result in Base64 format to produce the final ciphertext.

## Key Functions

1. Parameter Derivation: derive_parameters(key1, key2)
2. Chaotic Sequence Generation: generate_chaotic_sequence(length, x0, mu)
3. S-Box Substitution: apply_s_box(byte)
4. Key Influence: key_influence(sequence, key1, key2)
5. Data Encryption: encrypt_round(data, key1, key2)
6. Encryption Process: encrypt(plaintext, key1, key2, rounds, progress_callback)
7. Decryption Process: decrypt(ciphertext, key1, key2, rounds, progress_callback)
