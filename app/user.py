import os.path, pyzipper, psutil, base64, urllib.request, json, sys
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

try:
    root_path = sys.argv[1]
except:
    root_path = os.path.dirname(psutil.Process().exe())
print(f"Root path: {root_path}")
output_dir = os.path.join(root_path, "output")

def compress_zip(zip_filename, files_to_add):
    # 确保文件列表是列表形式
    if isinstance(files_to_add, str):
        files_to_add = [files_to_add]
    try:
        with pyzipper.ZipFile(zip_filename, 'w', compression=pyzipper.ZIP_DEFLATED) as zipf:
            for file_path in files_to_add:
                # 验证文件是否存在
                if not os.path.exists(file_path):
                    print(f"警告: 文件 '{file_path}' 不存在，跳过")
                    continue
                # 添加文件到 ZIP
                zipf.write(file_path)  # 要添加到压缩包的文件
                # zipf.write(file_path, arcname=os.path.basename(file_path))  # 如果不想保持原文件目录结构，使用 arcname 参数
        print(f"已创建压缩 ZIP 文件: {zip_filename}")
        return True
    except Exception as e:
        print(f"创建压缩 ZIP 失败: {str(e)}")
        return False

def decompress_zip(zip_filename, output_path):
    try:
        with pyzipper.ZipFile(zip_filename, 'r') as zipf:
            zipf.extractall(output_path)
        print(f"文件提取成功")
        return True
    except Exception as e:
        print(f"文件提取失败")
        return False

def encrypt_zip(zip_filename, files_to_add, password: str): # pyright: ignore[reportRedeclaration]
    # 确保密码是字节串
    if isinstance(password, str):
        password: bytes = password.encode(encoding='utf-8')
    # 确保文件列表是列表形式
    if isinstance(files_to_add, str):
        files_to_add = [files_to_add]
    try:
        with pyzipper.AESZipFile(zip_filename, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipf:
            # 设置全局密码
            zipf.setpassword(password)
            for file_path in files_to_add:
                # 验证文件是否存在
                if not os.path.exists(file_path):
                    print(f"警告: 文件 '{file_path}' 不存在，跳过")
                    continue
                # 添加文件到 ZIP（使用密码）
                zipf.write(file_path)
                # zipf.write(file_path, arcname=os.path.basename(file_path))  # 如果不想保持原文件目录结构，使用 arcname 参数
        print(f"已创建加密 ZIP 文件: {zip_filename}")
        return True
    except Exception as e:
        print(f"创建加密 ZIP 失败: {str(e)}")
        return False

def decrypt_zip(zip_path, output_path, password: str): # pyright: ignore[reportRedeclaration]
    if isinstance(password, str):
        password: bytes = password.encode(encoding='utf-8')  # 确保密码是字节串
    try:
        # 打开加密的 ZIP 文件
        with pyzipper.AESZipFile(zip_path, 'r') as zip_ref:
            # 方法 1: 设置全局密码
            zip_ref.setpassword(password)
            # 列出所有文件（验证密码）
            file_list = zip_ref.namelist()
            print("ZIP 内容:", file_list)  # ZIP 内容: ['test.csv']
            zip_ref.extractall(output_path)
        return True
    except FileNotFoundError:
        print("错误: ZIP 文件不存在")
    except Exception as e:
        print("未知错误:", e)
        return False

def create_user(name: str, password: str):
    # 生成ECC密钥对（替代原来的RSA）
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    url = "https://www.123h.top/id_allocator.php"
    response = urllib.request.urlopen(url)
    content = response.read()
    user_id = json.loads(content.decode('utf-8'))["id"]
    with open("private.pem", "w") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "w") as pub_file:
        pub_file.write(public_key)
    with open("username.txt", "w", encoding='utf-8') as user_file:
        user_file.write(name)
    with open("userid.txt", "w", encoding='utf-8') as id_file:
        id_file.write(str(user_id))
    encrypt_zip(os.path.join(root_path, "user.zip"), ["private.pem", "public.pem", "username.txt", "userid.txt"], password)
    compress_zip(os.path.join(root_path, "me.zip"), ["public.pem", "username.txt", "userid.txt"])
    os.remove("private.pem")
    os.remove("public.pem")
    os.remove("username.txt")
    os.remove("userid.txt")
    return public_key, private_key, name, user_id

def login_user(password: str):
    try:
        decrypt_zip(os.path.join(root_path, "user.zip"), output_dir, password)
        with open(os.path.join(output_dir, "public.pem"), "r") as pub_file:
            public_key = pub_file.read()
        with open(os.path.join(output_dir, "private.pem"), "r") as priv_file:
            private_key = priv_file.read()
        with open(os.path.join(output_dir, "username.txt"), "r", encoding='utf-8') as user_file:
            name = user_file.read()
        with open(os.path.join(output_dir, "userid.txt"), "r", encoding='utf-8') as id_file:
            user_id = id_file.read()
        os.remove(os.path.join(output_dir, "public.pem"))
        os.remove(os.path.join(output_dir, "private.pem"))
        os.remove(os.path.join(output_dir, "username.txt"))
        os.remove(os.path.join(output_dir, "userid.txt"))
        return True, public_key, private_key, name, user_id
    except Exception:
        return False, None, None, None, None

def analyze_users(user_zip:str):
    decompress_zip(user_zip, output_dir)
    with open(os.path.join(output_dir, "public.pem"), "r") as pub_file:
        public_key = pub_file.read()
    with open(os.path.join(output_dir, "username.txt"), "r", encoding='utf-8') as user_file:
        name = user_file.read()
    with open(os.path.join(output_dir, "userid.txt"), "r", encoding='utf-8') as id_file:
        user_id = id_file.read()
    os.remove(os.path.join(output_dir, "public.pem"))
    os.remove(os.path.join(output_dir, "username.txt"))
    os.remove(os.path.join(output_dir, "userid.txt"))
    return public_key, name, user_id

def encrypt_message(public_key_pem: str, message: str):
    """
    使用ECC+AES-256-GCM混合加密消息
    1. 使用ECDH生成共享密钥
    2. 使用共享密钥派生AES密钥
    3. 使用AES-256-GCM加密消息
    """
    # 导入接收方的ECC公钥
    recipient_key = ECC.import_key(public_key_pem)
    
    # 生成临时ECC密钥对用于ECDH
    ephemeral_key = ECC.generate(curve='P-256')
    ephemeral_public = ephemeral_key.public_key()
    
    # 执行ECDH计算共享密钥
    shared_secret = ephemeral_key.d * recipient_key.pointQ # pyright: ignore[reportOperatorIssue]
    # 修复：确保共享密钥为32字节，使用固定长度
    shared_key = shared_secret.x.to_bytes(32, 'big')  # 固定32字节长度
    
    # 使用共享密钥派生AES密钥
    aes_key = shared_key[:32]  # 256位密钥
    
    # 生成随机nonce
    nonce = get_random_bytes(12)  # GCM推荐使用12字节nonce
    
    # 使用AES-256-GCM加密消息
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    
    # 将临时公钥导出为PEM格式
    ephemeral_public_pem = ephemeral_public.export_key(format='PEM')
    
    # 组合所有数据
    encrypted_data = {
        'ephemeral_public_key': base64.b64encode(ephemeral_public_pem.encode()).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    
    return json.dumps(encrypted_data)

def decrypt_message(private_key_pem: str, encrypted_message: str):
    """
    解密使用ECC+AES-256-GCM混合加密的消息
    """
    # 解析加密数据
    encrypted_data = json.loads(encrypted_message)
    
    # 导入临时公钥
    ephemeral_public_pem = base64.b64decode(encrypted_data['ephemeral_public_key']).decode()
    ephemeral_public = ECC.import_key(ephemeral_public_pem)
    
    # 导入自己的私钥
    private_key = ECC.import_key(private_key_pem)
    
    # 执行ECDH计算共享密钥
    shared_secret = private_key.d * ephemeral_public.pointQ # pyright: ignore[reportOperatorIssue]
    # 修复：确保共享密钥为32字节，使用固定长度
    shared_key = shared_secret.x.to_bytes(32, 'big')  # 固定32字节长度
    
    # 使用共享密钥派生AES密钥
    aes_key = shared_key[:32]  # 256位密钥
    
    # 提取其他组件
    nonce = base64.b64decode(encrypted_data['nonce'])
    auth_tag = base64.b64decode(encrypted_data['auth_tag'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    # 使用AES-256-GCM解密消息
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, auth_tag)
    
    return plaintext.decode('utf-8')