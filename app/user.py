import os.path
import pyzipper
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64, urllib.request, json

root_path = os.path.dirname(os.path.abspath(__file__))
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
    # 生成RSA密钥对
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    url = "https://xn--jzh-k69dm57c4fd.xyz/id_allocator.php"
    response = urllib.request.urlopen(url)
    content = response.read()
    user_id = json.loads(content.decode('utf-8'))["id"]
    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)
    with open("username.txt", "w", encoding='utf-8') as user_file:
        user_file.write(name)
    with open("userid.txt", "w", encoding='utf-8') as id_file:
        id_file.write(str(user_id))
    encrypt_zip("user.zip", ["private.pem", "public.pem", "username.txt", "userid.txt"], password)
    compress_zip("me.zip", ["public.pem", "username.txt", "userid.txt"])
    os.remove("private.pem")
    os.remove("public.pem")
    os.remove("username.txt")
    os.remove("userid.txt")
    return public_key, private_key, name, user_id

def login_user(password: str):
    try:
        decrypt_zip("user.zip", output_dir, password)
        with open(os.path.join(output_dir, "public.pem"), "rb") as pub_file:
            public_key = pub_file.read()
        with open(os.path.join(output_dir, "private.pem"), "rb") as priv_file:
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
    with open(os.path.join(output_dir, "public.pem"), "rb") as pub_file:
        public_key = pub_file.read()
    with open(os.path.join(output_dir, "username.txt"), "r", encoding='utf-8') as user_file:
        name = user_file.read()
    with open(os.path.join(output_dir, "userid.txt"), "r", encoding='utf-8') as id_file:
        user_id = id_file.read()
    os.remove(os.path.join(output_dir, "public.pem"))
    os.remove(os.path.join(output_dir, "username.txt"))
    os.remove(os.path.join(output_dir, "userid.txt"))
    return public_key, name, user_id

def encrypt_message(public_key: bytes, message: str): # pyright: ignore[reportRedeclaration]
    message: bytes = message.encode(encoding='utf-8')
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted = base64.b64encode(cipher.encrypt(message)).decode('utf-8')
    return encrypted

def decrypt_message(private_key: bytes, encrypted_message: str): # pyright: ignore[reportRedeclaration]
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted.decode('utf-8')
