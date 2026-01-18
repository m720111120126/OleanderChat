import socket, user, os, urllib.request, json, urllib.error, sys, time
import ssl, random, base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from tkinter import messagebox
import tkinter as tk
from tkinter import simpledialog

myself_path = user.root_path
context = ssl.create_default_context()
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED

def get_ipv6_addresses():
    ipv6_addresses = []
    try:
        # 获取所有网络接口的信息
        info = socket.getaddrinfo(socket.gethostname(), None)
        for addr in info:
            # 检查地址族是否为AF_INET6（IPv6）
            if addr[0] == socket.AF_INET6 and addr[4][0] != '::1' and "fe80" not in addr[4][0]: # pyright: ignore[reportOperatorIssue]
                ipv6_addresses.append(addr[4][0])
    except Exception as e:
        print(f"Error retrieving IPv6 addresses: {e}")
    return ipv6_addresses

ipv6_addresses = get_ipv6_addresses()
if ipv6_addresses:
    print("IPv6 Addresses:")
    for ip in ipv6_addresses:
        print(ip)
else:
    messagebox.showerror("错误", "未找到IPv6地址，请检查网络设置。")
    print("No IPv6 addresses found.")
    sys.exit()

temp_window = tk.Tk()
temp_window.withdraw()
messagebox.showwarning("警告", "严禁利用本软件从事违法犯罪活动")
if not os.path.exists(os.path.join(myself_path, "user.zip")):
        username = str(simpledialog.askstring("Input", "请输入用户名："))
        if username == "None" or username == "":
            temp_window.destroy()
            sys.exit(0)
        password = str(simpledialog.askstring("Input", "请输入密码：", show='*'))
        if password == "None" or password == "":
            temp_window.destroy()
            sys.exit(0)
        public_key, private_key, name, user_id = user.create_user(username, password)
else:
    right = False
    while not right:
        password = str(simpledialog.askstring("Input", "请输入密码：", show='*'))
        if password == "None" or password == "":
            temp_window.destroy()
            sys.exit(0)
        right, public_key, private_key, name, user_id = user.login_user(password)
        if not right:
            messagebox.showerror("错误", "密码错误，请重新输入。")
temp_window.destroy()

payload = {
    "uuid": user_id, # pyright: ignore[reportPossiblyUnboundVariable]
    "ipv6_address": get_ipv6_addresses()[0]
}

files = os.listdir(os.path.join(myself_path, "addressBook"))
friends = {}
chat_record = {}
for file in files:
    public_key2, name2, user_id2 = user.analyze_users(os.path.join(myself_path, "addressBook", file))
    friends[user_id2] = {
        "user_id": user_id2,
        "public_key": public_key2,
        "name": name2,
        "file": file
    }
    chat_record[name2] = []


def recvall(sock, n):
    # Helper function to receive n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def server_receive(s: socket.socket):
    # 1. 接收消息体的长度 (4 bytes)
    raw_msg_len = recvall(s, 4)
    if not raw_msg_len:
        print("Connection closed by client 1")
        return None, None
    msg_len = int.from_bytes(raw_msg_len, 'big')

    # 2. 根据长度接收消息体
    msg_bytes = recvall(s, msg_len)
    if not msg_bytes:
        print("Connection closed by client 2")
        return None, None
    message = msg_bytes  # 不再解码为字符串，保持字节格式

    # 3. 接收签名的长度 (4 bytes)
    raw_sig_len = recvall(s, 4)
    if not raw_sig_len:
        print("Connection closed by client 3")
        return None, None
    sig_len = int.from_bytes(raw_sig_len, 'big')

    # 4. 根据长度接收签名
    sig_bytes = recvall(s, sig_len)
    if not sig_bytes:
        print("Connection closed by client 4")
        return None, None
    signature = base64.b64decode(sig_bytes) # 将Base64字节解码回原始签名

    return message, signature

def verify_signature(public_key_pem, message, signature):
    """
    使用ECC公钥验证消息签名
    """
    try:
        # 导入ECC公钥
        public_key = ECC.import_key(public_key_pem)
        
        # 创建哈希对象
        hasher = SHA256.new(message.encode('utf-8'))
        
        # 创建验证对象
        verifier = DSS.new(public_key, 'fips-186-3')
        
        # 验证签名
        verifier.verify(hasher, signature)
        return True
    except Exception as e:
        print(f"签名验证失败: {e}")
        return False

def handle_client(conn, addr, message_queue):
    try:
        while True:
            message_bytes, signature = server_receive(conn)
            if not message_bytes or not signature:
                print(f"客户端 {addr} 断开连接")
                break
            
            try:
                # 将字节解码为字符串进行初步解析
                message_str = message_bytes.decode('utf-8')
                # 解密消息
                decrypted_message = user.decrypt_message(private_key, message_str)  # pyright: ignore[reportArgumentType]
                message_data = json.loads(decrypted_message)
                
                # 查找好友信息
                this_friend = None
                for key in friends.keys():
                    if friends[key]["name"] == message_data["name"]:
                        this_friend = friends[key]
                        break
                
                if not this_friend:
                    print(f"未找到好友信息: {message_data['name']}")
                    continue
                
                # 使用ECC密钥进行签名验证
                if verify_signature(this_friend["public_key"], message_data["message"], signature):
                    # 将接收到的消息放入队列
                    message_queue.put(message_data)
                else:
                    print("签名验证失败")
                    
            except Exception as e:
                print(f"解密或解析消息失败: {e}")
                continue

    except Exception as e:
        print(f"处理客户端 {addr} 时发生错误: {e}")
    finally:
        conn.close()
        print(f"客户端 {addr} 连接已关闭")

def sign_message(private_key_pem, message):
    """
    使用ECC私钥对消息进行签名
    """
    # 导入ECC私钥
    private_key = ECC.import_key(private_key_pem)
    
    # 创建哈希对象
    hasher = SHA256.new(message.encode('utf-8'))
    
    # 创建签名对象
    signer = DSS.new(private_key, 'fips-186-3')
    
    # 生成签名
    signature = signer.sign(hasher)
    return signature

def send_message(user_id, public_key, message_str, port=19042):
    host = ""
    try:
        # 获取接收方的IPv6地址
        url = f"https://www.123h.top/ipv6_query.php?uuid={user_id}"
        response = urllib.request.urlopen(url, timeout=10, context=context)
        content = response.read()
        host = json.loads(content.decode('utf-8'))["ipv6_address"]
    except Exception as e:
        messagebox.showerror("错误", f"获取好友地址失败: {e}")
        print(f"获取好友地址失败: {e}")
        raise
    
    try:
        # 创建单一连接用于发送所有分片
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            
            # 简化的长消息发送：直接发送加密后的完整消息
            message_data = {"message": message_str, "name": name, "to": user_id}
            message_json = json.dumps(message_data)
            
            # 加密消息
            encrypted_message = user.encrypt_message(public_key, message_json)  # pyright: ignore[reportArgumentType]
            msg_bytes = encrypted_message.encode('utf-8')
            
            # 使用ECC私钥签名（签名原始消息内容）
            signature = sign_message(private_key, message_str)  # pyright: ignore[reportArgumentType]
            sig_bytes = base64.b64encode(signature)
            
            # 发送完整的消息包
            packet = (
                len(msg_bytes).to_bytes(4, 'big') +
                msg_bytes +
                len(sig_bytes).to_bytes(4, 'big') +
                sig_bytes
            )
            s.sendall(packet)
            
    except Exception as e:
        messagebox.showerror("错误", f"发送长消息失败: {e}")
        print(f"发送长消息失败: {e}")