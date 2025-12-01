import socket
import threading
import shutil, time
import queue, sys
import user, os, urllib.request, json, urllib.error
import ssl, random

context = ssl.create_default_context()
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
myself_path = user.root_path

print(myself_path)

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

MAX_CHUNK_SIZE = 200

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, Y, X, YES, BROWSE, W, CENTER, VERTICAL, WORD, END, DISABLED, NORMAL, FLAT
import tkinter as tk
from tkinter import font as tkfont
from tkinter import simpledialog
from tkinter import messagebox
from tkinter import filedialog

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

if os.path.exists(os.path.join(myself_path, "addressBook")) == False:
    os.mkdir(os.path.join(myself_path, "addressBook"))
if os.path.exists(os.path.join(myself_path, "output")) == False:
    os.mkdir(os.path.join(myself_path, "output"))

temp_window = tk.Tk()
temp_window.withdraw()
if not os.path.exists(os.path.join(myself_path, "user.zip")):
        username = str(simpledialog.askstring("Input", "请输入用户名："))
        if username == "None" or username == "":
            temp_window.destroy()
            sys.exit(0)
        password = str(simpledialog.askstring("Input", "请输入密码："))
        if password == "None" or password == "":
            temp_window.destroy()
            sys.exit(0)
        public_key, private_key, name, user_id = user.create_user(username, password)
else:
    right = False
    while not right:
        password = str(simpledialog.askstring("Input", "请输入密码："))
        if password == "None" or password == "":
            temp_window.destroy()
            sys.exit(0)
        right, public_key, private_key, name, user_id = user.login_user(password)
temp_window.destroy()

payload = {
    "uuid": user_id, # pyright: ignore[reportPossiblyUnboundVariable]
    "ipv6_address": get_ipv6_addresses()[0]
}

try:
    json_data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request("https://xn--jzh-k69dm57c4fd.xyz/ipv6_allocator.php", data=json_data, headers={'Content-Type': 'application/json'}, method='POST')
    urllib.request.urlopen(req, context=context)
except urllib.error.URLError as e:
    messagebox.showerror("错误", f"网络请求失败: {e}")
    print(f"网络请求失败: {e}")
    sys.exit(1)
except socket.timeout:
    messagebox.showerror("错误", "连接超时，请检查网络连接")
    print("连接超时，请检查网络连接")
    sys.exit(1)
except Exception as e:
    messagebox.showerror("错误", f"网络请求时发生错误: {e}")
    print(f"网络请求时发生错误: {e}")
    sys.exit(1)

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

# 创建一个队列用于线程间通信
message_queue = queue.Queue()
message_caches = {}
active_messages = {}

def recvall(sock, n):
    """Helper function to recv n bytes or return None if EOF is hit"""
    # 用于确保接收恰好 n 个字节
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def server_receive(s: socket.socket):
    # 1. 接收消息体的长度 (4 bytes)
    raw_msg_len = recvall(s, 4)
    if not raw_msg_len:
        print("Connection closed by client")
        return None, None
    msg_len = int.from_bytes(raw_msg_len, 'big')

    # 2. 根据长度接收消息体
    msg_bytes = recvall(s, msg_len)
    if not msg_bytes:
        print("Connection closed by client")
        return None, None
    message = msg_bytes.decode('utf-8') # 将字节解码回字符串

    # 3. 接收签名的长度 (4 bytes)
    raw_sig_len = recvall(s, 4)
    if not raw_sig_len:
        print("Connection closed by client")
        return None, None
    sig_len = int.from_bytes(raw_sig_len, 'big')

    # 4. 根据长度接收签名
    sig_bytes = recvall(s, sig_len)
    if not sig_bytes:
        print("Connection closed by client")
        return None, None
    signature = base64.b64decode(sig_bytes) # 将Base64字节解码回原始签名

    return message, signature

def handle_client(conn, addr, message_queue):
    try:
        while True:
            message, signature = server_receive(conn)
            if not message or not signature:
                break
            message = json.loads(user.decrypt_message(private_key, message)) # pyright: ignore[reportArgumentType]
            this_friend = {}
            for key in friends.keys():
                if friends[key]["name"] == message["name"]:
                    this_friend = friends[key]
            try:
                # 创建相同的哈希对象
                hasher = SHA256.new(message["message"].encode('utf-8'))
                # 创建一个验证对象
                verifier = pkcs1_15.new(RSA.import_key(this_friend["public_key"]))
                # 验证签名
                verifier.verify(hasher, signature)
                # 将接收到的消息放入队列
                message_queue.put(message)
            except ValueError:
                pass
            except Exception as e:
                messagebox.showerror("错误", f"验证过程中发生错误: {e}")
                print(f"验证过程中发生错误: {e}")

    finally:
        conn.close()

def start_server(host, port, message_queue, stop_event):
    active_threads = []
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        try:
            while not stop_event.is_set():
                try:
                    conn, addr = s.accept()
                    client_thread = threading.Thread(target=handle_client, args=(conn, addr, message_queue), daemon=True)
                    client_thread.start()
                    active_threads.append(client_thread)
                    active_threads = [t for t in active_threads if t.is_alive()]
                except socket.timeout:
                    continue
        finally:
            # 确保所有线程都有机会清理
            stop_event.set()
            for thread in active_threads:
                if thread.is_alive():
                    thread.join(timeout=1)

def send_message(user_id, public_key, message_str, port=19042):
    host = ""
    message_data = {"message": message_str, "name": name}
    message_json = json.dumps(message_data)
    
    # 如果JSON序列化后太大，自动切换到长消息发送方式
    if len(message_json.encode('utf-8')) > 400:  # 保守估计RSA OAEP限制
        return send_long_message(user_id, public_key, message_str, port)
    try:
        url = f"https://xn--jzh-k69dm57c4fd.xyz/ipv6_query.php?uuid={user_id}"
        response = urllib.request.urlopen(url, timeout=10, context=context)
        content = response.read()
        host = json.loads(content.decode('utf-8'))["ipv6_address"]
    except urllib.error.URLError as e:
        messagebox.showerror("错误", f"网络请求失败: {e}")
        print(f"网络请求失败: {e}")
        sys.exit(1)
    except socket.timeout:
        messagebox.showerror("错误", "连接超时，请检查网络连接")
        print("连接超时，请检查网络连接")
        sys.exit(1)
    except Exception as e:
        messagebox.showerror("错误", f"网络请求时发生错误: {e}")
        print(f"网络请求时发生错误: {e}")
        sys.exit(1)
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        # 创建一个SHA256哈希对象
        hasher = SHA256.new(message_str.encode('utf-8'))
        # 创建一个签名对象
        signer = pkcs1_15.new(RSA.import_key(private_key)) # pyright: ignore[reportArgumentType]
        # 生成签名
        signature = signer.sign(hasher)
        message = user.encrypt_message(public_key, json.dumps({"message": message_str, "name": name})) # pyright: ignore[reportArgumentType]
        msg_bytes = message.encode('utf-8')
        sig_bytes = base64.b64encode(signature)
        packet = (
            len(msg_bytes).to_bytes(4, 'big') +
            msg_bytes +
            len(sig_bytes).to_bytes(4, 'big') +
            sig_bytes
        )
        s.sendall(packet)

def send_long_message(user_id, public_key, message_str, port=19042):
    host = ""
    try:
        # 获取接收方的IPv6地址
        url = f"https://xn--jzh-k69dm57c4fd.xyz/ipv6_query.php?uuid={user_id}"
        response = urllib.request.urlopen(url, timeout=10, context=context)
        content = response.read()
        host = json.loads(content.decode('utf-8'))["ipv6_address"]
    except Exception as e:
        messagebox.showerror("错误", f"获取好友地址失败: {e}")
        print(f"获取好友地址失败: {e}")
        raise
    
    # 创建一个唯一的消息ID
    msg_id = f"{int(time.time())}_{random.randint(1000, 9999)}"
    
    # 将消息转换为字节并计算总分片数
    message_bytes = message_str.encode('utf-8')
    total_chunks = (len(message_bytes) + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE  # 向上取整
    
    try:
        # 创建单一连接用于发送所有分片
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            
            # 发送开始标记
            start_msg = json.dumps({"message": "[长消息，开始௹⺟]", "name": name, "msg_id": msg_id, "total": total_chunks})
            encrypted_start = user.encrypt_message(public_key, start_msg)
            start_bytes = encrypted_start.encode('utf-8')
            start_hasher = SHA256.new("[长消息，开始௹⺟]".encode('utf-8'))
            start_signer = pkcs1_15.new(RSA.import_key(private_key)) # pyright: ignore[reportArgumentType]
            start_signature = start_signer.sign(start_hasher)
            start_sig_bytes = base64.b64encode(start_signature)
            
            start_packet = (
                len(start_bytes).to_bytes(4, 'big') +
                start_bytes +
                len(start_sig_bytes).to_bytes(4, 'big') +
                start_sig_bytes
            )
            s.sendall(start_packet)
            
            # 按字节分片发送数据
            for i in range(0, len(message_bytes), MAX_CHUNK_SIZE):
                # 提取字节片段并解码回字符串（确保UTF-8完整性）
                # 注意：这里需要确保不会截断多字节字符
                chunk_bytes = message_bytes[i:i+MAX_CHUNK_SIZE]
                # 确保解码安全（处理可能的截断）
                try:
                    chunk = chunk_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    # 如果发生解码错误，尝试回退几个字节以找到完整的UTF-8字符
                    for j in range(1, 5):  # UTF-8最多4字节
                        if i + MAX_CHUNK_SIZE - j > i:
                            chunk_bytes_safe = message_bytes[i:i+MAX_CHUNK_SIZE-j]
                            try:
                                chunk = chunk_bytes_safe.decode('utf-8')
                                break
                            except UnicodeDecodeError:
                                continue
                    else:
                        # 最坏情况下，使用错误处理模式
                        chunk = chunk_bytes.decode('utf-8', errors='replace')
                
                # 确保JSON序列化后的大小不会超过RSA限制
                # 预检查JSON序列化后的大小
                chunk_data = {"message": chunk, "name": name, "msg_id": msg_id, "index": i//MAX_CHUNK_SIZE}
                chunk_json = json.dumps(chunk_data)
                
                # 如果JSON序列化后太大，进一步减小chunk大小
                while len(chunk_json.encode('utf-8')) > 400:  # 保守估计RSA OAEP限制
                    # 从末尾删除几个字符并重新检查
                    chunk = chunk[:-3]
                    chunk_data["message"] = chunk
                    chunk_json = json.dumps(chunk_data)
                    
                    # 如果已经很小了还不行，就只保留一个字符
                    if len(chunk) <= 1:
                        break
                
                encrypted_chunk = user.encrypt_message(public_key, chunk_json)
                
                chunk_msg = json.dumps({"message": chunk, "name": name, "msg_id": msg_id, "index": i//MAX_CHUNK_SIZE})
                encrypted_chunk = user.encrypt_message(public_key, chunk_msg)
                chunk_send_bytes = encrypted_chunk.encode('utf-8')
                chunk_hasher = SHA256.new(chunk.encode('utf-8'))
                chunk_signer = pkcs1_15.new(RSA.import_key(private_key)) # pyright: ignore[reportArgumentType]
                chunk_signature = chunk_signer.sign(chunk_hasher)
                chunk_sig_bytes = base64.b64encode(chunk_signature)
                
                chunk_packet = (
                    len(chunk_send_bytes).to_bytes(4, 'big') +
                    chunk_send_bytes +
                    len(chunk_sig_bytes).to_bytes(4, 'big') +
                    chunk_sig_bytes
                )
                s.sendall(chunk_packet)
                
            # 发送结束标记
            end_msg = json.dumps({"message": "[长消息，结束௹⺟]", "name": name, "msg_id": msg_id})
            encrypted_end = user.encrypt_message(public_key, end_msg)
            end_bytes = encrypted_end.encode('utf-8')
            end_hasher = SHA256.new("[长消息，结束௹⺟]".encode('utf-8'))
            end_signer = pkcs1_15.new(RSA.import_key(private_key)) # pyright: ignore[reportArgumentType]
            end_signature = end_signer.sign(end_hasher)
            end_sig_bytes = base64.b64encode(end_signature)
            
            end_packet = (
                len(end_bytes).to_bytes(4, 'big') +
                end_bytes +
                len(end_sig_bytes).to_bytes(4, 'big') +
                end_sig_bytes
            )
            s.sendall(end_packet)
            
    except Exception as e:
        messagebox.showerror("错误", f"发送长消息失败: {e}")
        print(f"发送长消息失败: {e}")
        raise

class WeChatUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Oleander Chat")
        self.root.geometry("1200x700")
        self.custom_font = tkfont.Font(family="微软雅黑", size=10)
        self.setup_ui()
    def setup_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=YES, padx=5, pady=5)
        friend_frame = ttk.Labelframe(main_frame, text="好友列表", bootstyle="info")
        friend_frame.pack(side=LEFT, fill=Y, padx=(0,5))
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="加好友", command=self.add_friend)
        self.context_menu.add_command(label="删除好友", command=self.remove_friend)
        friend_frame.bind("<Button-3>", self.show_context_menu)
        friend_frame.bind("<Button-2>", self.show_context_menu)
        self.friend_listbox = ttk.Treeview(friend_frame, height=20, selectmode=BROWSE)
        self.friend_listbox.pack(side=LEFT, fill=Y, padx=5, pady=5)
        friend_scroll = ttk.Scrollbar(friend_frame, orient=VERTICAL, command=self.friend_listbox.yview)
        friend_scroll.pack(side=RIGHT, fill=Y)
        self.friend_listbox.configure(yscrollcommand=friend_scroll.set)
        self.friend_listbox["columns"] = ("status",)
        self.friend_listbox.column("#0", width=120, anchor=W)
        self.friend_listbox.column("status", width=20, anchor=CENTER)
        self.friend_listbox.heading("#0", text="好友")
        self.friend_listbox.bind("<Button-3>", self.show_context_menu)
        self.friend_listbox.bind("<Button-2>", self.show_context_menu)

        for friend in friends.values():
            self.friend_listbox.insert("", "end", text=friend["name"])

        chat_frame = ttk.Frame(main_frame)
        chat_frame.pack(side=RIGHT, fill=BOTH, expand=YES)
        title_frame = ttk.Frame(chat_frame)
        title_frame.pack(fill=X, pady=(0,5))
        self.chat_title = ttk.Label(title_frame, text="选择一个好友开始聊天", font=self.custom_font)
        self.chat_title.pack(side=LEFT, padx=10)
        chat_container = ttk.Frame(chat_frame)
        chat_container.pack(fill=BOTH, expand=YES, pady=(0,5))
        self.chat_text = ttk.Text(
            chat_container, 
            wrap=WORD, 
            font=self.custom_font,
            state=DISABLED,
            relief=FLAT,
            highlightthickness=1,
            highlightbackground="#ddd"
        )
        self.chat_text.pack(side=LEFT, fill=BOTH, expand=YES, padx=(10,5))
        chat_scroll = ttk.Scrollbar(chat_container, orient=VERTICAL, command=self.chat_text.yview)
        chat_scroll.pack(side=RIGHT, fill=Y)
        self.chat_text.configure(yscrollcommand=chat_scroll.set)
        input_frame = ttk.Labelframe(chat_frame, text="发送消息", bootstyle="info")
        input_frame.pack(fill=X, pady=(0,5))
        self.message_input = ttk.Text(
            input_frame,
            height=4,
            font=self.custom_font,
            relief=FLAT,
            highlightthickness=1,
            highlightbackground="#ddd"
        )
        self.message_input.pack(fill=X, padx=10, pady=5)
        send_btn_file = ttk.Button(
            input_frame, 
            text="发送文件", 
            bootstyle="success-outline",
            command=self.send_file
        )
        send_btn_file.pack(side=RIGHT, padx=10, pady=5)
        send_btn = ttk.Button(
            input_frame, 
            text="发送", 
            bootstyle="success-outline",
            command=self.send_message
        )
        send_btn.pack(side=RIGHT, padx=10, pady=5)
        self.friend_listbox.bind("<<TreeviewSelect>>", self.on_friend_select)
        self.message_input.bind("<Return>", self.send_message_on_enter)
    
    def show_context_menu(self, event):
            """在鼠标位置显示右键菜单"""
            try:
                # 显示菜单，位置为鼠标点击的坐标
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                # 确保菜单在失去焦点时被取消（例如，点击菜单外部）
                self.context_menu.grab_release()

    def add_friend(self):
        """添加好友"""
        friend_file = filedialog.askopenfilename(title="请选择好友文件:", filetypes=[("压缩文件", "*.zip")])
        if friend_file:
            shutil.copy(friend_file, os.path.join(myself_path, "addressBook", f"{time.time()}.zip"))
            public_key, name, user_id = user.analyze_users(friend_file)
            friends[user_id] = {
                "user_id": user_id,
                "public_key": public_key,
                "name": name,
                "file": f"{time.time()}.zip"
            }
            chat_record[name] = []
            self.friend_listbox.insert("", "end", text=name)

    def remove_friend(self):
        """删除好友"""
        selection = self.friend_listbox.selection()
        if selection:
            friend_name = self.friend_listbox.item(selection[0])["text"]
            os.remove(os.path.join(myself_path, "addressBook", f"{friends[user_id]['file']}"))
            for key in friends.keys():
                if friends[key]["name"] == friend_name:
                    del friends[key]
                    break
            del chat_record[friend_name]
            self.friend_listbox.delete(selection[0])

    def on_friend_select(self, event):
        """好友选择事件"""
        selection = self.friend_listbox.selection()
        if selection:
            friend_name = self.friend_listbox.item(selection[0])["text"]
            self.chat_title.config(text=f"与 {friend_name} 聊天中")
            self.chat_text.config(state=NORMAL) # pyright: ignore[reportArgumentType]
            self.chat_text.delete(1.0, END)
            self.chat_text.config(state=DISABLED) # pyright: ignore[reportArgumentType]
            for msg in chat_record[friend_name]:
                self.display_message(msg)
    
    def send_message(self):
        """发送消息"""
        message = self.message_input.get(1.0, END).strip()
        if message:
            selection = self.friend_listbox.selection()
            if not selection:
                messagebox.showerror("错误", "请先选择一个好友")
                return
            this_friend = None
            for key in friends.keys():
                if friends[key]["name"] == self.friend_listbox.item(self.friend_listbox.selection()[0])["text"]:
                    this_friend = friends[key]
            if not this_friend:
                messagebox.showerror("错误", "未找到好友信息")
                return
            try:
                message_bytes = message.encode('utf-8')
                if len(message_bytes) > MAX_CHUNK_SIZE:
                    send_long_message(this_friend["user_id"], this_friend["public_key"], message)
                else:
                    send_message(this_friend["user_id"], this_friend["public_key"], message)
                self.display_message(f"我: {message}")
                chat_record[this_friend["name"]].append(f"我: {message}")
                self.message_input.delete(1.0, END)
            except Exception as e:
                messagebox.showerror("发送失败", f"消息发送失败，可能对方不在线")
                messagebox.showerror("发送失败", str(e))
    
    def send_file(self):
        """发送文件"""
        selection = self.friend_listbox.selection()
        if not selection:
            messagebox.showerror("错误", "请先选择一个好友")
            return
        this_friend = None
        for key in friends.keys():
            if friends[key]["name"] == self.friend_listbox.item(self.friend_listbox.selection()[0])["text"]:
                this_friend = friends[key]
        if not this_friend:
            messagebox.showerror("错误", "未找到好友信息")
            return
        file_path = filedialog.askopenfilename(title="请选择文件:", filetypes=[("所有文件", "*.*")])
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    file_data = base64.b64encode(f.read()).decode('utf-8')
                message = f"{file_data} card(file) {os.path.basename(file_path)}"
                send_long_message(this_friend["user_id"], this_friend["public_key"], message)
                self.display_card("我: "+message)
                chat_record[this_friend["name"]].append("我: "+message)
            except Exception as e:
                messagebox.showerror("发送失败", f"文件发送失败，可能对方不在线")
                messagebox.showerror("发送失败", str(e))

    def send_message_on_enter(self, event):
        """回车发送消息"""
        if not event.state & 0x1:  # 检查是否按下了Shift键
            self.send_message()
            return "break"  # 阻止默认的换行行为
    
    def display_message(self, message):
        if "card(file)" in message:
            self.display_card(message)
            return
        """显示消息"""
        self.chat_text.config(state=NORMAL) # pyright: ignore[reportArgumentType]
        self.chat_text.insert(END, message + "\n")
        self.chat_text.see(END)
        self.chat_text.config(state=DISABLED) # pyright: ignore[reportArgumentType]
    
    def display_card(self, message):
        """显示文件卡片消息"""
        if "card(file)"  in message:
            file = message.split(" card(file)")[0]
            self.chat_text.config(state=NORMAL) # pyright: ignore[reportArgumentType]
            self.chat_text.insert(END, message.split(": ")[0] + f"： {message.split(' card(file) ')[1]}\n")
            self.chat_text.tag_add("url", "end-10c", "end-1c")  # 标记"点击这里打开网页"这段文字
            self.chat_text.tag_config("url", foreground="blue", underline=True)
            def download_file(file):
                with open(filedialog.asksaveasfilename(title="保存文件为:", initialfile=message.split(" card(file) ")[1]), "wb") as f:
                    f.write(base64.b64decode(file.split(": ")[1]))
            self.chat_text.tag_bind("url", "<Button-1>", lambda e, f=file: download_file(f))
            self.chat_text.see(END)
            self.chat_text.config(state=DISABLED) # pyright: ignore[reportArgumentType]
    
    def custom_font_setting(self, family="微软雅黑", size=10):
        """自定义字体设置"""
        self.custom_font = tkfont.Font(family=family, size=size)
        self.chat_text.config(font=self.custom_font)
        self.message_input.config(font=self.custom_font)
        self.chat_title.config(font=self.custom_font)

def main():
    global message_cache, message_cache_open
    try:
        # 使用非阻塞方式尝试获取消息，设置超时为0
        message = message_queue.get_nowait()
        if message:
            # 检查chat_record中是否有该好友的记录，如果没有则创建
            if message["name"] not in chat_record:
                chat_record[message["name"]] = []
            
            # 尝试更新UI，但只有在有选择好友且选择的是当前发消息的好友时才显示
            try:
                if ui.friend_listbox.selection():
                    selected_friend = ui.friend_listbox.item(ui.friend_listbox.selection()[0])["text"]
                    if selected_friend == message["name"]:
                        if "msg_id" in message:
                            msg_id = message["msg_id"]
                            # 处理长消息开始标记
                            if message["message"] == "[长消息，开始௹⺟]":
                                # 初始化该消息的缓存
                                message_caches[msg_id] = ""
                                active_messages[msg_id] = True
                                if "total" in message:
                                    active_messages[f"{msg_id}_total"] = message["total"]
                                    active_messages[f"{msg_id}_received"] = 0
                            # 处理长消息结束标记
                            elif message["message"] == "[长消息，结束௹⺟]":
                                if msg_id in message_caches and active_messages.get(msg_id, False):
                                    # 组装完成，显示完整消息
                                    full_message = message_caches[msg_id]
                                    ui.display_message(f"{message['name']}: {full_message}")
                                    chat_record[message["name"]].append(f"{message['name']}: {full_message}")
                                    # 清理缓存
                                    del message_caches[msg_id]
                                    active_messages[msg_id] = False
                                    if f"{msg_id}_total" in active_messages:
                                        del active_messages[f"{msg_id}_total"]
                                        del active_messages[f"{msg_id}_received"]
                            # 处理普通分片
                            else:
                                if msg_id in active_messages and active_messages[msg_id]:
                                    # 添加到对应消息的缓存中
                                    if msg_id not in message_caches:
                                        message_caches[msg_id] = ""
                                    message_caches[msg_id] += message["message"]
                                    # 更新已接收分片计数
                                    if f"{msg_id}_received" in active_messages:
                                        active_messages[f"{msg_id}_received"] += 1
                        else:
                            chat_record[message["name"]].append(f"{message['name']}: {message['message']}")
                            ui.display_message(f"{message['name']}: {message['message']}")
            except Exception as e:
                print(f"UI更新错误: {e}")
            # 标记任务完成
            message_queue.task_done()
    except queue.Empty:
        # 队列为空，不做任何操作
        pass
    except Exception as e:
        print(f"处理消息时出错: {e}")
    
    # 100毫秒后再次调用main函数，保持UI响应性
    app.after(100, main)

if __name__ == "__main__":
    stop_event = threading.Event()
    server_thread = threading.Thread(target=start_server, args=("::", 19042, message_queue, stop_event), daemon=True)
    server_thread.start()

    # 主线程从队列中获取消息并处理
    app = ttk.Window(themename="cosmo")
    ui = WeChatUI(app)
    app.after(100, main)
    app.mainloop()
    stop_event.set()
    server_thread.join(timeout=1)
    sys.exit()
