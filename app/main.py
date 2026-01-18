import socket, threading, shutil, time, queue, sys, user, os, urllib.request, json, urllib.error
import ssl, base64

context = ssl.create_default_context()
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
myself_path = user.root_path
if os.path.exists(os.path.join(myself_path, "addressBook")) == False:
    os.mkdir(os.path.join(myself_path, "addressBook"))
if os.path.exists(os.path.join(myself_path, "output")) == False:
    os.mkdir(os.path.join(myself_path, "output"))

import connect
import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, Y, X, YES, BROWSE, W, CENTER, VERTICAL, WORD, END, DISABLED, NORMAL, FLAT, NO
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox
from tkinter import filedialog

try:
    json_data = json.dumps(connect.payload).encode('utf-8')
    req = urllib.request.Request("https://www.123h.top/ipv6_allocator.php", data=json_data, headers={'Content-Type': 'application/json'}, method='POST')
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

# 创建一个队列用于线程间通信
message_queue = queue.Queue()
message_caches = {}
active_messages = {}

firends_online = {}
for id in connect.friends.keys():
    i = connect.friends[id]
    firends_online[i["name"]] = {"oline": True, "user_id": i["user_id"], "host": None}

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
                    client_thread = threading.Thread(target=connect.handle_client, args=(conn, addr, message_queue), daemon=True)
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

def Peer_server(host, port, stop_event):
    """启动IPv6服务端，监听心跳包"""
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"Peer服务端启动，监听 IPv6 地址 {host}:{port}")
    while not stop_event.is_set():
        client, addr = server.accept()
        data = client.recv(1024).decode()
        if data == "HEARTBEAT":
            client.send("HEARTBEAT".encode())
            print(f"收到对方心跳包，对方在线: {addr}")
        client.close()

def send_heartbeat(host, port, name):
    """定期发送心跳包给对方（IPv6）"""
    client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect((host, port))
        client.send("HEARTBEAT".encode())
        data = client.recv(1024).decode()
        print(f"已发送心跳包给 {host}")
        if data == "HEARTBEAT":
            ui.update_friend_status(name, "在线")
            return True
    except Exception as e:
        print(f"发送心跳包失败: {e}")
    finally:
        client.close()
    ui.update_friend_status(name, "离线")
    return False

class WeChatUI:
    def __init__(self, root):
        messagebox.showwarning("警告", "严禁利用本软件从事违法犯罪活动")
        self.root = root
        self.root.title("Oleander Chat")
        self.root.geometry("1200x700")
        self.custom_font = tkfont.Font(family="微软雅黑", size=10)
        self.setup_ui()
    def setup_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=YES, padx=5, pady=5)
        friend_frame = ttk.Labelframe(main_frame, text="好友列表", bootstyle="info")
        friend_frame.pack(side=LEFT, fill=Y, padx=(0,5), pady=5)
        self.friend_listbox = ttk.Treeview(
            friend_frame, 
            height=20, 
            selectmode=BROWSE,
            show='tree headings',
            columns=("status",)
        )
        self.friend_listbox.column("#0", width=150, anchor=W, stretch=NO)  # pyright: ignore[reportArgumentType] # 好友名
        self.friend_listbox.column("status", width=100, anchor=CENTER, stretch=NO)  # pyright: ignore[reportArgumentType] # 状态
        self.friend_listbox.heading("#0", text="好友")
        self.friend_listbox.heading("status", text="状态")
        friend_scroll = ttk.Scrollbar(friend_frame, orient=VERTICAL, command=self.friend_listbox.yview)
        friend_scroll.pack(side=RIGHT, fill=Y, padx=(0,5), pady=5)
        self.friend_listbox.configure(yscrollcommand=friend_scroll.set)
        self.friend_listbox.pack(side=LEFT, fill=Y, padx=(5,0), pady=5)
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="加好友", command=self.add_friend)
        self.context_menu.add_command(label="删除好友", command=self.remove_friend)
        friend_frame.bind("<Button-3>", self.show_context_menu)
        friend_frame.bind("<Button-2>", self.show_context_menu)
        self.friend_listbox.bind("<Button-3>", self.show_context_menu)
        self.friend_listbox.bind("<Button-2>", self.show_context_menu)
        for friend in connect.friends.values():
            if friend["name"] not in firends_online:
                firends_online[friend["name"]] = {"oline": False, "user_id": friend["user_id"], "host": None}
            self.friend_listbox.insert("", "end", text=friend["name"], values=("在线" if firends_online[friend["name"]]["oline"] else "离线",))
        chat_frame = ttk.Frame(main_frame)
        chat_frame.pack(side=RIGHT, fill=BOTH, expand=YES)
        title_frame = ttk.Frame(chat_frame)
        title_frame.pack(fill=X, pady=(0,5))
        self.chat_title = ttk.Label(title_frame, text="OleanderChat", font=self.custom_font)
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
            connect.friends[user_id] = {
                "user_id": user_id,
                "public_key": public_key,
                "name": name,
                "file": f"{time.time()}.zip"
            }
            connect.chat_record[name] = []
            firends_online[name] = {"oline": False, "user_id": user_id, "host": None}
            self.friend_listbox.insert("", "end", text=name, values=("离线",))

    def remove_friend(self):
        """删除好友"""
        selection = self.friend_listbox.selection()
        if selection:
            friend_name = self.friend_listbox.item(selection[0])["text"]
            os.remove(os.path.join(myself_path, "addressBook", f"{connect.friends[connect.user_id]['file']}"))
            for key in connect.friends.keys():
                if connect.friends[key]["name"] == friend_name:
                    del connect.friends[key]
                    break
            del connect.chat_record[friend_name]
            self.friend_listbox.delete(selection[0])

    def on_friend_select(self, event):
        """好友选择事件"""
        selection = self.friend_listbox.selection()
        if selection:
            friend_name = self.friend_listbox.item(selection[0])["text"]
            firends_online[friend_name]["oline"] = send_heartbeat(firends_online[friend_name]["host"], 19043, friend_name)
            if not firends_online[friend_name]["oline"]:
                messagebox.showerror("错误", "好友不在线")
                self.chat_title.config(text=f"{friend_name} (离线)")
                self.chat_text.config(state=NORMAL) # pyright: ignore[reportArgumentType]
                self.chat_text.delete(1.0, END)
                self.chat_text.config(state=DISABLED) # pyright: ignore[reportArgumentType]
                for msg in connect.chat_record[friend_name]:
                    self.display_message(msg)
                return
            self.chat_title.config(text=f"{friend_name}")
            self.chat_text.config(state=NORMAL) # pyright: ignore[reportArgumentType]
            self.chat_text.delete(1.0, END)
            self.chat_text.config(state=DISABLED) # pyright: ignore[reportArgumentType]
            for msg in connect.chat_record[friend_name]:
                self.display_message(msg)
    
    def update_friend_status(self, friend_name, status):
        """
        更新指定好友的状态
        :param friend_name: 好友名称
        :param status: 新状态，如 "在线"、"离线" 等
        """
        # 遍历所有项，找到匹配的好友并更新状态
        for item in self.friend_listbox.get_children():
            if self.friend_listbox.item(item, "text") == friend_name:
                self.friend_listbox.item(item, values=(status,))
                break
    
    def send_message(self):
        """发送消息"""
        message = self.message_input.get(1.0, END).strip()
        if message:
            selection = self.friend_listbox.selection()
            if not selection:
                messagebox.showerror("错误", "请先选择一个好友")
                return
            this_friend = None
            for key in connect.friends.keys():
                if connect.friends[key]["name"] == self.friend_listbox.item(self.friend_listbox.selection()[0])["text"]:
                    this_friend = connect.friends[key]
            if not this_friend:
                messagebox.showerror("错误", "未找到好友信息")
                return
            try:
                message_bytes = message.encode('utf-8')
                connect.send_message(this_friend["user_id"], this_friend["public_key"], message)
                self.display_message(f"我: {message}")
                connect.chat_record[this_friend["name"]].append(f"我: {message}")
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
        for key in connect.friends.keys():
            if connect.friends[key]["name"] == self.friend_listbox.item(self.friend_listbox.selection()[0])["text"]:
                this_friend = connect.friends[key]
        if not this_friend:
            messagebox.showerror("错误", "未找到好友信息")
            return
        file_path = filedialog.askopenfilename(title="请选择文件:", filetypes=[("所有文件", "*.*")])
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    file_data = base64.b64encode(f.read()).decode('utf-8')
                message = f"{file_data} card(file) {os.path.basename(file_path)}"
                connect.send_message(this_friend["user_id"], this_friend["public_key"], message)
                self.display_card("我: "+message)
                connect.chat_record[this_friend["name"]].append("我: "+message)
            except MemoryError:
                messagebox.showerror("发送失败", f"文件过大，不建议使用OleanderChat发送大文件，建议使用带密码的压缩包上传至网盘后使用OleanderChat分享链接")
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

def main():
    for name in firends_online.keys():
        friend = firends_online[name]
        user_id = friend["user_id"]
        if not friend["host"]:
            try:
                url = f"https://www.123h.top/ipv6_query.php?uuid={user_id}"
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
            firends_online[name]["host"] = host
        if not firends_online[name]["oline"]:
            firends_online[name]["oline"] = send_heartbeat(firends_online[name]["host"], 19043, name)
    try:
        # 使用非阻塞方式尝试获取消息，设置超时为0
        message = message_queue.get_nowait()
        if message:
            # 检查connect.chat_record中是否有该好友的记录，如果没有则创建
            if message["name"] not in connect.chat_record:
                connect.chat_record[message["name"]] = []
            
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
                                    connect.chat_record[message["name"]].append(f"{message['name']}: {full_message}")
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
                            connect.chat_record[message["name"]].append(f"{message['name']}: {message['message']}")
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
    server_thread_Peer = threading.Thread(target=Peer_server, args=("::", 19043, stop_event), daemon=True)
    server_thread_Peer.start()

    # 主线程从队列中获取消息并处理
    app = ttk.Window(themename="cosmo")
    ui = WeChatUI(app)
    app.after(100, main)
    app.mainloop()
    stop_event.set()
    server_thread.join(timeout=1)
    server_thread_Peer.join(timeout=1)
    sys.exit()