import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import json
import socket
import threading
import time
import uuid
from datetime import datetime

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("聊天程序")
        self.root.geometry("1200x800")
        
        # 设置主题样式
        style = ttk.Style()
        style.configure("Chat.TFrame", background="#f0f0f0")
        style.configure("Header.TLabel", font=("微软雅黑", 12, "bold"))
        style.configure("Peer.TFrame", relief="solid", borderwidth=1)
        
        # 网络设置
        self.DEFAULT_UDP_PORT = 8859
        self.BROADCAST_PORT = 8850
        self.UDP_PORT = self.DEFAULT_UDP_PORT
        self.socket = None
        self.broadcast_socket = None
        self.is_online = False
        self.hostname = socket.gethostname()
        self.local_ip = self.get_local_ip()
        self.uuid = self.generate_uuid()
        self.peers = {}  # 存储对端信息
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10", style="Chat.TFrame")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # 创建设置面板
        self.create_settings_panel()
        
        # 左侧面板（对端列表）
        self.create_left_panel()
        
        # 右侧面板（聊天区域）
        self.create_right_panel()
        
        # 绑定回车键发送消息
        self.input_field.bind('<Return>', lambda e: self.send_message())
    
    def generate_uuid(self):
        try:
            # 使用启动时间生成UUID
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(datetime.now().timestamp())))
        except Exception as e:
            print(f"无法生成UUID: {e}")
            # 如果生成失败，使用随机UUID
            return str(uuid.uuid4())
    
    def get_local_ip(self):
        try:
            # 创建一个UDP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # 连接一个外部地址（不需要真实连接）
            s.connect(('8.8.8.8', 80))
            # 获取本地IP
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            # 如果上述方法失败，尝试获取所有网络接口
            try:
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                return ip
            except Exception:
                return '127.0.0.1'
    
    def create_settings_panel(self):
        # 设置面板
        self.settings_frame = ttk.LabelFrame(self.main_frame, text="本机设置", padding="5")
        self.settings_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # 本机信息
        host_info = ttk.Frame(self.settings_frame)
        host_info.pack(fill=tk.X, pady=5)
        
        ttk.Label(host_info, text="本机名：").pack(side=tk.LEFT)
        ttk.Label(host_info, text=self.hostname).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(host_info, text="UUID：").pack(side=tk.LEFT)
        ttk.Label(host_info, text=self.uuid[:8]).pack(side=tk.LEFT)  # 只显示UUID的前8位
        
        # 端口设置
        port_frame = ttk.Frame(self.settings_frame)
        port_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(port_frame, text="UDP端口：").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(port_frame, width=10)
        self.port_entry.insert(0, str(self.DEFAULT_UDP_PORT))
        self.port_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # 按钮区域
        button_frame = ttk.Frame(self.settings_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        self.online_button = ttk.Button(button_frame, text="上线", command=self.go_online)
        self.online_button.pack(side=tk.LEFT, padx=5)
        
        self.refresh_button = ttk.Button(button_frame, text="刷新", command=self.refresh_peers)
        self.refresh_button.pack(side=tk.LEFT, padx=5)
        
        self.add_contact_button = ttk.Button(button_frame, text="添加联系人", command=self.show_add_contact_dialog)
        self.add_contact_button.pack(side=tk.LEFT, padx=5)
        
        self.delete_contact_button = ttk.Button(button_frame, text="删除联系人", command=self.delete_selected_contact)
        self.delete_contact_button.pack(side=tk.LEFT, padx=5)
    
    def create_left_panel(self):
        self.left_panel = ttk.Frame(self.main_frame, style="Peer.TFrame")
        self.left_panel.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        
        # 对端列表标题
        self.peers_header = ttk.Label(self.left_panel, text="通信列表", style="Header.TLabel")
        self.peers_header.pack(fill=tk.X, padx=5, pady=5)
        
        # 对端列表
        columns = ('hostname', 'ip', 'port', 'uuid')
        self.peers_list = ttk.Treeview(self.left_panel, columns=columns, height=20, selectmode='extended', show='tree headings')
        
        # 设置列标题
        self.peers_list.heading('hostname', text='主机名')
        self.peers_list.heading('ip', text='IP地址')
        self.peers_list.heading('port', text='端口')
        self.peers_list.heading('uuid', text='UUID')
        
        # 设置列宽度
        self.peers_list.column('hostname', width=100)
        self.peers_list.column('ip', width=120)
        self.peers_list.column('port', width=60)
        self.peers_list.column('uuid', width=80)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(self.left_panel, orient="vertical", command=self.peers_list.yview)
        self.peers_list.configure(yscrollcommand=scrollbar.set)
        
        # 使用grid布局管理器
        self.peers_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # 绑定选择事件
        self.peers_list.bind('<<TreeviewSelect>>', self.on_select)
        
        # 创建复选框图片
        self.checked_img = tk.PhotoImage(width=16, height=16)
        self.unchecked_img = tk.PhotoImage(width=16, height=16)
        self.checked_img.put(('black',), to=(3, 7, 12, 8))
        self.checked_img.put(('black',), to=(3, 8, 12, 9))
        self.checked_img.put(('black',), to=(3, 9, 12, 10))
        self.checked_img.put(('black',), to=(3, 10, 12, 11))
        
        # 存储选中状态
        self.checked_items = set()
    
    def on_select(self, event):
        # 处理选择事件
        item = self.peers_list.selection()
        if item:
            if item[0] in self.checked_items:
                self.checked_items.remove(item[0])
                self.peers_list.item(item[0], image=self.unchecked_img)
            else:
                self.checked_items.add(item[0])
                self.peers_list.item(item[0], image=self.checked_img)
    
    def delete_selected_contact(self):
        selected = self.peers_list.selection()
        if not selected:
            messagebox.showwarning("提示", "请选择要删除的联系人")
            return
            
        if messagebox.askyesno("确认", "确定要删除选中的联系人吗？"):
            for peer_id in selected:
                self.peers_list.delete(peer_id)
                if peer_id in self.peers:
                    del self.peers[peer_id]
    
    def refresh_peers(self):
        if not self.is_online:
            messagebox.showwarning("提示", "请先上线！")
            return
        self.broadcast_presence(force=True)
    
    def go_online(self):
        if self.is_online:
            try:
                if self.socket:
                    self.socket.close()
                if self.broadcast_socket:
                    self.broadcast_socket.close()
            except:
                pass
            self.socket = None
            self.broadcast_socket = None
            self.is_online = False
            self.online_button.config(text="上线")
            self.port_entry.config(state='normal')
            return
        
        try:
            port = int(self.port_entry.get())
            if port < 1024 or port > 65535:
                raise ValueError("端口号必须在1024-65535之间")
            
            # 创建消息socket
            self.UDP_PORT = port
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('0.0.0.0', self.UDP_PORT))
            
            # 创建广播socket
            self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.broadcast_socket.bind(('0.0.0.0', self.BROADCAST_PORT))
            
            self.is_online = True
            self.online_button.config(text="下线")
            self.port_entry.config(state='disabled')
            
            # 启动网络线程
            self.start_network_threads()
            
            messagebox.showinfo("提示", "上线成功！")
            
        except Exception as e:
            messagebox.showerror("错误", f"上线失败: {str(e)}")
            self.is_online = False
    
    def show_add_contact_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("添加联系人")
        dialog.geometry("300x200")
        dialog.transient(self.root)
        
        ttk.Label(dialog, text="主机名:").grid(row=0, column=0, padx=5, pady=5)
        hostname_entry = ttk.Entry(dialog)
        hostname_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="IP地址:").grid(row=1, column=0, padx=5, pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="端口:").grid(row=2, column=0, padx=5, pady=5)
        port_entry = ttk.Entry(dialog)
        port_entry.insert(0, str(self.DEFAULT_UDP_PORT))
        port_entry.grid(row=2, column=1, padx=5, pady=5)
        
        def add_contact():
            try:
                hostname = hostname_entry.get().strip()
                ip = ip_entry.get().strip()
                port = int(port_entry.get().strip())
                
                if not hostname or not ip:
                    raise ValueError("主机名和IP地址不能为空")
                
                if port < 1024 or port > 65535:
                    raise ValueError("端口号必须在1024-65535之间")
                
                peer_id = f"{hostname}_{ip}"
                peer_info = {
                    'hostname': hostname,
                    'ip': ip,
                    'port': port,
                    'uuid': str(uuid.uuid4())  # 为手动添加的联系人生成随机UUID
                }
                
                if peer_id not in self.peers:
                    self.peers[peer_id] = peer_info
                    self.peers_list.insert('', 'end', peer_id, 
                        values=(hostname, ip, port, peer_info['uuid'][:8]),
                        image=self.unchecked_img)  # 添加未选中的复选框图片
                    dialog.destroy()
                else:
                    messagebox.showwarning("警告", "该联系人已存在！")
                    
            except Exception as e:
                messagebox.showerror("错误", str(e))
        
        ttk.Button(dialog, text="添加", command=add_contact).grid(row=3, column=0, columnspan=2, pady=20)
    
    def send_message(self):
        if not self.is_online:
            messagebox.showwarning("提示", "请先上线！")
            return
            
        message = self.input_field.get().strip()
        if not message:
            return
            
        selected_peers = self.checked_items  # 使用选中的项目而不是selection
        if not selected_peers:
            messagebox.showwarning("提示", "请选择至少一个接收方")
            return
                
        message_data = {
            'type': 'message',
            'from': self.hostname,
            'content': message,
            'timestamp': datetime.now().timestamp()
        }
        
        for peer_id in selected_peers:
            peer = self.peers[peer_id]
            try:
                self.socket.sendto(json.dumps(message_data).encode(), (peer['ip'], peer['port']))
            except Exception as e:
                messagebox.showerror("发送失败", f"发送消息到 {peer['hostname']} 失败: {str(e)}")
        
        self.update_chat_display(message_data, is_self=True)
        self.input_field.delete(0, tk.END)
    
    def send_file(self):
        if not self.is_online:
            messagebox.showwarning("提示", "请先上线！")
            return
            
        selected_peers = self.peers_list.selection()
        if not selected_peers:
            messagebox.showwarning("提示", "请选择至少一个接收方")
            return
            
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
            
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        # 发送文件信息
        file_info = {
            'type': 'file',
            'from': self.hostname,
            'content': {
                'filename': file_name,
                'filesize': file_size
            },
            'timestamp': datetime.now().timestamp()
        }
        
        for peer_id in selected_peers:
            peer = self.peers[peer_id]
            try:
                # 发送文件信息
                self.socket.sendto(json.dumps(file_info).encode(), (peer['ip'], peer['port']))
                time.sleep(0.1)  # 等待接收方准备好
                
                # 开始发送文件内容
                self.progress_label.config(text=f"正在发送: {file_name}")
                self.progress['value'] = 0
                
                with open(file_path, 'rb') as f:
                    sent_size = 0
                    chunk_size = 8192  # 8KB chunks
                    
                    while sent_size < file_size:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                            
                        self.socket.sendto(chunk, (peer['ip'], peer['port']))
                        sent_size += len(chunk)
                        progress = (sent_size / file_size) * 100
                        self.progress['value'] = progress
                        self.root.update()
                        time.sleep(0.001)  # 防止发送过快
                
                self.progress['value'] = 100
                self.progress_label.config(text=f"文件发送完成: {file_name}")
                self.update_chat_display({
                    'from': self.hostname,
                    'content': f"文件 {file_name} 发送完成"
                }, is_self=True)
                
            except Exception as e:
                messagebox.showerror("发送失败", f"发送文件到 {peer['hostname']} 失败: {str(e)}")
                self.progress_label.config(text="文件发送失败")
                
            finally:
                self.root.after(2000, lambda: self.progress_label.config(text=""))
                self.root.after(2000, lambda: self.progress.configure(value=0))
    
    def update_chat_display(self, message, is_self=False):
        self.chat_display.config(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = "你" if is_self else message.get('from', 'Unknown')
        self.chat_display.insert(tk.END, f"[{timestamp}] {prefix}: {message.get('content', '')}\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')
    
    def handle_file(self, message, addr):
        content = message['content']
        filename = content['filename']
        filesize = content['filesize']
        sender = message.get('from', addr[0])
        
        # 创建接收目录
        save_dir = os.path.join(os.path.expanduser("~"), "Downloads", "ChatFiles")
        os.makedirs(save_dir, exist_ok=True)
        
        save_path = os.path.join(save_dir, filename)
        
        self.update_chat_display({
            'from': sender,
            'content': f"正在接收文件: {filename} ({filesize} 字节)"
        })
        
        # 开始接收文件内容
        try:
            with open(save_path, 'wb') as f:
                received_size = 0
                self.progress_label.config(text=f"正在接收: {filename}")
                
                while received_size < filesize:
                    chunk, _ = self.socket.recvfrom(8192)
                    if not chunk:
                        break
                        
                    f.write(chunk)
                    received_size += len(chunk)
                    progress = (received_size / filesize) * 100
                    self.progress['value'] = progress
                    self.root.update()
                
                self.progress['value'] = 100
                self.progress_label.config(text=f"文件接收完成: {filename}")
                self.update_chat_display({
                    'from': sender,
                    'content': f"文件 {filename} 接收完成，保存在: {save_path}"
                })
                
        except Exception as e:
            messagebox.showerror("接收失败", f"接收文件 {filename} 失败: {str(e)}")
            self.progress_label.config(text="文件接收失败")
            if os.path.exists(save_path):
                os.remove(save_path)
                
        finally:
            self.root.after(2000, lambda: self.progress_label.config(text=""))
            self.root.after(2000, lambda: self.progress.configure(value=0))
    
    def handle_message(self, message, addr):
        self.update_chat_display(message)
    
    def handle_broadcast(self, message, addr):
        content = message['content']
        if content['uuid'] == self.uuid:
            return  # 忽略自己的广播
            
        peer_id = f"{content['hostname']}_{content['ip']}"
        if peer_id not in self.peers:
            self.peers[peer_id] = content
            self.peers_list.insert('', 'end', peer_id, 
                values=(content['hostname'], content['ip'], 
                       content['port'], content['uuid'][:8]),
                image=self.unchecked_img)  # 添加未选中的复选框图片
    
    def broadcast_presence(self, force=False):
        if not self.is_online:
            return
            
        message = {
            'type': 'broadcast',
            'content': {
                'ip': self.local_ip,
                'port': self.UDP_PORT,
                'hostname': self.hostname,
                'uuid': self.uuid
            }
        }
        
        try:
            self.broadcast_socket.sendto(json.dumps(message).encode(), ('<broadcast>', self.BROADCAST_PORT))
            if force:
                # 强制刷新时多发送几次
                time.sleep(0.1)
                self.broadcast_socket.sendto(json.dumps(message).encode(), ('<broadcast>', self.BROADCAST_PORT))
        except Exception as e:
            print(f"广播错误: {e}")
        
        # 定期重新广播
        self.root.after(10000, self.broadcast_presence)
    
    def start_network_threads(self):
        # 启动消息接收线程
        message_thread = threading.Thread(target=self.receive_messages, daemon=True)
        message_thread.start()
        
        # 启动广播接收线程
        broadcast_thread = threading.Thread(target=self.receive_broadcast, daemon=True)
        broadcast_thread.start()
        
        # 发送广播
        self.broadcast_presence()
    
    def receive_broadcast(self):
        while self.is_online:
            try:
                data, addr = self.broadcast_socket.recvfrom(65535)
                message = json.loads(data.decode())
                if message['type'] == 'broadcast':
                    self.handle_broadcast(message, addr)
            except Exception as e:
                if self.is_online:  # 只在在线状态下打印错误
                    print(f"接收广播错误: {e}")
    
    def receive_messages(self):
        while True:
            try:
                data, addr = self.socket.recvfrom(65535)
                try:
                    message = json.loads(data.decode())
                    if message['type'] == 'broadcast':
                        self.handle_broadcast(message, addr)
                    elif message['type'] == 'message':
                        self.handle_message(message, addr)
                    elif message['type'] == 'file':
                        self.handle_file(message, addr)
                except json.JSONDecodeError:
                    # 如果不是JSON格式，认为是文件内容
                    continue
            except Exception as e:
                print(f"接收消息错误: {e}")

    def create_right_panel(self):
        # 右侧面板（聊天区域）
        self.right_panel = ttk.Frame(self.main_frame)
        self.right_panel.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 聊天显示区域
        self.chat_display = tk.Text(self.right_panel, height=25, width=70, font=("微软雅黑", 10))
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.chat_display.config(state='disabled')
        
        # 创建滚动条
        scrollbar = ttk.Scrollbar(self.chat_display.master, orient='vertical', command=self.chat_display.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_display['yscrollcommand'] = scrollbar.set
        
        # 底部控制面板
        self.control_panel = ttk.Frame(self.right_panel)
        self.control_panel.pack(fill=tk.X, pady=(0, 5))
        
        # 输入框和按钮
        self.input_frame = ttk.Frame(self.control_panel)
        self.input_frame.pack(fill=tk.X)
        
        self.input_field = ttk.Entry(self.input_frame, font=("微软雅黑", 10))
        self.input_field.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.send_button = ttk.Button(self.input_frame, text="发送", command=self.send_message, width=10)
        self.send_button.pack(side=tk.LEFT, padx=5)
        
        self.file_button = ttk.Button(self.input_frame, text="发送文件", command=self.send_file, width=10)
        self.file_button.pack(side=tk.LEFT)
        
        # 进度条框架
        self.progress_frame = ttk.Frame(self.control_panel)
        self.progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(self.progress_frame, length=300, mode='determinate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
