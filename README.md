# Python UDP聊天程序

这是一个基于Python开发的UDP聊天程序，支持多人聊天、文件传输和自动发现功能。

## 功能特点

1. 图形化界面
   - 美观、大方的用户界面
   - 支持多人聊天
   - 实时显示在线用户
   - 支持文件传输进度显示

2. 网络通信
   - 基于UDP协议
   - 支持自动发现功能
   - 支持多IP地址绑定
   - 可配置的端口设置

3. 文件传输
   - 支持任意类型文件的发送和接收
   - 实时进度条显示
   - 自动保存接收文件

4. 通信控制
   - 增加一个站id，这个站ID用于标记不同站间不能进行通信，即便能够收到对方的消息也不进行处理


## 技术规范

### 界面要求

1. 通信区域
   - 消息输入框
   - 聊天内容显示区域
   - 发送按钮
   - 文件传输进度条

2. 用户信息区域
   - 显示本机名称
   - 显示本机所有IP地址
   - UDP端口设置（默认8859）
   - 在线状态控制
   - 增加站ID，可以用字符串表示，也可以自定义，默认值"default-station"

3. 联系人管理
   - 显示在线用户列表
   - 支持多选发送
   - 支持手动添加/删除联系人
   - 支持联系人刷新

### 通信协议

使用JSON格式进行消息交换，支持以下类型：

1. 文本消息 (type: message)
   ```json
   {
       "type": "message",
       "content": "消息内容",
       "uuid": "发送者UUID"
   }
   ```

2. 文件传输 (type: file)
   ```json
   {
       "type": "file",
       "content": {
           "filename": "文件名",
           "filesize": 文件大小
       },
       "uuid": "发送者UUID"
   }
   ```

3. 广播消息 (type: broadcast)
   ```json
   {
       "type": "broadcast",
       "content": {
           "ip": "发送者IP",
           "port": 端口号,
           "hostname": "主机名",
           "uuid": "UUID"
       }
   }
   ```

### 网络配置

- 消息通信端口：默认UDP 8859（可修改）
- 广播监听端口：固定UDP 8850
- 支持绑定本机所有网络接口

## 工作流程

1. 启动流程
   - 程序启动后默认离线状态
   - 点击"上线"按钮后创建socket连接
   - 自动广播本机信息
   - 开始监听广播和消息

2. 用户发现
   - 自动接收并响应广播消息
   - 根据UUID过滤重复用户
   - 支持手动添加联系人
   - 支持刷新在线状态
   - 收到广播后，将对方加入本地列表，同时回复一个消息，告知对方本机在线，这个消息不在接收区显示

3. 消息通信
   - 支持选择多个接收者
   - 自动记录未知发送者
   - 显示发送和接收状态
   - 支持文件传输进度显示


## 开发说明

- 开发工具：Cursor IDE
- 开发方式：AI辅助开发
- 开发语言：Python
- 主要依赖：tkinter, socket, json

## 使用说明

1. 启动程序
   ```bash
   python src/main.py
   ```

2. 基本操作
   - 点击"上线"开始通信
   - 选择联系人后可发送消息
   - 点击"发送文件"选择要传输的文件
   - 点击"刷新"更新在线用户列表

3. 注意事项
   - 确保网络正常连接
   - 确保端口未被占用
   - 多个网卡时注意选择正确的IP地址
   - 大文件传输时请耐心等待

注：
    本项目使用cursor没事儿开发的，全程没看代码，只编辑README.md文件和进行输入执行命令
