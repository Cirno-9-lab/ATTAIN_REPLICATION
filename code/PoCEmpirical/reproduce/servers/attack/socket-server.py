from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/')
def index():
    return 'Hello Socket.IO!'


@socketio.on('connect')
def handle_connect():
    print('客户端已连接')
    # 连接成功后发送 null 数据给客户端
    emit(None)  # 发送 null 数据

@socketio.on('message')
def handle_message(data):
    print('收到消息:', data)
    emit('response', {'data': '服务端收到消息'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8081, allow_unsafe_werkzeug=True)


# Flask==2.0.3
# Flask-SocketIO==4.3.1
# python-socketio==4.6.0
# python-engineio==3.13.2
# Werkzeug==2.0.3