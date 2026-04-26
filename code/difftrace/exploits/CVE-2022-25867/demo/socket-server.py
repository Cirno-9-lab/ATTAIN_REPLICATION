import socketio
import eventlet
from flask import Flask

sio = socketio.Server(cors_allowed_origins="*")
app = Flask(__name__)
app.wsgi_app = socketio.WSGIApp(sio, app.wsgi_app)

# 连接事件
@sio.event
def connect(sid, environ):
    print("Client connected:", sid)

# 所有事件监听
@sio.on("*")
def catch_all(event, sid, data):
    print(f"Received event '{event}' with data: {data}")

# 启动服务
if __name__ == '__main__':
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', 8081)), app)
