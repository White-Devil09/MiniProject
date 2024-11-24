import asyncio
import telnetlib3
import subprocess
import re
from flask import Flask, request, jsonify

# Global variables for telnet connection
telnet_reader = None
telnet_writer = None
loop = asyncio.get_event_loop()

# Loading auth token
with open('/home/bhanu/.emulator_console_auth_token') as token_file:
    adb_auth_token = token_file.read().strip()

# Getting port number of emulator
result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
lines = result.stdout.splitlines()
for line in lines:
    if 'emulator-' in line:
        match = re.search(r'emulator-(\d+)', line)
        if match:
            emulator_number = match.group(1)

host = 'localhost'
port = emulator_number

async def open_telnet_connection():
    global telnet_reader, telnet_writer
    telnet_reader, telnet_writer = await telnetlib3.open_connection(host, port)
    print("Telnet connection established")
    # Authenticate with the emulator
    telnet_writer.write(f'auth {adb_auth_token}\n')
    await telnet_writer.drain()
    response = await asyncio.wait_for(telnet_reader.read(1024), timeout=5)
    if "OK" not in response:
        raise RuntimeError("Failed to authenticate with the emulator")

async def send_telnet_command(command):
    global telnet_reader, telnet_writer
    if not telnet_writer:
        await open_telnet_connection()
    telnet_writer.write(command + '\n')
    await telnet_writer.drain()
    response = await asyncio.wait_for(telnet_reader.read(1024), timeout=5)
    return response

def send_telnet_command_sync(command):
    return loop.run_until_complete(send_telnet_command(command))

# Flask server setup
app = Flask(__name__)

with app.app_context():
    loop.run_until_complete(open_telnet_connection())

@app.route('/', methods=['POST'])
def webhook():
    if request.method == 'POST':
        data = request.json
        print("Received data:", data)
        try:
            response = send_telnet_command_sync(f'sms send {data["sender"]} {data["sms"]}')
            print("Telnet response:", response)
        except Exception as e:
            print("Error sending telnet command:", e)
            return jsonify({'status': 'error', 'message': str(e)}), 500
        return jsonify({'status': 'success', 'message': 'Data received'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
