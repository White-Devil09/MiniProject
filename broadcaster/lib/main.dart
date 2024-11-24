import 'package:flutter/material.dart';
import 'dart:async';
import 'package:permission_handler/permission_handler.dart';
import 'package:readsms/readsms.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _plugin = Readsms();
  String sms = '...';
  String sender = '...';
  String time = '...';
  String _message = ''; // Variable to hold the message

  final TextEditingController _ipController = TextEditingController();
  final TextEditingController _portController = TextEditingController();
  String? _serverIp;
  String? _serverPort;

  @override
  void initState() {
    super.initState();
    getPermission().then((value) {
      if (value) {
        _plugin.read();
        _plugin.smsStream.listen((event) {
          setState(() {
            sms = event.body;
            sender = event.sender;
            time = event.timeReceived.toString();
            _message = ''; // Clear message when a new SMS is received
          });
          _sendSmsDataToServer(sms, sender, time);
        });
      }
    });
  }

  Future<bool> getPermission() async {
    if (await Permission.sms.status == PermissionStatus.granted) {
      return true;
    } else {
      if (await Permission.sms.request() == PermissionStatus.granted) {
        return true;
      } else {
        return false;
      }
    }
  }

  void _setServerDetails(BuildContext context) {
    setState(() {
      _serverIp = _ipController.text.trim();
      _serverPort = _portController.text.trim();
    });

    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_serverIp!.isNotEmpty && _serverPort!.isNotEmpty) {
        setState(() {
          _message = 'Server details set to $_serverIp:$_serverPort';
        });
      } else {
        setState(() {
          _message = 'Please enter both IP and Port';
        });
      }
    });
  }

  Future<void> _sendSmsDataToServer(
      String sms, String sender, String time) async {
    if (_serverIp != null && _serverPort != null) {
      String url =
          'http://$_serverIp:$_serverPort/'; // Adjust the endpoint as needed
      try {
        final response = await http.post(
          Uri.parse(url),
          headers: {'Content-Type': 'application/json'},
          body: '{"sender": "$sender", "time": "$time", "sms": "$sms"}',
        );

        setState(() {
          if (response.statusCode == 200) {
            _message = 'SMS data sent successfully!';
          } else {
            _message =
                'Failed to send SMS data. Server responded with ${response.statusCode}.';
          }
        });
      } catch (e) {
        setState(() {
          _message = 'Error sending SMS data to server: $e';
        });
      }
    } else {
      setState(() {
        _message = 'Please set the server IP and Port first';
      });
    }
  }

  @override
  void dispose() {
    super.dispose();
    _plugin.dispose();
    _ipController.dispose();
    _portController.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('SMS Broadcaster'),
        ),
        body: Column(
          children: [
            Expanded(
              child: Center(
                child: Padding(
                  padding: const EdgeInsets.all(18.0),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      TextField(
                        controller: _ipController,
                        decoration: const InputDecoration(
                          labelText: 'Server IP',
                        ),
                      ),
                      TextField(
                        controller: _portController,
                        decoration: const InputDecoration(
                          labelText: 'Server Port',
                        ),
                        keyboardType: TextInputType.number,
                      ),
                      const SizedBox(height: 20),
                      ElevatedButton(
                        onPressed: () => _setServerDetails(context),
                        child: const Text('Set Server IP and Port'),
                      ),
                      const SizedBox(height: 20),
                      Text(
                        'Sms Sender: $sender',
                        style: const TextStyle(
                            fontSize: 20, fontWeight: FontWeight.bold),
                      ),
                      Text(
                        'Received time: $time',
                        style: const TextStyle(
                            fontSize: 15, fontWeight: FontWeight.bold),
                      ),
                      const SizedBox(height: 10),
                      Text('Sms content: $sms'),
                    ],
                  ),
                ),
              ),
            ),
            Container(
              color: Colors.blueGrey[50],
              padding: const EdgeInsets.all(8.0),
              child: Text(
                _message,
                style: const TextStyle(fontSize: 16, color: Colors.black),
                textAlign: TextAlign.center,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
