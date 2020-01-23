import 'dart:convert';
import 'dart:io';

/// store
abstract class Store {}

class AccessClientHandler {
  List<String> logs;
  String ip;

  AccessClientHandler(List<String> logs, String ip}) {
    this.logs = logs;
    this.ip = ip;
    loadConfig();
  }

  loadConfig() async {
    String path = "ip-"+ip+'.json';
    var file = File(path);
    if (!await file.exists()) {
      return;
    }

    String content = await file.readAsString();
    Map<String,dynamic> data = json.decode(content);
    logs = [];
    if (data.containsKey('log')) {
      (data['log'] as List).forEach((String log) {
        logs.add(log);
      });
    }

  }

  save() {
    Map<String, dynamic> res = {
      'log': logs,
      'ip': ips,
    };
  }

  static load(String ip) {
    var cli  = AccessClientHandler([], ip );
    return cli;
  }
}
