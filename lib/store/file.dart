import 'dart:convert';
import 'dart:io';

class AccessClientHandler {
  Map<String, dynamic> logs;
  String ip;
  String configPath;

  AccessClientHandler(Map<String, dynamic> this.logs, String this.ip,
      {String this.configPath = ""}) {
    loadConfig();
  }
  /// store count of access
  addAccessCount(String file, String url, { int count = 1}) {
    if(! logs.containsKey(file)) {
      this.resetAccessCount(file);
    }
    logs[file]['count'] += 1;
    return logs[file];
  }

  resetAccessCount(String file) {
    logs[file] = { 'count': 0 };
  }

  save() async {
    Map<String, dynamic> res = {
      'log': logs,
      'ip': ip,
    };
    var file = File(pathToConfig);
    String content = await json.encode(res);
    return file.writeAsStringSync(content);
  }

  load(String ip) {
    var cli = AccessClientHandler({}, ip);
    return cli;
  }

  get pathToConfig() {
    return
        configPath.isEmpty ? "" : configPath + '/' + "ip-" + ip + '.json';
  }

  loadConfig() async {
    var file = File(pathToConfig);
    if (!await file.exists()) {
      return;
    }

    String content = await file.readAsString();
    Map<String, dynamic> data = json.decode(content);
    logs = {};
    if (data.containsKey('log')) {
      logs = data['log'];
    }
  }

}
