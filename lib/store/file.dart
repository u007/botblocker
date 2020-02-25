import 'dart:convert';
import 'dart:io';

const int defaultMaxLog = 50;
const Duration defaultMaxDurationOfLog = Duration(hours: 3);

class AccessClientHandler {
  Map<String, dynamic> logs;
  String ip;
  String configPath;

  AccessClientHandler(Map<String, dynamic> this.logs, String this.ip,
      {String this.configPath = ""}) {
    loadConfig();
  }

  /// store count of access, returns the entry with:
  /// 'history' List<Map<String, dynamic>>'
  /// 'count' int
  addAccessCount(String file, String url,
      {DateTime accessTime, int count = 1}) {
    if (!logs.containsKey(file)) {
      this.resetAccessCount(file, url: url);
    }
    logs[file][url]['history'].add({'time': accessTime ?? new DateTime.now()});
    logs[file][url]['count'] += 1;
    return logs[file][url];
  }

  /// reset access
  resetAccessCount(String file, {String url: ''}) {
    List<Map<String, dynamic>> history = [];
    logs[file] = {};
    if (url.isNotEmpty) {
      logs[file][url] = {'count': 0, 'history': history};
    }
  }

  // trim access to reduce memory usage
  trim({String file: '', Duration maxDuration: defaultMaxDurationOfLog}) {
    /// based on 3h log only

    DateTime now = DateTime.now();
    DateTime fromDate = now.subtract(maxDuration);
    if (file.isNotEmpty) {
      logs[file].forEach((url, _) {
        //clean by date
        while (logs[file][url]['history'].length > 0) {
          String date = logs[file][url]['history'][0]['time'];
          DateTime tDate = DateTime.parse(date);
          if (tDate.isBefore(fromDate)) {
            print("removing history $tDate");
            logs[file][url]['history'].removeAt(0);
          } else {
            break;
          }
        } // reduce by time
        while (logs[file][url]['history'].length > defaultMaxLog) {
          logs[file][url]['history'].removeAt(0);
        } // reduce by length
        logs[file][url]['count'] = logs[file][url]['history'].length;
      }); //each url
      return;
    }

    //trim all files
    logs.forEach((String file, _) {
      logs[file].forEach((url, _) {
        //clean by date
        while (logs[file][url]['history'].length > 0) {
          String date = logs[file][url]['history'][0]['time'];
          DateTime tDate = DateTime.parse(date);
          if (tDate.isBefore(fromDate)) {
            print("removing history $tDate");
            logs[file][url]['history'].removeAt(0);
          } else {
            break;
          }
        } // reduce by time
        while (logs[file][url]['history'].length > defaultMaxLog) {
          logs[file][url]['history'].removeAt(0);
        } // reduce by length
        logs[file][url]['count'] = logs[file][url]['history'].length;
      }); //each url
    });
  }

  //persists log
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

  get pathToConfig {
    return configPath.isEmpty ? "" : configPath + '/' + "ip-" + ip + '.json';
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
