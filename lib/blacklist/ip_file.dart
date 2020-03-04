import 'dart:convert';
import 'dart:io';

import 'package:botblocker/util/logging.dart';

class BanIPInfo {
  final String ip;
  String reason;
  BanIPInfo(this.ip, {this.reason});

  String toJSON() {
    return json.encode(toMap());
  }

  Map<String, dynamic> toMap() {
    return {'ip': ip, 'reason': reason};
  }

  static BanIPInfo fromMap(Map<String, dynamic> data) {
    if (!data.containsKey('ip')) {
      throw "ip required";
    }
    BanIPInfo info = BanIPInfo(data['ip']);

    if (data.containsKey('reason')) {
      info.reason = data['reason'];
    }
    return info;
  }

  static fromJSON(String jsonData) {
    Map<String, dynamic> mapped = json.decode(jsonData);
    return fromMap(mapped);
  }
}

class IPFileSaver {
  final String savePath;
  IPFileSaver({this.savePath = ".data/block.json"});

  storeUnban(String ip) async {
    String filePath = "$savePath";

    //creates dir and file if not exists
    File file = new File(filePath);
    if (!await file.exists()) {
      return;
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");
    List<String> newLines = [];
    bool bFoundLine = false;

    for (int c = 1; c < lines.length; c++) {
      String line = lines[c];
      BanIPInfo info = BanIPInfo.fromJSON(line);
      if (info.ip == ip) {
        logger.info("found, unbanning ip $ip");
        bFoundLine = true;
      } else {
        newLines.add(line); //save non unban
      }
    }

    if (!bFoundLine) {
      return; // not found
    }

    file.writeAsStringSync(newLines.join("\n"));
  }

  storeBan(String ip, DateTime date, {String reason = ''}) async {
    //date specific path
    String filePath = "$savePath";

    //creates dir and file if not exists
    File file = new File(filePath);
    if (!await file.exists()) {
      await load();
      file = new File(filePath);
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");
    bool bFoundLine = false;
    for (int c = 1; c < lines.length; c++) {
      String line = lines[c];
      BanIPInfo info = BanIPInfo.fromJSON(line);
      if (info.ip == ip) {
        logger.info("found banip $ip");
        // lines[c] = info.toJSON();
        bFoundLine = true;
        break;
      }
    }

    if (!bFoundLine) {
      BanIPInfo info = BanIPInfo(ip, reason: reason);
      logger.info("new ip $ip");
      lines.add(info.toJSON());

      file.writeAsStringSync(lines.join("\n"));
    }
  }

  Future<List<BanIPInfo>> load() async {
    String filePath = "$savePath";
    File file = new File(filePath);
    if (!await file.exists()) {
      file.createSync(recursive: true);
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");

    List<BanIPInfo> ips = [];
    if (lines.length == 1 && lines[0].trim() == '') {
      return ips;
    }
    for (int c = 0; c < lines.length; c++) {
      String line = lines[c];
      BanIPInfo info = BanIPInfo.fromJSON(line);
      ips.add(info);
    }

    return ips;
  }
}
