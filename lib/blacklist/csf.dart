import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:intl/intl.dart';
import 'package:process_run/which.dart';
import 'package:synagie5/util/date.dart';
import '../util/logging.dart';
import './abstract.dart';

/// Blacklist handling via CSF firewall
class CSFBlackList extends BlackListHandler {
  final String violationPath;
  String csfPath = "";
  int version = 0;
  CSFBlackList({this.violationPath = ".data/ip", this.csfPath = ""});

  storeAndBlockIP(
      String ip, DateTime date, String logName, String violatedPath) async {
    if (!isBannedIP(ip)) {
      await banIP(ip);
    }

    return storeViolation(ip, date, logName, violatedPath);
  }

  // first line is json, second line onwards are access log
  Future<Map<String, dynamic>> loadIP(String ip) async {
    String filePath = "$violationPath/$ip.log";
    File file = new File(filePath);
    if (!await file.exists()) {
      file.createSync(recursive: true);
      file.writeAsStringSync('{"count": 1, "v": 1}\n', mode: FileMode.append);
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");
    Map<String, dynamic> data = jsonDecode(lines[0]);
    version = data['v'];

    //TODO based on v (version), change format to new version
    return data;
  }

  Future<ViolationInfo> loadIPViolation(
      String ip, String logName, String violatedPath) async {
    String filePath = "$violationPath/$ip.log";
    File file = new File(filePath);
    if (!await file.exists()) {
      file.createSync(recursive: true);
      file.writeAsStringSync('{"count": 1, "v": 1}\n', mode: FileMode.append);
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");

    for (int c = 1; c < lines.length; c++) {
      String line = lines[c];
      Map<String, dynamic> data = jsonDecode(line);
      return ViolationInfo()..fromMap(data);
    }

    return ViolationInfo(logName: logName, path: violatedPath);
  }

  storeViolation(String ip, DateTime date, String logName, String violatedPath,
      {count: 1}) async {
    //date specific path
    String datePath = DateFormat("yyyy-MM-dd").format(date);
    String filePath = "$violationPath/$datePath/$ip.log";

    //creates dir and file if not exists
    File file = new File(filePath);
    if (!await file.exists()) {
      await loadIP(ip); //create file
      file = new File(filePath);
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");
    bool bFoundLine = false;
    for (int c = 1; c < lines.length; c++) {
      String line = lines[c];
      Map<String, dynamic> data = jsonDecode(line);
      ViolationInfo info = ViolationInfo()..fromMap(data);
      if (info.logName == logName && info.path == violatedPath) {
        info.addDate(date);
        logger.info(
            "found violation $logName: $violatedPath, count: ${info.count}");
        lines[c] = info.toJSON();
        bFoundLine = true;
        break;
      }
    }

    if (!bFoundLine) {
      ViolationInfo info = ViolationInfo(logName: logName, path: violatedPath);
      info.addDate(date);
      logger
          .info("new violation $logName: $violatedPath, count: ${info.count}");
      lines.add(info.toJSON());
    }

    file.writeAsStringSync(lines.join("\n"));
  }

  banIP(String ip) async {
    if (await isWhiteListedIP(ip)) {
      throw "Is whitelisted ip $ip";
    }
    await csfRun(['-d', ip]); //to remove from block csf -dr ip
  }

  isBannedIP(String ip) async {
    var res = await csfRun(['-g', ip]);
    if (res.indexOf('csf.allow:') >= 0) {
      logger.fine("is csf.allow $ip");
      return false;
    }

    if (res.indexOf('csf.deny:') >= 0) {
      logger.fine("is csf.deny $ip");
      return true;
    }

    return true;
  }

  isWhiteListedIP(String ip) async {
    var res = await csfRun(['-g', ip]);
    if (res.indexOf('csf.allow:') >= 0) {
      logger.fine("is csf.allow $ip");
      return true;
    }

    if (res.indexOf('csf.ignore:') >= 0) {
      logger.fine("is csf.ignore $ip");
      return true;
    }

    return false;
  }

  Future<String> csfRun(
    List<String> args,
  ) async {
    Completer c = new Completer();
    if (csfPath == "") {
      csfPath = whichSync('csf');
      if (csfPath == null) {
        throw "Missing csf";
      }
    }

    Process.run(csfPath, args).then((ProcessResult results) {
      logger.fine(results.stdout);
      c.complete(results.stdout);
    });
    return c.future;
  }
}

class ViolationInfo {
  String logName;
  String path;
  List<DateTime> dates;

  ViolationInfo({this.logName, this.path, this.dates}) {}

  addDate(DateTime date) {
    dates.insert(0, date);
    DateTime now = getNow();
    DateTime expiredTime = now.subtract(Duration(days: 2));
    int index = 0;
    //clean up
    while (dates[index].isAfter(expiredTime)) {
      dates.removeAt(index);
    }
  }

  countViolation(Duration duration) {
    DateTime now = getNow();
    DateTime expiredTime = now.subtract(duration);
    int index = 0;
    int count = 0;
    //clean up
    while (dates[index].isBefore(expiredTime)) {
      count += 1;
    }

    return count;
  }

  Map<String, dynamic> toMap() {
    List<String> outDates = [];
    for (int c = 0; c < dates.length; c++) {
      outDates.add(utcTimeFormat(dates[c]));
    }
    return {'log_name': logName, 'path': path, 'date': outDates};
  }

  String toJSON() {
    return json.encode(toMap());
  }

  int count() {
    return dates.length;
  }

  fromMap(Map<String, dynamic> mapped) {
    logName = mapped['log_name'];
    path = mapped['path'];
    dates = [];
    mapped['date'].forEach((var dateStr) {
      DateTime theDate = parseUTCTimeString(dateStr);
      dates.add(theDate);
    });
  }
}
