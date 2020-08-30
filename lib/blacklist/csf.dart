import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:botblocker/blacklist/ip_file.dart';
import 'package:process_run/which.dart';
import 'package:botblocker/util/date.dart';
import '../util/logging.dart';
import './abstract.dart';

/// Blacklist handling via CSF firewall
class CSFBlackList extends BlackListHandler {
  final String violationPath;
  IPFileSaver ipSaver;
  String csfPath = "";
  int version = 0;
  bool test = false;
  CSFBlackList(
      {this.violationPath = ".data/ip", this.csfPath = "", this.test = false}) {
    ipSaver = IPFileSaver();
  }

  resetIP(String ip, {String logName: null}) async {
    if (test) return;
    String filePath = "$violationPath/$ip.log";
    File file = new File(filePath);
    if (!file.existsSync()) {
      return;
    }

    if (logName == null) {
      file.deleteSync();
      return;
    }

    String content = file.readAsStringSync();
    List<String> newLines = [];
    List<String> lines = content.split("\n");
    for (int c = 1; c < lines.length; c++) {
      String line = lines[c];
      Map<String, dynamic> data = jsonDecode(line);
      ViolationInfo info = ViolationInfo()..fromMap(data);
      if (info.logName != logName) {
        newLines.add(line);
      }
    }

    file.writeAsStringSync(newLines.join("\n"));
  }

  storeAndBlockIP(String ip, DateTime date, String logName, String violatedPath,
      {String reason = ''}) async {
    if (!isBannedIP(ip)) {
      await banIP(ip, reason: reason);
    }

    return storeViolation(ip, date, logName, violatedPath);
  }

  // first line is json, second line onwards are access log
  Future<Map<String, dynamic>> loadIP(String ip) async {
    String filePath = "$violationPath/$ip.log";
    File file = new File(filePath);
    if (!file.existsSync()) {
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
    if (!file.existsSync()) {
      file.createSync(recursive: true);
      file.writeAsStringSync('{"count": 1, "v": 1}\n', mode: FileMode.append);
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");

    for (int c = 1; c < lines.length; c++) {
      String line = lines[c];
      if (line.trim().length == 0) {
        continue;
      }
      Map<String, dynamic> data = jsonDecode(line);
      ViolationInfo info = ViolationInfo()..fromMap(data);
      if (info.logName == logName && info.path == violatedPath) {
        return info;
      }
    }

    return ViolationInfo(logName: logName, path: violatedPath);
  }

  /* stores to .data/x.x.x.x.log with 
  * 1st line indicate configuration
  * second onwards lines indicate log file based violation and rules
  */
  storeViolation(String ip, DateTime date, String logName, String violatedPath,
      {count: 1}) async {
    //date specific path
    String filePath = "$violationPath/$ip.log";

    //creates dir and file if not exists
    File file = new File(filePath);
    if (!file.existsSync()) {
      await loadIP(ip); //create file
      file = new File(filePath);
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");
    bool bFoundLine = false;
    for (int c = 1; c < lines.length; c++) {
      String line = lines[c];
      if (line.trim() == '') {
        continue; //ignore empty line
      }
      Map<String, dynamic> data = jsonDecode(line);
      ViolationInfo info = ViolationInfo()..fromMap(data);
      if (info.logName == logName && info.path == violatedPath) {
        logger.fine("found violation $logName: $violatedPath, adding $date");
        info.addDate(date);
        logger.info(
            "found violation $logName: $violatedPath, count: ${info.count()}");
        lines[c] = info.toJSON();
        bFoundLine = true;
        break;
      }
    }

    if (!bFoundLine) {
      ViolationInfo info = ViolationInfo(logName: logName, path: violatedPath);
      info.addDate(date);
      logger.info(
          "new violation $logName: $violatedPath, count: ${info.count()}");
      lines.add(info.toJSON());
    }

    file.writeAsStringSync(lines.join("\n"));
  }

  unBanAll() async {
    List<BanIPInfo> list = await ipSaver.load();
    for (int c = 0; c < list.length; c++) {
      BanIPInfo ipInfo = list[c];
      await unBanIP(ipInfo.ip);
    }
  }

  unBanIP(String ip) async {
    if (await isWhiteListedIP(ip)) {
      throw "Is whitelisted ip $ip";
    }

    await ipSaver.storeUnban(ip);
    await csfRun(['-dr', ip]); //to remove from block csf -dr ip
  }

  banIP(String ip, {String reason = ''}) async {
    if (test) {
      return;
    }
    if (await isWhiteListedIP(ip)) {
      throw "Is whitelisted ip $ip";
    }

    await ipSaver.storeBan(ip, getNow(), reason: reason);
    await csfRun(['-d', ip, reason]); //to remove from block csf -dr ip
  }

  isBannedIP(String ip) async {
    if (test) {
      return false;
    }
    var res = await csfRun(['-g', ip]);
    if (res.indexOf('csf.allow:') >= 0) {
      logger.fine("is csf.allow $ip");
      return false;
    }

    if (res.indexOf('csf.deny:') >= 0) {
      logger.fine("is csf.deny $ip");
      return true;
    }

    return false;
  }

  isWhiteListedIP(String ip) async {
    if (test) {
      return false;
    }
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
    if (test) {
      throw "Is test, please do not run this in test";
    }
    Completer c = new Completer<String>();
    if (csfPath == "") {
      final filePath = File('/usr/sbin/csf');
      if (filePath.existsSync()) {
        csfPath = '/usr/sbin/csf';
      } else {
        csfPath = whichSync('csf');
        if (csfPath == null) {
          throw "Missing csf";
        }
      }
    }

    Process.run(csfPath, args).then((ProcessResult results) {
      // logger.fine(results.stdout);
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
    logger.fine("addDate $date");
    if (dates == null) {
      dates = [date];
    } else {
      dates.insert(0, date);
    }

    if (dates.length < 2) {
      return;
    }

    logger.fine("adddate cleanup ${dates.length}");
    //clean up
    dates.sort((a, b) => a.isAfter(b) ? 0 : 1);

    DateTime now = getNow();
    DateTime expiredTime = now.subtract(Duration(days: 2));
    int index = dates.length - 1;

    while (dates[index].isBefore(expiredTime)) {
      dates.removeAt(index);
      index = index - 1;
    }

    //clean up duplicate
    DateTime lastDate;
    for (int c = dates.length - 1; c >= 0; c--) {
      if (lastDate == null) {
        lastDate = dates[c];
        continue;
      }
      if (lastDate.isAtSameMomentAs(dates[c])) {
        logger.fine("removed duplicate ${c + 1} ${dates[c]}");
        dates.removeAt(c + 1);
      }
      lastDate = dates[c];
    }
    logger.fine("adddate after cleanup ${dates.length}");
  }

  countViolation(Duration duration) {
    if (dates == null) {
      return 0;
    }
    DateTime now = getNow();
    DateTime expiredTime = now.subtract(duration);
    int count = 0;
    //clean up

    for (int index = 0; index < dates.length; index++) {
      if (dates[index].isAfter(expiredTime)) {
        break;
      }
      count += 1;
    }

    return count;
  }

  Map<String, dynamic> toMap() {
    List<String> outDates = [];
    if (dates != null) {
      for (int c = 0; c < dates.length; c++) {
        outDates.add(utcTimeFormat(dates[c]));
      }
    }

    return {'log_name': logName, 'path': path, 'date': outDates};
  }

  String toJSON() {
    return json.encode(toMap());
  }

  String toString() {
    return toJSON();
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
