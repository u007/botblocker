import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:intl/intl.dart';
import 'package:process_run/which.dart';
import '../util/logging.dart';
import './abstract.dart';

/// Blacklist handling via CSF firewall
class CSFBlackList extends BlackListHandler {
  final String violationPath;
  String csfPath = "";

  CSFBlackList({this.violationPath = ".data/ip", this.csfPath = ""});

  storeAndBlockIP(String ip, DateTime date, String violatedPath) async {
    if (!isBannedIP(ip)) {
      await banIP(ip);
    }

    return storeViolation(ip, date, violatedPath);
  }

  loadIP(String ip) async {
    String filePath = "$violationPath/$ip.log";
    File file = new File(filePath);
    if (!await file.exists()) {
      file.createSync(recursive: true);
      file.writeAsStringSync('{"count": 1, "v": 1}\n', mode: FileMode.append);
    }

    String content = file.readAsStringSync();
    List<String> lines = content.split("\n");
    Map<String, dynamic> data = jsonDecode(lines[0]);
    return data;
  }

  storeViolation(String ip, DateTime date, String violatedPath) async {
    //date specific path
    String datePath = DateFormat("yyyy-MM-dd").format(date);
    String filePath = "$violationPath/$datePath/$ip.log";

    //creates dir and file if not exists
    File file = new File(filePath);
    if (!await file.exists()) {
      file.createSync(recursive: true);
    }
    file.writeAsStringSync(violatedPath + "\n", mode: FileMode.append);

    String isoDateTime = date.toIso8601String();
    // write not general path for entire ip
    // store first line as json
    filePath = "$violationPath/$ip.log";
    file = new File(filePath);
    if (!await file.exists()) {
      file.createSync(recursive: true);
      file.writeAsStringSync('{"count": 1}\n', mode: FileMode.append);
    }

    file.writeAsStringSync(isoDateTime + ':' + violatedPath + "\n",
        mode: FileMode.append);
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
