import 'dart:async';
import 'dart:io';
import 'dart:convert';
import 'package:botblocker/blacklist/csf.dart';
import 'package:mutex/mutex.dart';

import 'detector/urls.dart';
import 'util/logging.dart';
import 'package:intl/intl.dart';
import 'package:path/path.dart';
import './sniffer/abstract.dart';
import 'package:colorize/colorize.dart';

RegExp matchLogLine = new RegExp(
  // r"(?<ip>.*?) (?<remote_log_name>.*?) (?<userid>.*?) \[(?<date>.*?)(?= ) (?<timezone>.*?)\] \"(?<request_method>.*?) (?<path>.*?)(?<request_version> HTTP/.*)?\" (?<status>.*?) (?<length>.*?) \"(?<referrer>.*?)\" \"(?<user_agent>.*?)\" (?<session_id>.*?) (?<generation_time_micro>.*?) (?<virtual_host>.*)",
  r"(?<ip>.*?) (?<remote_log_name>.*?) (?<userid>.*?) \[(?<date>.*?)(?= ) (?<timezone>.*?)\] "
          r'"' +
      r"(?<method>.*?) (?<path>.*?)(?<request_version> HTTP/.*)?" + // quoted
      r'" ' +
      r"(?<status>.*?) (?<length>.*?) " +
      r'"' +
      r"(?<referrer>.*?)" + // quoted
      r'" "' +
      r"(?<agent>.*?)" + // quoted
      r'"',
  // r"(?<session_id>.*?) (?<generation_time_micro>.*?) (?<virtual_host>.*)",
  caseSensitive: false,
  multiLine: false,
);

/*
r"(?P<ip>.*?) (?P<remote_log_name>.*?) (?P<userid>.*?) \[(?P<date>.*?)(?= ) (?P<timezone>.*?)\] \"(?P<request_method>.*?) (?P<path>.*?)(?P<request_version> HTTP/.*)?\" (?P<status>.*?) (?P<length>.*?) \"(?P<referrer>.*?)\" \"(?P<user_agent>.*?)\" (?P<session_id>.*?) (?P<generation_time_micro>.*?) (?P<virtual_host>.*)"*/
const sensitiveCountLimit = [
  {'text': 'wp-login.php', 'triggerCount': 5},
  {'text': '!wp-config.php', 'triggerCount': 1},
];

sniffLog(String logPath, SnifferHandler sniffHandler) async {
  logInfo("sniffLog: $logPath");
  if (FileSystemEntity.typeSync(logPath) == FileSystemEntityType.notFound) {
    throw FileSystemException(logPath);
  }
  logInfo("sniffLog: loading config for $logPath");
  Map<String, dynamic> logConfig = await sniffHandler.getLogFileConfig(logPath);
  logInfo("sniffLog: starting: $logPath | $logConfig");
  await sniffLogwithConfig(logPath, logConfig, sniffHandler);
  logInfo("sniffLog: sniffed: $logPath.");
}

Future<void> sniffLogwithConfig(String logPath, Map<String, dynamic> logConfig,
    SnifferHandler sniffHandler) async {
  int lastLine = logConfig['lastLine'] as int;
  final String lastText = logConfig['lastText'] as String;

  logInfo("path: $logPath, lastLine: $lastLine: $lastText");
  var file = File(logPath);
  String logFileName = basename(logPath);
  List<ViolationRule> rules = violationConfig.containsKey(logFileName)
      ? violationConfig[logFileName]
      : [];
  rules.addAll(violationConfig.containsKey('*') ? violationConfig['*'] : []);
  // Read file
  // var contents = StringBuffer();
  var contentStream = file.openRead();
  int lineNo = 1;
  int newLine = 0;
  String readLastLine = "";
  bool cancelThis = false;
  var reader = contentStream.transform(Utf8Decoder()).transform(LineSplitter());
  int lineCount = await reader.length;

  //reopen stream
  contentStream = file.openRead();
  reader = contentStream.transform(Utf8Decoder()).transform(LineSplitter());

  logInfo("sniffLog($logPath) line count ${lineCount}...");
  if (lineCount < lastLine) {
    logInfo("log file shorter than last line $lineCount vs $lastLine");
    lineNo = 1;
    lastLine = 0;
  } else {
    if (lastLine > 0) {
      logInfo("sniffLog($logPath) Skipping to $lastLine...");
      reader = reader.skip(lastLine - 1);
      lineNo = lastLine; //next line is next line
    }
  }

  logFine("sniffLog($logPath) listening line from ${lineNo}...");
  int readLine = 0;
  // mutex required because reader execute done before finishing executing stream of last line

  await for (var line in reader) {
    if (cancelThis) {
      logFiner("already cancelled");
      break;
    }
    logFine("sniffLog($logPath) ${lineNo}: $line");
    if (lastLine > 0 && lineNo == lastLine) {
      if (lastText != null) {
        if (!line.startsWith(lastText)) {
          logInfo(
              "sniffLog($logPath:$lineNo) Line($lastLine) mismatch, expecting: \"$lastText\", found: $line");
          cancelThis = true;
          // reader.cancel();
          // reader.cancel();
          //rerun from start
          logConfig['lastLine'] = 0;
          logConfig['lastText'] = null;
          // starts from beginning
          var res = await sniffLogwithConfig(logPath, logConfig, sniffHandler);
          return res;
        }
      }

      logInfo("sniffLog($logPath:$lineNo) encounter lastline $lastLine");
      // logFiner("Skipping last line $lineNo to $lastLine");
      lineNo += 1;
      continue; // start with next line
    }

    logFiner("sniffLog($logPath) Reading $lineNo: $line");
    // logFine("read:$lineNo: $line");
    RegExpMatch match = matchLogLine.firstMatch(line);
    if (match == null) {
      logInfo("nothing matched on line: $lineNo: $line");
      lineNo += 1;
      continue; //skip
    }
    String ip, logDate, method, path, agent = '';
    // logFine("match: ${match.groupNames.toString()} ");
    ip = match.namedGroup('ip');
    logDate = match.namedGroup('date');
    method = match.namedGroup('method');
    path = match.namedGroup('path');
    agent = match.namedGroup('agent');

    //30/Nov/2019:11:33:25
    DateFormat format = new DateFormat("dd/MMM/yyyy:hh:mm:ss");
    DateTime date = format.parse(logDate);
    logFine(
        "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method path: $path agent: $agent");

    // check if path matches any of the banned list and violated within the hour

    for (ViolationRule rule in rules) {
      bool bFound = false;
      if (rule.exact && rule.url == path) {
        logFine(
            "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method found exact: $rule");
        bFound = true;
      } else if (!rule.exact) {
        if (path.contains(rule.url)) {
          bFound = true;
        }
      }
      if (!bFound) continue;

      CSFBlackList bHandler = CSFBlackList(test: false);
      if (await bHandler.isBannedIP(ip)) {
        logInfo("sniffLog($logPath:$lineNo) banned ip: $ip, skipping");
        continue;
      }

      if (await bHandler.isWhiteListedIP(ip)) {
        logInfo("sniffLog($logPath:$lineNo) whitelisted ip: $ip, skipping");
        continue;
      }

      if (rule.count <= 1) {
        // await bHandler.banIP(ip);
        await bHandler.storeAndBlockIP(ip, date, logFileName, path,
            reason: 'botblock ${rule.id}');
      } else {
        logInfo(
            "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method found $rule");
        ViolationInfo info =
            await bHandler.loadIPViolation(ip, logFileName, path);
        // logFine(
        //     "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method loaded");
        int violatedCount = await info.countViolation(rule.duration) + 1;
        if (violatedCount >= rule.count) {
          logInfo(
              "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method violated count ${rule.count}, violatedCount: $violatedCount - banning!");
          await bHandler.banIP(ip, reason: 'botblock ${rule.id}');
        } else {
          logFine(
              "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method violated count ${rule.count}, violatedCount: $violatedCount - counting...");
        }

        await bHandler.storeViolation(ip, date, logFileName, path,
            count: violatedCount);
      }
    } //each rules

    readLastLine = line;

    newLine += 1;
    lineNo += 1;
  } //each line

  if (!cancelThis) {
    logInfo("done $logPath ${lineNo - 1} readed: $readLine");
    if (newLine > 0) {
      logInfo(
          "completed ${lineNo - 1} line(s) with $newLine new lines on $logPath");
      await sniffHandler.saveLogFileConfig(logPath, lineNo - 1, readLastLine);
      logInfo(
          "saved ${lineNo - 1} line(s) with $newLine new lines on $logPath");
    } else {
      logInfo("nothing changed on $logPath");
    }
  } else {
    logFine("cancelled done");
  }
  logFine("sniffLog($logPath) ended.");
}

logInfo(String msg) {
  print('*' + msg);
  logger.info(msg);
}

logFine(String msg) {
  Colorize cStr = Colorize('*' + msg)..lightGray();
  print(cStr);
  logger.fine(msg);
}

logFiner(String msg) {
  Colorize cStr = Colorize('*' + msg)..darkGray();
  print(cStr);
  logger.finer(msg);
}
