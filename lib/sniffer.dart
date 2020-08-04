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

Future sniffLog(String logPath, SnifferHandler sniffHandler) async {
  if (FileSystemEntity.typeSync(logPath) == FileSystemEntityType.notFound) {
    throw FileSystemException(logPath);
  }

  Map<String, dynamic> logConfig = await sniffHandler.getLogFileConfig(logPath);

  return sniffLogwithConfig(logPath, logConfig, sniffHandler);
}

sniffLogwithConfig(String logPath, Map<String, dynamic> logConfig,
    SnifferHandler sniffHandler) async {
  int lastLine = logConfig['lastLine'] as int;
  final String lastText = logConfig['lastText'] as String;

  logger.info("path: $logPath, lastLine: $lastLine: $lastText");
  var file = File(logPath);
  String logFileName = basename(logPath);
  List<ViolationRule> rules = violationConfig.containsKey(logFileName)
      ? violationConfig[logFileName]
      : [];
  rules.addAll(violationConfig.containsKey('*') ? violationConfig['*'] : []);
  //TODO cancel stream for better performance
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

  logger.info("sniffLog($logPath) line count ${lineCount}...");
  if (lineCount < lastLine) {
    logger.info("log file shorter than last line $lineCount vs $lastLine");
    lineNo = 1;
    lastLine = 0;
  } else {
    if (lastLine > 0) {
      logger.info("sniffLog($logPath) Skipping to $lastLine...");
      reader = reader.skip(lastLine - 1);
      lineNo = lastLine; //next line is next line
    }
  }

  logger.fine("sniffLog($logPath) listening line from ${lineNo}...");
  int readLine = 0;
  // mutex required because reader execute done before finishing executing stream of last line

  Mutex singleLineMutex = Mutex();

  await reader.listen((String line) async {
    await singleLineMutex.acquire();
    readLine = lineNo;
    if (cancelThis) {
      await singleLineMutex.release();
      logger.finer("already cancelled");
      return;
    }
    // logger.info("sniffLog($logPath:$lineNo) line: $line");
    if (lastLine > 0 && lineNo == lastLine) {
      if (lastText != null) {
        if (!line.startsWith(lastText)) {
          logger.info(
              "sniffLog($logPath:$lineNo) Line($lastLine) mismatch, expecting: \"$lastText\", found: $line");
          cancelThis = true;
          // reader.cancel();
          // reader.cancel();
          //rerun from start
          logConfig['lastLine'] = 0;
          logConfig['lastText'] = null;
          await singleLineMutex.release();
          var res = await sniffLogwithConfig(logPath, logConfig, sniffHandler);
          return res;
        }
      }

      logger.info("sniffLog($logPath:$lineNo) encounter lastline $lastLine");
      // logger.finer("Skipping last line $lineNo to $lastLine");
      lineNo += 1;
      await singleLineMutex.release();
      return; // start with next line
    }

    logger.finer("Reading $lineNo: $line");
    // logger.fine("read:$lineNo: $line");
    RegExpMatch match = matchLogLine.firstMatch(line);
    if (match == null) {
      logger.info("nothing matched on line: $lineNo: $line");
      lineNo += 1;
      await singleLineMutex.release();
      return;
    }
    String ip, logDate, method, path, agent = '';
    // logger.fine("match: ${match.groupNames.toString()} ");
    ip = match.namedGroup('ip');
    logDate = match.namedGroup('date');
    method = match.namedGroup('method');
    path = match.namedGroup('path');
    agent = match.namedGroup('agent');

    //30/Nov/2019:11:33:25
    DateFormat format = new DateFormat("dd/MMM/yyyy:hh:mm:ss");
    DateTime date = format.parse(logDate);
    logger.fine(
        "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method path: $path agent: $agent");

    // check if path matches any of the banned list and violated within the hour

    for (ViolationRule rule in rules) {
      bool bFound = false;
      if (rule.exact && rule.url == path) {
        logger.fine(
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
        logger.info("sniffLog($logPath:$lineNo) banned ip: $ip, skipping");
        continue;
      }

      if (await bHandler.isWhiteListedIP(ip)) {
        logger.info("sniffLog($logPath:$lineNo) whitelisted ip: $ip, skipping");
        continue;
      }

      if (rule.count <= 1) {
        // await bHandler.banIP(ip);
        await bHandler.storeAndBlockIP(ip, date, logFileName, path,
            reason: 'botblock ${rule.id}');
      } else {
        logger.info(
            "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method found $rule");
        ViolationInfo info =
            await bHandler.loadIPViolation(ip, logFileName, path);
        // logger.fine(
        //     "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method loaded");
        int violatedCount = await info.countViolation(rule.duration) + 1;
        if (violatedCount >= rule.count) {
          logger.info(
              "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method violated count ${rule.count}, violatedCount: $violatedCount - banning!");
          await bHandler.banIP(ip, reason: 'botblock ${rule.id}');
        } else {
          logger.fine(
              "sniffLog($logPath:$lineNo) ip: $ip, date: $date method: $method violated count ${rule.count}, violatedCount: $violatedCount - counting...");
        }

        await bHandler.storeViolation(ip, date, logFileName, path,
            count: violatedCount);
      }
    }

    readLastLine = line;

    newLine += 1;
    lineNo += 1;
    await singleLineMutex.release();
    // logger.fine("words: ${words.length}");
  }, onDone: () async {
    if (!cancelThis) {
      logger.info("done $logPath ${lineNo - 1} readed: $readLine");
      if (newLine > 0) {
        logger.info(
            "completed ${lineNo - 1} line(s) with $newLine new lines on $logPath");
        await sniffHandler.saveLogFileConfig(logPath, lineNo - 1, readLastLine);
        logger.info(
            "saved ${lineNo - 1} line(s) with $newLine new lines on $logPath");
      } else {
        logger.info("nothing changed on $logPath");
      }
    } else {
      logger.fine("cancelled done");
    }
  }, onError: (e) {
    logger.severe("Error: $logPath {$lineNo-1} ${e}");
  }, cancelOnError: true);
}
