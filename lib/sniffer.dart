import 'dart:async';
import 'dart:io';
import 'dart:convert';
import 'util/logging.dart';
import 'package:intl/intl.dart';

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

/// read log file from last line, otherwise from beginnning and find for bad url access
/// and allow whitelisting of ip avoidance and also blacklist ip when needed via csf
Future sniffLog(String logPath) async {
  if (FileSystemEntity.typeSync(logPath) == FileSystemEntityType.notFound) {
    throw ("${logPath} missing");
  }

  //TODO read from last line
  var file = File(logPath);
  // Read file
  // var contents = StringBuffer();
  var contentStream = file.openRead();
  int lineNo = 1;
  await contentStream.transform(Utf8Decoder()).transform(LineSplitter()).listen(
      (String line) {
    // logger.fine("read:$lineNo: $line");
    RegExpMatch match = matchLogLine.firstMatch(line);
    if (match == null) {
      logger.severe("nothing matched on line: $lineNo: $line");
      lineNo += 1;
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
        "matched($lineNo) ip: $ip, date: $date method: $method path: $path agent: $agent");
    lineNo += 1;
    // logger.fine("words: ${words.length}");
  }, onDone: () {
    logger.info("completed $lineNo line(s) on $logPath");
  }, onError: (e) {
    logger.severe("Error: ${e.toString()}");
  });
}
