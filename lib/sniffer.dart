import 'dart:async';
import 'dart:io';
import 'dart:convert';
import 'util/logging.dart';

RegExp matchLogLine = new RegExp(
  // r"([^ ])*\S+([^ ])*\S+([^ ]*)\S+([^ ]*)\S+([^ ]*).*",
  // r"([^ ]*)\S+([^ ]*)\S+([^ ]*)\S+.*", //\S+([^ ]*)
  // r"(?P.*?) (?P.*?) (?P.*?) \[(?P.*?)(?= ) (?P.*?)\] \"(?P.*?) (?P<path>.*?)(?P HTTP/.*)?\" (?P.*?) (?P.*?) \"(?P.*?)\" \"(?P.*?)\" (?P.*?) (?P.*?) (?P.*)",
  // r"(?<ip>.*?) (?<remote_log_name>.*?) (?<userid>.*?) \[(?<date>.*?)(?= ) (?<timezone>.*?)\] \"(?<request_method>.*?) (?<path>.*?)(?<request_version> HTTP/.*)?\" (?<status>.*?) (?<length>.*?) \"(?<referrer>.*?)\" \"(?<user_agent>.*?)\" (?<session_id>.*?) (?<generation_time_micro>.*?) (?<virtual_host>.*)",
  r"(?<ip>.*?) (?<remote_log_name>.*?) (?<userid>.*?) \[(?<date>.*?)(?= ) (?<timezone>.*?)\] "
          r'"' +
      r"(?<method>.*?) (?<path>.*?)(?<request_version> HTTP/.*)?" +
      r'" ' +
      r"(?<status>.*?) (?<length>.*?) " +
      r'"' +
      r"(?<referrer>.*?)" +
      r'" ' +
      r"(?<agent>.*?)" +
      r'" ' +
      r"(?<session_id>.*?) (?<generation_time_micro>.*?) (?<virtual_host>.*)",
  caseSensitive: false,
  multiLine: false,
);

/*
r"(?P<ip>.*?) (?P<remote_log_name>.*?) (?P<userid>.*?) \[(?P<date>.*?)(?= ) (?P<timezone>.*?)\] \"(?P<request_method>.*?) (?P<path>.*?)(?P<request_version> HTTP/.*)?\" (?P<status>.*?) (?P<length>.*?) \"(?P<referrer>.*?)\" \"(?P<user_agent>.*?)\" (?P<session_id>.*?) (?P<generation_time_micro>.*?) (?P<virtual_host>.*)"*/
const sensitiveCountLimit = [
  {'text': '', 'triggerCount': 3}
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
    logger.fine("read:$lineNo: $line");
    RegExpMatch match = matchLogLine.firstMatch(line);
    // Iterable<RegExpMatch> words = matchLogLine.allMatches(line);

    if (match.groupNames == null) {
      logger.severe("nothing matched: ${match.toString()}");
      return;
    }
    String ip, logDate, method, path, agent = '';
    logger.fine("match: ${match.groupNames.toString()} ");
    ip = match.namedGroup('ip');
    logDate = match.namedGroup('date');
    method = match.namedGroup('method');
    path = match.namedGroup('path');
    agent = match.namedGroup('agent');
    logger.fine(
        "matched: ip: $ip, date: $logDate method: $method path: $path agent: $agent");
    // logger.fine("words: ${words.length}");
  }, onDone: () {
    logger.info("completed $logPath");
  }, onError: (e) {
    logger.severe("Error: ${e.toString()}");
  });
}
