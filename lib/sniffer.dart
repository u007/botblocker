import 'dart:async';
import 'dart:io';
import 'dart:convert';
import 'util/logging.dart';

RegExp matchLogLine = new RegExp(
  // r"([^ ])*\S+([^ ])*\S+([^ ]*)\S+([^ ]*)\S+([^ ]*).*",
  r"([^ ]*)\S+([^ ]*)\S+([^ ]*)\S+.*", //\S+([^ ]*)
  caseSensitive: false,
  multiLine: false,
);

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
    Iterable<RegExpMatch> words = matchLogLine.allMatches(line);

    if (words == null) {
      logger.severe("Found null!");
      return;
    }
    // List<String> words = line.split(new RegExp(r"[^ ]*\s+[^ ]*"));

    String ip, logDate = '';
    int index = 0;
    for (var match in words) {
      if (match == null) {
        index += 1;
        continue;
      }
      logger.fine("match: ${match.groupCount} | (${match.group(1)})");

      switch (index) {
        case 0:
          ip = match.group(1);
          break;
        case 3:
          logDate = match.group(1);
          break;
      }
      logger.fine("ip: $ip, date: $logDate");
      index += 1;
    }

    // logger.fine("words: ${words.length}");
  }, onDone: () {
    logger.info("completed $logPath");
  }, onError: (e) {
    logger.severe("Error: ${e.toString()}");
  });
}
