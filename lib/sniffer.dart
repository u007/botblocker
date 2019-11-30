import 'dart:async';
import 'dart:io';
import 'dart:convert';
import 'util/logging.dart';

RegExp matchLogLine = new RegExp(
  r"([^ ])*\s+([^ ])*\s+([^ ]*)\s+([^ ]*)\s+([^ ]*)).*",
  caseSensitive: false,
  multiLine: false,
);

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

    // List<String> words = line.split(new RegExp(r"[^ ]*\s+[^ ]*"));

    logger.fine("words: ${words.length}: $words");
  }, onDone: () {
    logger.info("completed $logPath");
  }, onError: (e) {
    logger.severe("Error: $e.toString()");
  });
}
