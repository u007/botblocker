import 'dart:async';
import 'dart:io';
import 'dart:convert';
import 'util/logger.dart';

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

  await contentStream.transform(Utf8Decoder()).transform(LineSplitter()).listen(
      (String line) {
    logger.d("reading line ${line}");
  }, onDone: () {
    logger.i("completed ${logPath}");
  }, onError: (e) {
    logger.e("Error: ${e.toString()}");
  });
}
