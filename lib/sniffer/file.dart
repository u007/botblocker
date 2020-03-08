import 'package:crypto/crypto.dart';
import 'package:path/path.dart';
import 'dart:convert'; // for the utf8.encode method
import 'dart:async';
import 'dart:io';
import './abstract.dart';
import '../util/logging.dart';

/// Filebase Sniffer configuration
/// to save and load lastLine, lastText and version
class FileSnifferHandler extends SnifferHandler {
  final String configPath;

  FileSnifferHandler({this.configPath: './data'});

  Future<File> prepareLogFileConfig(String path) async {
    File logFile = File(path).absolute;
    String name = basename(logFile.path);

    var bytes = utf8.encode(logFile.path); // data being hashed
    var digest = sha1.convert(bytes);

    String filePath = "$configPath/${digest.toString()}-$name.json";
    logger.fine("prepare logconfig $filePath | actual: ${logFile.path}");
    File file = new File(filePath);
    if (!await file.exists()) {
      file.createSync(recursive: true);
      file.writeAsStringSync('{"lastLine": 0, "lastText": null, "v": 1}');
    }
    logger.fine("prepared logconfig $filePath | actual: ${logFile.path}");
    return file;
  }

  Future<Map<String, dynamic>> getLogFileConfig(String path) async {
    File file = await prepareLogFileConfig(path);

    String content = file.readAsStringSync();
    Map<String, dynamic> data = jsonDecode(content);
    return data;
  }

  Future<String> saveLogFileConfig(String path, int lineNo, String lastLine,
      {version = 1}) async {
    logger.fine("saveLogFileConfig ${path}");
    File file = await prepareLogFileConfig(path);
    logger.fine("saveLogFileConfig ${file.path} | actual: ${path}");
    final data = {
      "lastLine": lineNo,
      "lastText": lastLine,
      "v": version,
    };

    final content = jsonEncode(data);
    file.writeAsStringSync(content);

    return file.path;
  }

  resetLogFileConfig(String path) async {
    File logFile = File(path).absolute;
    String name = basename(logFile.path);

    var bytes = utf8.encode(logFile.path); // data being hashed
    var digest = sha1.convert(bytes);

    String filePath = "$configPath/${digest.toString()}-$name.json";
    logger.fine("resetting logconfig $filePath, actual: ${logFile.path}");
    File file = new File(filePath);
    if (await file.exists()) {
      file.deleteSync();
    }
  }
}
