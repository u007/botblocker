import 'dart:async';

/// handles saving and loading of sniffer configuration
abstract class SnifferHandler {
  /// read log file from last line, otherwise from beginnning and find for bad url access
  /// and allow whitelisting of ip avoidance and also blacklist ip when needed via csf
  Future<Map<String, dynamic>> getLogFileConfig(String path);
  Future<String> saveLogFileConfig(String path, int lineNo, String lastLine,
      {version = 1});
}
