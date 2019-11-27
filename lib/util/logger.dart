import 'package:logger/logger.dart';

final logger = Logger(printer: LogHandler());

class LogHandler extends LogPrinter {
  @override
  void log(Level level, message, error, StackTrace stackTrace) {
    //May allow extend to provide external logging
    println(message);
  }
}
