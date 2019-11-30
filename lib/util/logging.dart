import 'package:logging/logging.dart';
import 'package:colorize/colorize.dart';

//
// Logger.root.level = Level.ALL;
final logger = Logger('default');

setupLogger() {
  Logger.root.level = Level.FINE; // defaults to Level.INFO
  Logger.root.onRecord.listen((record) {
    // String str = '${record.level.name}: ${record.time} ${record.message}';
    String str = '${record.level.name}: ${record.message}';

    if (record.level >= Level.SEVERE) {
      str += '\n' + StackTrace.current.toString();
      Colorize cStr = Colorize(str)..red();
      print(cStr);
      return;
    }

    if (record.level == Level.FINE) {
      Colorize cStr = Colorize(str)..lightGray();
      print(cStr);
      return;
    }
    print(str);
  });
}