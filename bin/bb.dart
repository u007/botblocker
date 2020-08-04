import 'package:botblocker/blacklist/csf.dart';
import 'package:botblocker/sniffer/file.dart';

import '../lib/watcher.dart';
import '../lib/util/logging.dart';

final version = "v1.0.5";
main(List<String> args) async {
  print("bb($version)");
  setupLogger();
  // await watchDestination('/etc/apache2/logs/domlogs/');
  String cmd = args.length > 0 ? args[0] : '';
  switch (cmd) {
    case 'reset-ip':
      Map<String, dynamic> data = expectArgs(
          args, ['ip', 'logName:optional'], 'reset-ip', 'Reset an ip record');
      output("Resetting IP ${data['ip']} logName: ${data['logName']}...");
      await CSFBlackList().resetIP(data['ip'], logName: data['logName']);
      output("IP ${data['ip']} logName: ${data['logName']}: reset done.");
      break;

    case 'reset-log':
      Map<String, dynamic> data = expectArgs(args, ['path'], 'reset-log',
          'Reset an log file record.\nExample bb.exe reset-log log/xyz.com.\nExample #2: bb.exe reset-log /var/log/httpd/xyz.com.log');
      output("Resetting log ${data['path']}...");
      await FileSnifferHandler().resetLogFileConfig(data['path']);
      output(
          "Resetting log ${data['ip']} logName: ${data['logName']}: reset done.");
      break;

    case 'unblock':
      Map<String, dynamic> data =
          expectArgs(args, ['ip'], 'unblock', 'Unblock an ip');
      output("Unblocking IP ${data['ip']}...");
      await CSFBlackList().unBanIP(data['ip']);
      output("IP ${data['ip']} has been unblock.");
      break;

    case 'undo-blocks':
      Map<String, dynamic> data = expectArgs(
          args, ['yes'], 'unblock', 'Unblock all ip, passing 1 to confirm');
      output("Unblocking all IP yes? ${data['yes']}...");
      if (data['yes'] == '1') {
        await CSFBlackList().unBanAll();
        output("Unblocked all IP.");
      } else {
        output("Does nothing.");
      }
      break;

    case 'block':
      Map<String, dynamic> data =
          expectArgs(args, ['ip'], 'block', 'Block an ip');
      output("Blocking IP ${data['ip']}...");
      await CSFBlackList().banIP(data['ip'], reason: 'botblock manual');
      output("IP ${data['ip']} has been blocked!");
      break;

    case 'watch':
      Map<String, dynamic> data = expectArgs(args, ['path'], 'watch',
          'watch a directory.\nExample: bb.exe watch logs\nExample#2: bb.exe watch /c/logs\nExample#3: bb.exe watch /var/logs/httpd/domain.log');
      output("Watching ${data['path']}...");
      await watchDestination(data['path']);
      break;

    case 'help':
      output(
          "bb.exe reset-ip / reset-log / block / unblock / watch / undo-blocks");
      break;

    default:
      if (args.length > 0) {
        throw "Unknown command ${args[0]}, please use 'help' for available commands";
      }
    // await watchDestination('logs');
  }
  ;
}

output(String message) {
  print(message);
}

/*
args: from command line
names: list  of names
  "name:optional" for optional field
*/
Map<String, dynamic> expectArgs(
    List<String> args, List<String> names, String prefix, String comment,
    {offset: 1}) {
  int minLength = offset;
  for (int c = 0; c < names.length; c++) {
    if (names[c].endsWith(':optional')) {
      break;
    }
    minLength = c + offset + 1;
  }
  // output("Expecting minLength: $minLength, args: ${args.length}");
  if (args.length < minLength) {
    List<String> out = [prefix];

    for (int c = 0; c < names.length; c++) {
      out.add("<${names[c]}>");
    }
    String error = "Arguments missing: bb.exe ${out.join(' ')}\n$comment";
    throw error;
  }
  Map<String, dynamic> res = {};

  for (int c = 0; c < names.length; c++) {
    String name = names[c];

    if (args.length > c + offset) {
      res[name] = args[c + offset];
    } else {
      res[name] = null;
    }
  }

  return res;
}
