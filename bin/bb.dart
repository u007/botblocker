import 'package:botblocker/blacklist/csf.dart';

import '../lib/watcher.dart';
import '../lib/util/logging.dart';

main(List<String> args) async {
  setupLogger();
  // await watchDestination('/etc/apache2/logs/domlogs/');
  String cmd = args.length > 0 ? args[0] : '';
  switch (cmd) {
    case 'reset':
      Map<String, dynamic> data = expectArgs(
          args, ['ip', 'logName:optional'], 'reset', 'Reset an ip record');
      output("Resetting IP ${data['ip']} logName: ${data['logName']}...");
      await CSFBlackList().resetIP(data['ip'], logName: data['logName']);
      output("IP ${data['ip']} logName: ${data['logName']} reset done.");
      break;
    case 'unblock':
      Map<String, dynamic> data =
          expectArgs(args, ['ip'], 'unblock', 'Unblock an ip');
      output("Unblocking IP ${data['ip']}...");
      await CSFBlackList().unBanIP(data['ip']);
      output("IP ${data['ip']} has been unblock.");
      break;

    case 'block':
      Map<String, dynamic> data =
          expectArgs(args, ['ip'], 'block', 'Block an ip');
      output("UBlocking IP ${data['ip']}...");
      await CSFBlackList().banIP(data['ip']);
      output("IP ${data['ip']} has been blocked!");
      break;
    default:
      await watchDestination('./logs');
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
  output("Expecting minLength: $minLength, args: ${args.length}");
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
