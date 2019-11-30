import '../lib/watcher.dart';
import '../lib/util/logging.dart';

main() async {
  setupLogger();
  // await watchDestination('/etc/apache2/logs/domlogs/');
  await watchDestination('/var/log');
}
