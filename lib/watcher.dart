import 'dart:async';

import 'package:botblocker/util/lock.dart';
import 'package:watcher/watcher.dart';
import 'package:path/path.dart' as p;
import 'util/logging.dart';

import 'dart:io';
import './sniffer/file.dart';
import './sniffer.dart';
import 'package:mutex/mutex.dart';

Mutex lock = Mutex();
File lockFile = File(".watcher.lock");

/// make a watcher for all domain logs in a directory
// watch /etc/apache2/logs/domlogs/*
watchDestination(String path) async {
  String absolutePath = p.absolute(path);
  logger.info("watching2 $absolutePath");
  var watcher = DirectoryWatcher(absolutePath);
  var started = false;
  watcher.events.listen(SingularProcess('watcher', (event) async {
    logger.fine("path: $path event: ${event.toString()}");
    final eventPath = event.path;
    if (eventPath.endsWith('~') ||
        eventPath.endsWith(".swp") ||
        eventPath.endsWith(".swpx") ||
        eventPath.endsWith(".bkup") ||
        eventPath.endsWith(".bk") ||
        eventPath.endsWith(".lock") ||
        eventPath.endsWith("bytes_log")) {
      return;
    }

    await processQueue({eventPath: true});
    // await lock.acquire();
    // if (!waitingFile.containsKey(eventPath)) {
    //   waitingFile[eventPath] = true;
    //   logger.info("aded queue: path: $eventPath event: ${event.toString()}");
    //   await processQueue([eventPath]);
    // } else {
    //   logger.info(
    //       "skip exists queue: path: $eventPath event: ${event.toString()}");
    // }
    // await lock.release();
    //if file pattern
  }).handler);
}

processQueue(Map<String, bool> waitingFile) async {
  logger.fine("processing queue ${waitingFile.keys}");
  // await lock.acquire();
  while (waitingFile.keys.length > 0) {
    final pendingFile = waitingFile.keys.first;

    try {
      await sniffLog(pendingFile, FileSnifferHandler());
      waitingFile.remove(pendingFile);
    } on FileSystemException {
      //ignore
      logger.fine("ignoring missing $pendingFile");
    } catch (error, stack) {
      logger.info("path: $pendingFile unhandled exception: $error | $stack");
    }
  }

  // await lock.release();

  // Timer.run(() async {
  //   logger.fine("loop... sleeping 5s");
  //   await sleep(Duration(seconds: 5));
  //   processQueue();
  // });
}
