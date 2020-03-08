import 'package:watcher/watcher.dart';
import 'package:path/path.dart' as p;
import 'util/logging.dart';

import 'dart:io';
import './sniffer/file.dart';
import './sniffer.dart';
import 'package:mutex/mutex.dart';

/// make a watcher for all domain logs in a directory
///
// watch /etc/apache2/logs/domlogs/*
watchDestination(String path) async {
  Mutex lock = Mutex();
  String absolutePath = p.absolute(path);
  logger.info("watching2 $absolutePath");
  var watcher = DirectoryWatcher(absolutePath);
  watcher.events.listen((event) async {
    logger.fine("path: $path event: ${event.toString()}");
    final eventPath = event.path;
    if (eventPath.endsWith('~') ||
        eventPath.endsWith(".swp") ||
        eventPath.endsWith(".swpx")) {
      return;
    }
    //if file pattern
    try {
      await lock.acquire();
      await sniffLog(eventPath, FileSnifferHandler());
    } on FileSystemException {
      //ignore
      logger.fine("ignoring missing $eventPath");
    } finally {
      lock.release();
    }
  });
}
