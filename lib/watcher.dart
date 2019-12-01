import 'package:watcher/watcher.dart';
import 'package:path/path.dart' as p;
import 'util/logging.dart';

import 'dart:io';
import './sniffer/file.dart';
import './sniffer.dart';

/// make a watcher for all domain logs in a directory
///
// watch /etc/apache2/logs/domlogs/*
watchDestination(String path) async {
  logger.info("watching $path");
  var watcher = DirectoryWatcher(p.absolute(path));
  watcher.events.listen((event) async {
    logger.fine("path: $path event: ${event.toString()}");
    final eventPath = event.path;
    if (eventPath.endsWith('~') || eventPath.endsWith(".swp")) {
      return;
    }
    //if file pattern
    try {
      await sniffLog(eventPath, FileSnifferHandler());
    } on FileSystemException {
      //ignore
      logger.fine("ignoring missing $eventPath");
    }
  });
}
