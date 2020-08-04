// import 'dart:async';
import 'dart:async';
import 'dart:isolate';

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
String runningPath = '';
final receiverMutex = Mutex();
ReceivePort mainReceiver = ReceivePort();

/// make a watcher for all domain logs in a directory
// watch /etc/apache2/logs/domlogs/*
watchDestination(String path) async {
  String absolutePath = p.absolute(path);
  logger.info("watching $absolutePath");
  var watcher = DirectoryWatcher(absolutePath);

  SendPort queueReceiver;
  mainReceiver.listen((data) {
    if (data is SendPort) {
      if (queueReceiver != null) {
        return;
      }
      logger.info('watchReceiver: init sendport');
      queueReceiver = data;
    } else {
      logger.info('watchReceiver: received: $data');
    }
  });

  Isolate watchIso =
      await Isolate.spawn(watchIsolate, WatchInit(mainReceiver.sendPort));

  // final watcherHandler = SingularProcess('watcher', (event) async {
  //   logger.fine("caught: $path event: ${event.toString()}");
  //   final eventPath = event.path;
  //   final eventType = event.type;
  //   if (eventPath.endsWith('~') ||
  //       eventPath.endsWith(".swp") ||
  //       eventPath.endsWith(".swpx") ||
  //       eventPath.endsWith(".bkup") ||
  //       eventPath.endsWith(".bk") ||
  //       eventPath.endsWith(".lock") ||
  //       eventPath.endsWith("bytes_log")) {
  //     return;
  //   }

  //   queueReceiver.send('$eventType:$eventPath');
  // });

  // watcher.events.listen(watcherHandler.tryHandle);
  watcher.events.listen((event) async {
    logger.fine("caught: $path event: ${event.toString()}");
    final eventPath = event.path;
    final eventType = event.type;
    if (eventPath.endsWith('~') ||
        eventPath.endsWith(".swp") ||
        eventPath.endsWith(".swpx") ||
        eventPath.endsWith(".bkup") ||
        eventPath.endsWith(".bk") ||
        eventPath.endsWith(".lock") ||
        eventPath.endsWith("bytes_log")) {
      return;
    }

    queueReceiver.send('$eventType:$eventPath');
  });

  Timer.periodic(Duration(seconds: 10), (Timer t) async {
    logger.info('watchDestination: run...');
    // await receiverMutex.acquire();
    try {
      queueReceiver.send('queue');
    } catch (err, stack) {
      logger.info('error processQueue: $err | $stack');
    } finally {
      // await receiverMutex.release();
    }
  });
}

void watchIsolate(WatchInit initConfig) async {
  ReceivePort receiver = ReceivePort();
  print('watchIsolate: sending watcher sendport');
  await initConfig.sendPort.send(receiver.sendPort);
  Map<String, bool> pendingQueue = {};
  receiver.listen((data) async {
    logger.info("watchISO: $data");
    await receiverMutex.acquire();
    logger.finer("watchISO: starting $data");

    try {
      if (data is String) {
        if (data == 'queue') {
          await processQueue(pendingQueue);
          pendingQueue = {};
          return;
        }
        final event = data.split(':');
        final file = event[1];
        if (pendingQueue.containsKey(file)) {
          print('watchIsolate: ignoring $file, already in queue');
          return;
        }

        pendingQueue[file] = true;
      }
    } catch (err) {
      logger.info('watchIsolate: error: $err');
    } finally {
      await receiverMutex.release();
    }
    // loggerLog('[loggingIsolate] $data');
    // pendingLogs.add(data);
  }); // receiver
} // watchIsolate

processQueue(Map<String, bool> waitingFile) async {
  logger.fine("processQueue ${waitingFile.keys}");
  // await lock.acquire();
  while (waitingFile.keys.length > 0) {
    final pendingFile = waitingFile.keys.first;

    try {
      await sniffLog(pendingFile, FileSnifferHandler());
      waitingFile.remove(pendingFile);
    } on FileSystemException {
      //ignore
      logger.fine("processQueue ignoring missing $pendingFile");
    } catch (error, stack) {
      logger.info(
          "processQueue path: $pendingFile unhandled exception: $error | $stack");
    }
  }
} // processQueue

class WatchInit {
  final SendPort sendPort;
  WatchInit(this.sendPort);
}
