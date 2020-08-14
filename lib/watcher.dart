// import 'dart:async';
import 'dart:async';
import 'dart:convert';
import 'dart:isolate';

import 'package:botblocker/util/lock.dart';
import 'package:process_run/which.dart';
import 'package:watcher/watcher.dart';
import 'package:path/path.dart' as p;
import 'util/logging.dart';

import 'dart:io';
import './sniffer/file.dart';
import './sniffer.dart';
import 'package:mutex/mutex.dart';
import 'package:colorize/colorize.dart';

Mutex lock = Mutex();
File lockFile = File(".watcher.lock");
String runningPath = '';
final receiverMutex = Mutex();
ReceivePort mainReceiver = ReceivePort();

String iNotifyWaitPath = '';

watchDestination(String path) async {
  if (Platform.isMacOS || Platform.isLinux) {
    logInfo("detecting inotifywait...");
    iNotifyWaitPath = whichSync('inotifywait');
  }

  if (iNotifyWaitPath == null || iNotifyWaitPath.isEmpty) {
    logInfo(
        "Missing iNotifyWait, falling back to watcher (not stable). for more information, use help");
    return watchDestinationViaWatcher(path);
  }

  SendPort queueReceiver;
  String absolutePath = p.absolute(path);
  final processArgs = '''-r -m -e modify $absolutePath'''.split(' ').toList();

  mainReceiver.listen((data) async {
    if (data is SendPort) {
      logInfo('watchReceiver: mainReceiver received sendport');
      queueReceiver = data;

      logInfo("$iNotifyWaitPath ${processArgs.join(' ')}");
      await Process.start(iNotifyWaitPath, processArgs,
              includeParentEnvironment: true)
          .then((Process proc) {
        logFine("inotifywait started");
        proc.stdout.transform(utf8.decoder).listen((data) {
          List<String> lines = data.substring(0, data.length - 1).split('\n');
          for (var c = 0; c < lines.length; c++) {
            String line = lines[c];
            // logFine("inotifywait-out: $line");
            List<String> updates = line.split(' ');
            if (updates.length < 3) {
              logSevere('Invalid notify event: $line | $updates | all: $lines');
              return;
            }
            final eventPath = updates[0] + updates[2];
            final eventType = updates[1];
            if (eventPath.endsWith('~') ||
                eventPath.endsWith(".swp") ||
                eventPath.endsWith(".swpx") ||
                eventPath.endsWith(".bkup") ||
                eventPath.endsWith(".bk") ||
                eventPath.endsWith(".lock") ||
                eventPath.endsWith("bytes_log")) {
              logFine("inotifywait-out: ignored: $line");
              continue;
            }
            logFine("inotifywait-out: $line");

            queueReceiver.send('$eventType:$eventPath');
          } //each lines
        });
        proc.stderr.transform(utf8.decoder).listen((data) {
          String line = data.substring(0, data.length - 1);
          logFine("inotifywait-error: $line");
        });
        proc.exitCode.then((exitCode) {
          logInfo('inotifywait-exit: $exitCode');
          exit(exitCode);
        });
      });
      // queueReceiver.send('queue');
      // queueReceiver.send('modify:/usr/local/apache/domlogs/upa.com.my');
    } else {
      logInfo('watchReceiver: mainReceiver received: $data');
    }
  });

  Isolate watchIso =
      await Isolate.spawn(watchIsolate, WatchInit(mainReceiver.sendPort));

  // final inotifySpaceStreamer =
  //     new StreamTransformer.fromHandlers(handleData: (data, sink) {
  //   print("new $data | $sink");
  //   sink.add(data);
  // });

  /*
  inotifywait -r -m -e modify /usr/local/apache/domlogs | 
   while read path _ file; do 
       echo $path$file modified
   done*/

  // logInfo('watcher ended.');
}

/// make a watcher for all domain logs in a directory
// watch /etc/apache2/logs/domlogs/*
watchDestinationViaWatcher(String path) async {
  String absolutePath = p.absolute(path);
  logInfo("watching $absolutePath");
  var watcher = DirectoryWatcher(absolutePath);

  SendPort queueReceiver;
  mainReceiver.listen((data) {
    if (data is SendPort) {
      logInfo('watchReceiver: mainReceiver received sendport');
      queueReceiver = data;
      // queueReceiver.send('queue');
      // queueReceiver.send('modify:/usr/local/apache/domlogs/upa.com.my');
    } else {
      logInfo('watchReceiver: mainReceiver received: $data');
    }
  });

  Isolate watchIso =
      await Isolate.spawn(watchIsolate, WatchInit(mainReceiver.sendPort));
  // queueReceiver.send('queue');
  // final watcherHandler = SingularProcess('watcher', (event) async {
  //   logFine("caught: $path event: ${event.toString()}");
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
  // Timer.periodic(Duration(seconds: 10), (Timer t) {
  //   logInfo('watchDestination: run...');
  //   if (queueReceiver == null) {
  //     logInfo("watchDestination: queueReceiver not ready");
  //     return;
  //   }
  //   // await receiverMutex.acquire();
  //   try {
  //     queueReceiver.send('queue');
  //   } catch (err, stack) {
  //     logInfo('error processQueue: $err | $stack');
  //   } finally {
  //     // await receiverMutex.release();
  //   }
  // });
  // watcher.events.listen(watcherHandler.tryHandle);
  watcher.events.listen((event) async {
    logFine("caught: $path event: ${event.toString()}");
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
    // logFine('sent: $eventType:$eventPath');
  });

  // logInfo('watcher ended.');
}

void watchIsolate(WatchInit initConfig) async {
  ReceivePort receiver = ReceivePort();

  receiver.listen((data) async {
    logInfo("watchISO: received $data");
    await receiverMutex.acquire();
    logFine("watchISO: starting $data");

    try {
      if (data is String) {
        // if (data == 'queue') {
        //   await processQueue(pendingQueue);
        //   pendingQueue = {};
        //   return;
        // }
        final event = data.split(':');
        final file = event[1];
        // if (pendingQueue.containsKey(file)) {
        //   logInfo('watchISO: ignoring $file, already in queue');
        //   return;
        // }
        // pendingQueue[file] = true;
        // var toProcess = <String, bool>{};
        // toProcess[file] = true;
        // await processQueue(toProcess);
        await sniffLog(file, FileSnifferHandler());
        logInfo("watchISO: sniffLog $file done.");
      } else {
        logInfo("watchISO: unknown data: $data");
      }
    } catch (err) {
      logInfo('watchISO: error: $err');
    } finally {
      logInfo("watchISO: receiverMutex release");
      await receiverMutex.release();
    }
    // loggerLog('[loggingIsolate] $data');
    // pendingLogs.add(data);
  }); // receiver

  // print('watchISO: sending watcher sendport');
  initConfig.sendPort.send(receiver.sendPort);
} // watchIsolate

// processQueue(Map<String, bool> waitingFile) async {
//   logFine("processQueue ${waitingFile.keys}");
//   // await lock.acquire();
//   while (waitingFile.keys.length > 0) {
//     final pendingFile = waitingFile.keys.first;

//     try {
//       await sniffLog(pendingFile, FileSnifferHandler());
//       waitingFile.remove(pendingFile);
//     } on FileSystemException {
//       //ignore
//       logFine("processQueue ignoring missing $pendingFile");
//     } catch (error, stack) {
//       logInfo(
//           "processQueue path: $pendingFile unhandled exception: $error | $stack");
//     }
//   }
// } // processQueue

class WatchInit {
  final SendPort sendPort;
  WatchInit(this.sendPort);
}

logInfo(String msg) {
  print(msg);
  logger.info(msg);
}

logFine(String msg) {
  // Colorize cStr = Colorize(msg)..lightGray();
  // print(cStr);
  logger.fine(msg);
}

logSevere(String msg) {
  // Colorize cStr = Colorize(msg)..red();
  // print(cStr);
  logger.severe(msg);
}
