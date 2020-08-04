import 'dart:io';

import './logging.dart';

const Duration defaultTimeout = Duration(minutes: 30);
typedef requestHandler(dynamic req);

class SingularProcess {
  final String lockName;
  final requestHandler handler;
  File lockFile;
  String path;

  Duration timeout;
  bool setupDone = false;

  SingularProcess(this.lockName, this.handler, {lockDuration: defaultTimeout}) {
    print('singularProcess($lockName) initialise');
    setupLogger();
    timeout = lockDuration;
    path = "./${lockName}.lck";
    lockFile = new File(path);
    setup();
  }

  setup() async {
    if (FileSystemEntity.typeSync(path) != FileSystemEntityType.notFound) {
      await lockFile.deleteSync();
    }
    setupDone = true;
  }

  //handle without exception
  tryHandle(dynamic p) async {
    String debugPrefix = '';
    try {
      debugPrefix = p.path;
      await handle(p);
    } catch (err, stack) {
      logger.info(
          "singularProcess($lockName)$debugPrefix tryHandle error: $err | $stack");
    }
  }

  handle(dynamic p) async {
    String debugPrefix = p.path;
    logger.info("singularProcess($lockName)$debugPrefix handling....");
    while (!setupDone) {
      logger.fine('singularProcess($lockName)$debugPrefix waiting setup');
      await sleep(Duration(milliseconds: 100));
    }
    logger.info("singularProcess($lockName)$debugPrefix timeout $timeout");
    var end = new DateTime.now().toUtc().add(timeout);
    var now = new DateTime.now().toUtc();
    var fileType = FileSystemEntity.typeSync(path);
    while (fileType != FileSystemEntityType.notFound && now.isBefore(end)) {
      await sleep(Duration(milliseconds: 100));
      final now2 = new DateTime.now().toUtc();
      final timeWait = now2.difference(now);
      if (timeWait.inSeconds % 10 > 0) {
        logger.fine(
            "singularProcess($lockName)$debugPrefix Waiting for lock ${path}");
      }
    }

    if (fileType != FileSystemEntityType.notFound) {
      throw "Unable to obtain lock ${path}";
    }

    logger.info(
        "singularProcess($lockName)$debugPrefix creating lockfile ${path}");
    await lockFile.create(recursive: true);
    fileType = FileSystemEntity.typeSync(path);
    logger.info(
        "singularProcess($lockName)$debugPrefix typeSync ok after create? $fileType");

    if (fileType == FileSystemEntityType.notFound) {
      throw "Unable to create lock ${path}";
    }
    // gwpLockSync.lockSync(FileLock.exclusive);
    try {
      // print("not calling handler!");
      return await handler(p);
    } catch (err) {
      logger.info("singularProcess($lockName)$debugPrefix  error: $err");
      rethrow;
    } finally {
      if (FileSystemEntity.typeSync(path) != FileSystemEntityType.notFound) {
        await lockFile.deleteSync();
      }
      // gwpLockSync.unlockSync();
    }
  }
}
