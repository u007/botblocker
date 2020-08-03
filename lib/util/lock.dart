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
  }

  handle(dynamic p) async {
    while (!setupDone) {
      await sleep(Duration(milliseconds: 100));
    }
    logger.info("singularProcess($lockName) timeout $timeout");
    var end = new DateTime.now().toUtc().add(timeout);
    var now = new DateTime.now().toUtc();
    var fileType = FileSystemEntity.typeSync(path);
    while (fileType != FileSystemEntityType.notFound && now.isBefore(end)) {
      await sleep(Duration(milliseconds: 100));
      now = new DateTime.now().toUtc();
      logger.fine("singularProcess($lockName) Waiting for lock ${path}");
    }

    if (fileType != FileSystemEntityType.notFound) {
      throw "Unable to obtain lock ${path}";
    }

    logger.info("typeSync $fileType ok?");
    logger.info("singularProcess($lockName) creating lockfile ${path}");
    await lockFile.create(recursive: true);
    // gwpLockSync.lockSync(FileLock.exclusive);
    try {
      return await handler(p);
    } catch (err) {
      logger.info("singularProcess($lockName) error: $err");
      rethrow;
    } finally {
      if (FileSystemEntity.typeSync(path) != FileSystemEntityType.notFound) {
        await lockFile.deleteSync();
      }
      // gwpLockSync.unlockSync();
    }
  }
}
