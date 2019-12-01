import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:intl/intl.dart';
import 'package:process_run/process_run.dart';
// import 'package:process_run/shell.dart';
import 'package:process_run/which.dart';
import "package:async/async.dart";
// import 'package:path/path.dart';

final violationPath = ".data/";
var csfPath = "";

storeViolation(String ip, DateTime date, String violatedPath) async {
  String datePath = DateFormat("yyyy-MM-dd").format(date);
  String filePath = "$violationPath/$datePath/$ip.log";

  //creates dir and file if not exists
  File file = new File(filePath);
  if (!await file.exists()) {
    file.createSync(recursive: true);
  }

  file.writeAsStringSync(violatedPath + "\n", mode: FileMode.append);
}

isBannedIP(String ip) async {
  await csfRun(['-g', ip]);
}

csfRun(List<String> args,
    {String workingDirectory,
    Map<String, String> environment,
    bool includeParentEnvironment = true,
    bool runInShell,
    Encoding stdoutEncoding = systemEncoding,
    Encoding stderrEncoding = systemEncoding,
    Stream<List<int>> stdin,
    StreamSink<List<int>> stdout,
    StreamSink<List<int>> stderr,
    bool verbose,
    bool commandVerbose}) {
  if (csfPath == "") {
    csfPath = whichSync('csf');
    if (csfPath == null) {
      throw "Missing csf";
    }
  }

  var output = OutputStreamSink<List<int>>();

  return run(csfPath, args, workingDirectory: workingDirectory, stdout: output);
}

class OutputStreamSink<T> implements StreamSink<T> {
  /// The results corresponding to events that have been added to the sink.
  final results = <Result<T>>[];

  /// Whether [close] has been called.
  bool get isClosed => _isClosed;
  var _isClosed = false;

  @override
  Future get done => _doneCompleter.future;
  final _doneCompleter = Completer<dynamic>();

  final Func _onDone;

  /// Creates a new sink.
  ///
  /// If [onDone] is passed, it's called when the user calls [close]. Its result
  /// is piped to the [done] future.
  OutputStreamSink({onDone()}) : _onDone = onDone ?? (() {});

  @override
  void add(T event) {
    results.add(Result<T>.value(event));
  }

  @override
  void addError(error, [StackTrace stackTrace]) {
    results.add(Result<T>.error(error, stackTrace));
  }

  @override
  Future addStream(Stream<T> stream) {
    var completer = Completer.sync();
    stream.listen(add, onError: addError, onDone: completer.complete);
    return completer.future;
  }

  @override
  Future close() {
    _isClosed = true;
    _doneCompleter.complete(Future.microtask(_onDone));
    return done;
  }
}
