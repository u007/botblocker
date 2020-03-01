abstract class BlackListHandler {
  storeAndBlockIP(
      String ip, DateTime date, String logName, String violatedPath);
  loadIP(String ip);
  storeViolation(String ip, DateTime date, String logName, String violatedPath);
  banIP(String ip);
  isBannedIP(String ip);
  isWhiteListedIP(String ip);
}

// class OutputStreamSink<T> implements StreamSink<T> {
//   /// The results corresponding to events that have been added to the sink.
//   final results = <Result<T>>[];

//   /// Whether [close] has been called.
//   bool get isClosed => _isClosed;
//   var _isClosed = false;

//   @override
//   Future get done => _doneCompleter.future;
//   final _doneCompleter = Completer<dynamic>();

//   final Func _onDone;

//   /// Creates a new sink.
//   ///
//   /// If [onDone] is passed, it's called when the user calls [close]. Its result
//   /// is piped to the [done] future.
//   OutputStreamSink({onDone()}) : _onDone = onDone ?? (() {});

//   @override
//   void add(T event) {
//     results.add(Result<T>.value(event));
//   }

//   @override
//   void addError(error, [StackTrace stackTrace]) {
//     results.add(Result<T>.error(error, stackTrace));
//   }

//   @override
//   Future addStream(Stream<T> stream) {
//     var completer = Completer.sync();
//     stream.listen(add, onError: addError, onDone: completer.complete);
//     return completer.future;
//   }

//   @override
//   Future close() {
//     _isClosed = true;
//     _doneCompleter.complete(Future.microtask(_onDone));
//     return done;
//   }
// }
