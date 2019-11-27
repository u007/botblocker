import 'dart:async';
import 'dart:io';
import 'dart:convert';

Future sniffLog(String logPath) async {
  if (FileSystemEntity.typeSync(logPath) == FileSystemEntityType.notFound) {
    throw ("${logPath} missing");
  }

  var file = File(logPath);
  // Read file
  var contents = StringBuffer();
  var contentStream = file.openRead();

  await contentStream.transform(Utf8Decoder()).transform(LineSplitter()).listen(
      (String line) = {
        contents.write(line), // Add line to our StringBuffer object
      },
          
      onDone: () => print(contents
          .toString()), // Call toString() method to receive the complete data
      onError: (e) => print('[Problems]: $e'));
}
