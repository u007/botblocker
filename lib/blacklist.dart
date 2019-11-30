import 'package:intl/intl.dart';
import 'dart:io';

final violationPath = ".data/";

storeViolation(String ip, DateTime date, String violatedPath) async {
  String datePath = DateFormat("yyyy-MM-dd").format(date);
  String filePath = "$violationPath/$datePath/$ip";

  //creates dir and file if not exists
  File file = new File(filePath);

  if (!await file.exists()) {
    file.createSync(recursive: true);
  }
}
