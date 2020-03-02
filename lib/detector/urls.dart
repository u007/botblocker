const defaultRuleDuration = Duration(minutes: 15);

class ViolationRule {
  final String id;
  final String url;
  final bool exact;
  final int count;
  final Duration duration;
  ViolationRule(this.id, this.url,
      {this.exact: false, this.count: 1, this.duration: defaultRuleDuration});
}

final Map<String, List<ViolationRule>> violationConfig = {
  'apache.log': [ViolationRule('wp-login-apache', 'wp-login.php', count: 5)],
  '*': [ViolationRule('wp-login-all', 'wp-login.php', count: 5)],
  '*': [
    ViolationRule('xmlrpc-all', 'xmlrpc.php',
        count: 7, duration: Duration(minutes: 10))
  ],
  // '*': [ViolationRule('phpmyadmin/', count: 5)] //TODO
};
