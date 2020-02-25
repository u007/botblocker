const defaultRuleDuration = Duration(minutes: 15);

class ViolationRule {
  final String url;
  final bool exact;
  final int count;
  final Duration duration;
  ViolationRule(this.url,
      {this.exact: false, this.count: 1, this.duration: defaultRuleDuration});
}

final Map<String, List<ViolationRule>> violationConfig = {
  'apache.log': [ViolationRule('/wp-login.php', count: 5)]
};
