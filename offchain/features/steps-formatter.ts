// Prints every scenario with its Gherkin steps and their outcome, then cucumber's summary
// (cucumber 11 has no built-in pretty format, and only one formatter may write to stdout).
import { SummaryFormatter, formatterHelpers, Status, type IFormatterOptions } from '@cucumber/cucumber';

const MARK: Record<string, string> = {
  [Status.PASSED]: '\u001b[32m✔\u001b[0m',
  [Status.FAILED]: '\u001b[31m✘\u001b[0m',
  [Status.SKIPPED]: '\u001b[36m-\u001b[0m',
  [Status.UNDEFINED]: '\u001b[33m?\u001b[0m',
  [Status.PENDING]: '\u001b[33m…\u001b[0m',
};

export default class StepsFormatter extends SummaryFormatter {
  static readonly documentation = 'scenarios with their steps, then the summary';

  constructor(options: IFormatterOptions) {
    super(options);
    let feature = '';
    options.eventBroadcaster.on('envelope', (env) => {
      if (!env.testCaseFinished) return;
      const attempt = this.eventDataCollector.getTestCaseAttempt(env.testCaseFinished.testCaseStartedId);
      const name = attempt.gherkinDocument.feature?.name ?? '';
      if (name !== feature) {
        feature = name;
        this.log(`\nFeature: ${name}\n`);
      }
      this.log(`\n  Scenario: ${attempt.pickle.name}\n`);
      const parsed = formatterHelpers.parseTestCaseAttempt({
        testCaseAttempt: attempt, snippetBuilder: this.snippetBuilder, supportCodeLibrary: this.supportCodeLibrary,
      });
      for (const s of parsed.testSteps) {
        if (!s.text) continue; // hooks
        this.log(`    ${MARK[s.result.status] ?? s.result.status} ${s.keyword}${s.text}\n`);
        if (s.result.status === Status.FAILED && s.result.message) {
          this.log(`        ${s.result.message.split('\n').slice(0, 6).join('\n        ')}\n`);
        }
      }
    });
  }
}
