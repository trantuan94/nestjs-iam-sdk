// @ts-check
/**
 * Mutation testing for the code that decides allow / deny. A surviving mutant
 * in here is a refusal the suite would not notice going missing.
 *
 *   npm run mutate
 *
 * @type {import('@stryker-mutator/api/core').PartialStrykerOptions}
 */
export default {
  testRunner: 'jest',
  // Every suite for every mutant. `findRelatedTests` (the default) follows
  // imports, and missed the e2e suites that reach the code through
  // examples/ → src/index.ts: 13 of 137 tests ran, and the score was a lie.
  jest: { configFile: 'jest.config.js', enableFindRelatedTests: false },
  mutate: [
    'src/client/iam-authz.client.ts',
    'src/guard/iam-authz.guard.ts',
    'src/checker/iam-authz.service.ts',
    'src/checker/failure.ts',
    'src/guard/resolvers.ts',
    'src/decision/**/*.ts',
    'src/swagger/**/*.ts',
    '!src/**/*.spec.ts',
  ],
  concurrency: 4,
  coverageAnalysis: 'perTest',
  reporters: ['clear-text', 'progress', 'html'],
  htmlReporter: { fileName: 'reports/mutation/index.html' },
  thresholds: { high: 90, low: 80, break: 75 },
};
