# Testing Guide

This directory contains unit and integration tests for XeoKey.

## Test Structure

```
tests/
├── unit/              # Unit tests for individual functions/modules
│   ├── sanitize.test.ts
│   ├── csrf.test.ts
│   ├── rateLimit.test.ts
│   └── password-encryption.test.ts
├── integration/       # Integration tests for API endpoints and database
│   ├── auth.test.ts
│   └── password.test.ts
└── helpers/           # Test utilities and helpers
    └── test-utils.ts
```

## Running Tests

### Run all tests
```bash
bun test
```

### Run only unit tests
```bash
bun test:unit
```

### Run only integration tests
```bash
bun test:integration
```

### Run tests in watch mode
```bash
bun test:watch
```

### Run tests with coverage
```bash
bun test:coverage
```

## Test Environment

Tests use a separate test database (`XeoKey_Test`) to avoid affecting development data.

### Environment Variables for Testing

Tests automatically set up the following environment variables:
- `NODE_ENV=test`
- `MONGODB_URI` (from `TEST_MONGODB_URI` or defaults to `mongodb://localhost:27017`)
- `SESSION_SECRET` (test secret)
- `ENCRYPTION_KEY` (test key)
- `LOG_LEVEL=error` (suppress logs during tests)

You can override the MongoDB URI by setting `TEST_MONGODB_URI`:

```bash
TEST_MONGODB_URI=mongodb://localhost:27017 bun test
```

## Writing Tests

### Unit Tests

Unit tests should test individual functions in isolation:

```typescript
import { describe, it, expect } from 'bun:test';
import { myFunction } from '../../path/to/module';

describe('myFunction', () => {
  it('should do something', () => {
    expect(myFunction('input')).toBe('expected');
  });
});
```

### Integration Tests

Integration tests should test the interaction between multiple components:

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { setupTestEnv, cleanupTestEnv } from '../helpers/test-utils';
import { connectMongoDB, closeMongoDB } from '../../db/mongodb';

describe('Feature Integration', () => {
  beforeAll(async () => {
    setupTestEnv();
    await connectMongoDB();
  });

  afterAll(async () => {
    await closeMongoDB();
    cleanupTestEnv();
  });

  it('should work end-to-end', async () => {
    // Test implementation
  });
});
```

## Test Utilities

The `test-utils.ts` file provides helpful utilities:

- `setupTestEnv()` - Set up test environment variables
- `cleanupTestEnv()` - Clean up test environment
- `connectTestDatabase()` - Connect to test database
- `dropTestDatabase()` - Drop all collections
- `createTestRequest()` - Create test HTTP requests
- `createAuthenticatedRequest()` - Create authenticated requests
- `randomString()` - Generate random strings for testing
- `sleep()` - Wait for a specified time

## Best Practices

1. **Isolation**: Each test should be independent and not rely on other tests
2. **Cleanup**: Always clean up test data after tests
3. **Naming**: Use descriptive test names that explain what is being tested
4. **Coverage**: Aim for high test coverage of critical paths
5. **Speed**: Keep tests fast - use mocks for slow operations when possible
6. **Clarity**: Write clear, readable tests that serve as documentation

## Continuous Integration

Tests should pass in CI/CD pipelines. Make sure:
- Tests don't require manual intervention
- Tests clean up after themselves
- Tests work in headless environments
- Tests don't depend on external services (unless necessary)

