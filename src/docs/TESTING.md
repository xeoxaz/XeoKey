# Testing Documentation

XeoKey now includes a comprehensive test suite with both unit and integration tests.

## Quick Start

```bash
# Run all tests
bun test

# Run only unit tests
bun test:unit

# Run only integration tests
bun test:integration

# Run tests in watch mode
bun test:watch

# Run tests with coverage
bun test:coverage
```

## Test Coverage

### Unit Tests (`tests/unit/`)

- **sanitize.test.ts** - Input sanitization and validation
  - String sanitization
  - Website name sanitization
  - Username sanitization
  - Username validation
  - Password validation

- **csrf.test.ts** - CSRF token management
  - Token creation
  - Token verification
  - Token expiration
  - Token deletion

- **rateLimit.test.ts** - Rate limiting
  - Request limiting
  - Different limits per endpoint
  - Different limits per IP
  - Rate limit reset

- **password-encryption.test.ts** - Encryption configuration
  - Environment variable setup
  - Test configuration

### Integration Tests (`tests/integration/`)

- **auth.test.ts** - Authentication flow
  - User creation
  - User authentication
  - Session management
  - Duplicate user prevention

- **password.test.ts** - Password management
  - Password entry creation
  - Password encryption/decryption
  - Password retrieval
  - Password updates
  - Password deletion

## Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── sanitize.test.ts
│   ├── csrf.test.ts
│   ├── rateLimit.test.ts
│   └── password-encryption.test.ts
├── integration/            # Integration tests
│   ├── auth.test.ts
│   └── password.test.ts
├── helpers/                # Test utilities
│   └── test-utils.ts
└── README.md              # Test documentation
```

## Test Utilities

The `tests/helpers/test-utils.ts` file provides:

- `setupTestEnv()` - Configure test environment
- `cleanupTestEnv()` - Clean up after tests
- `connectTestDatabase()` - Connect to test database
- `dropTestDatabase()` - Clean test database
- `createTestRequest()` - Create HTTP requests for testing
- `createAuthenticatedRequest()` - Create authenticated requests
- `randomString()` - Generate random test data
- `sleep()` - Wait for async operations

## Test Database

Tests use a separate database (`XeoKey_Test`) to avoid affecting development data.

Set `TEST_MONGODB_URI` to use a different MongoDB instance:

```bash
TEST_MONGODB_URI=mongodb://localhost:27017 bun test
```

## Writing New Tests

### Unit Test Example

```typescript
import { describe, it, expect } from 'bun:test';
import { myFunction } from '../../path/to/module';

describe('myFunction', () => {
  it('should do something', () => {
    expect(myFunction('input')).toBe('expected');
  });
});
```

### Integration Test Example

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

## Best Practices

1. **Isolation**: Each test should be independent
2. **Cleanup**: Always clean up test data
3. **Naming**: Use descriptive test names
4. **Speed**: Keep tests fast
5. **Coverage**: Test critical paths
6. **Clarity**: Write readable tests

## CI/CD Integration

Tests are designed to run in CI/CD pipelines:

- No manual intervention required
- Automatic cleanup
- Works in headless environments
- Fast execution

## Troubleshooting

### Tests fail with "Database not connected"

Make sure MongoDB is running and accessible:

```bash
# Check MongoDB status
mongosh --eval "db.adminCommand('ping')"
```

### Tests are slow

- Use `TEST_MONGODB_URI` to point to a local test instance
- Ensure MongoDB is running locally
- Check network connectivity

### Integration tests fail

- Verify MongoDB is running
- Check `TEST_MONGODB_URI` is correct
- Ensure test database can be created

