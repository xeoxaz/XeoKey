# Debug Logging Configuration

XeoKey now supports conditional debug logging that can be controlled via environment variables. This allows you to enable verbose logging when needed for debugging, while keeping production logs clean and performant.

## Configuration

Debug logging can be enabled in two ways:

### Option 1: Using DEBUG Environment Variable

Set `DEBUG=true` or `DEBUG=1` in your `.env` file:

```env
DEBUG=true
```

### Option 2: Using LOG_LEVEL Environment Variable

Set `LOG_LEVEL=debug` in your `.env` file:

```env
LOG_LEVEL=debug
```

## Log Levels

The `LOG_LEVEL` environment variable accepts the following values:

- `debug` - Most verbose, includes all debug messages
- `info` - Default level, includes info, warnings, and errors
- `warn` - Only warnings and errors
- `error` - Only errors

## Default Behavior

- **Development mode**: Log level defaults to `info`
- **Production mode**: Log level defaults to `info`
- **Debug mode**: Automatically enabled if `DEBUG=true` or `LOG_LEVEL=debug`

## Usage in Code

Debug logging is now handled through the `debugLog()` utility function:

```typescript
import { debugLog } from './utils/debug';
import { logger } from './utils/logger';

// This will only log if debug mode is enabled
debugLog(logger, 'Processing request...');
debugLog(logger, `User ID: ${userId}, Action: ${action}`);
```

## Benefits

1. **Performance**: Debug logs are only evaluated when debug mode is enabled
2. **Clean Production Logs**: Production logs won't be cluttered with debug information
3. **Flexible Debugging**: Enable verbose logging when troubleshooting without code changes
4. **Consistent Logging**: All debug logs follow the same conditional pattern

## Example .env Configuration

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
MONGODB_URI=mongodb://localhost:27017

# Security
SESSION_SECRET=your-secret-key
ENCRYPTION_KEY=your-encryption-key

# Debug & Logging Configuration
# Set DEBUG=true or LOG_LEVEL=debug to enable verbose debug logging
DEBUG=false
LOG_LEVEL=info
```

## Troubleshooting

If you're not seeing debug logs:

1. Check that `DEBUG=true` or `LOG_LEVEL=debug` is set in your `.env` file
2. Ensure the `.env` file is in the project root
3. Restart the server after changing environment variables
4. Verify the log level in the logger configuration matches your environment variable

