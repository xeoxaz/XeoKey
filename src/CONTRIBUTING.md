# Contributing to XeoKey

Thank you for your interest in contributing to XeoKey! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Report security issues privately

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/XeoKey.git`
3. Install dependencies: `bun install`
4. Create a new branch: `git checkout -b feature/your-feature-name`

## Development Setup

1. Create a `.env` file (see README.md for required variables)
2. Start MongoDB (if using local instance)
3. Run in development mode: `bun run dev`

## Making Changes

### Code Style

- Use TypeScript with strict mode enabled
- Follow existing code style and formatting
- Use 2 spaces for indentation
- Use meaningful variable and function names
- Add JSDoc comments for public APIs

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (e.g., "Add", "Fix", "Update")
- Reference issues when applicable: "Fix #123"

### Pull Requests

1. Ensure your code follows the project's style guidelines
2. Test your changes thoroughly
3. Update documentation if needed
4. Create a clear PR description explaining:
   - What changes were made
   - Why the changes were made
   - How to test the changes

## Security

- **Never commit secrets or credentials**
- Report security vulnerabilities privately to the maintainers
- Follow security best practices in your code

## Questions?

Feel free to open an issue for questions or discussions about the project.

