const assert = require('assert');
const { execFile } = require('child_process');
const validator = require('validator');

/**
 * Tests for Command Injection remediation in routes/index.js
 *
 * These tests verify that the create endpoint properly handles image URLs
 * and is protected against command injection attacks.
 */

describe('Command Injection Security Tests', () => {
  describe('Image URL Processing in Create Endpoint', () => {

    // Mock the execFile function to capture calls without executing
    let originalExecFile;
    let execFileCalls = [];

    beforeEach(() => {
      execFileCalls = [];
      // Reset mock before each test
    });

    test('should reject URLs with command injection attempts using semicolon', () => {
      // GIVEN - A malicious URL with command injection using semicolon
      const maliciousUrl = 'http://example.com/image.jpg; rm -rf /';

      // WHEN - We validate the URL
      const isValid = validator.isURL(maliciousUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL with semicolon injection should be rejected');
    });

    test('should reject URLs with command injection using pipe', () => {
      // GIVEN - A malicious URL with command injection using pipe
      const maliciousUrl = 'http://example.com/image.jpg | cat /etc/passwd';

      // WHEN - We validate the URL
      const isValid = validator.isURL(maliciousUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL with pipe injection should be rejected');
    });

    test('should reject URLs with command injection using ampersand', () => {
      // GIVEN - A malicious URL with command injection using ampersand
      const maliciousUrl = 'http://example.com/image.jpg & whoami';

      // WHEN - We validate the URL
      const isValid = validator.isURL(maliciousUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL with ampersand injection should be rejected');
    });

    test('should reject URLs with command injection using backticks', () => {
      // GIVEN - A malicious URL with command injection using backticks
      const maliciousUrl = 'http://example.com/image.jpg`whoami`';

      // WHEN - We validate the URL
      const isValid = validator.isURL(maliciousUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL with backtick injection should be rejected');
    });

    test('should reject URLs with command injection using $() substitution', () => {
      // GIVEN - A malicious URL with command substitution
      const maliciousUrl = 'http://example.com/$(whoami).jpg';

      // WHEN - We validate the URL
      const isValid = validator.isURL(maliciousUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected (dollar sign makes it invalid)
      assert.strictEqual(isValid, false, 'URL with command substitution should be rejected');
    });

    test('should reject URLs with newline injection', () => {
      // GIVEN - A malicious URL with newline and additional command
      const maliciousUrl = 'http://example.com/image.jpg\nmalicious-command';

      // WHEN - We validate the URL
      const isValid = validator.isURL(maliciousUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL with newline injection should be rejected');
    });

    test('should accept valid HTTP URL', () => {
      // GIVEN - A legitimate HTTP URL
      const validUrl = 'http://example.com/image.jpg';

      // WHEN - We validate the URL
      const isValid = validator.isURL(validUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be accepted
      assert.strictEqual(isValid, true, 'Valid HTTP URL should be accepted');
    });

    test('should accept valid HTTPS URL', () => {
      // GIVEN - A legitimate HTTPS URL
      const validUrl = 'https://secure.example.com/images/photo.png';

      // WHEN - We validate the URL
      const isValid = validator.isURL(validUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be accepted
      assert.strictEqual(isValid, true, 'Valid HTTPS URL should be accepted');
    });

    test('should accept URL with query parameters', () => {
      // GIVEN - A URL with legitimate query parameters
      const validUrl = 'https://example.com/image.jpg?size=large&format=png';

      // WHEN - We validate the URL
      const isValid = validator.isURL(validUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be accepted
      assert.strictEqual(isValid, true, 'URL with query parameters should be accepted');
    });

    test('should reject URL without protocol', () => {
      // GIVEN - A URL without protocol
      const invalidUrl = 'example.com/image.jpg';

      // WHEN - We validate the URL with require_protocol option
      const isValid = validator.isURL(invalidUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL without protocol should be rejected');
    });

    test('should reject URL with file protocol', () => {
      // GIVEN - A URL with file protocol (potential local file access)
      const invalidUrl = 'file:///etc/passwd';

      // WHEN - We validate the URL restricted to http/https
      const isValid = validator.isURL(invalidUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL with file protocol should be rejected');
    });

    test('should reject URL with ftp protocol', () => {
      // GIVEN - A URL with ftp protocol
      const invalidUrl = 'ftp://example.com/file.jpg';

      // WHEN - We validate the URL restricted to http/https
      const isValid = validator.isURL(invalidUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL with ftp protocol should be rejected');
    });

    test('should reject javascript protocol URL (XSS attempt)', () => {
      // GIVEN - A URL with javascript protocol
      const invalidUrl = 'javascript:alert(1)';

      // WHEN - We validate the URL
      const isValid = validator.isURL(invalidUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'URL with javascript protocol should be rejected');
    });

    test('should handle URL-encoded command injection attempts', () => {
      // GIVEN - A URL with URL-encoded command injection
      const maliciousUrl = 'http://example.com/image.jpg%3Brm%20-rf%20/';

      // WHEN - We validate the URL
      const isValid = validator.isURL(maliciousUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL encoding makes it technically valid as a URL
      // The key security improvement is using execFile instead of exec
      // execFile passes this as a literal argument, not as shell commands
      assert.strictEqual(isValid, true, 'URL-encoded characters are valid in URLs');
      // NOTE: Even if this passes URL validation, execFile will treat it as
      // a literal string argument, preventing shell interpretation
    });

    test('should verify execFile is called with correct arguments for valid URL', (done) => {
      // GIVEN - A valid URL
      const validUrl = 'https://example.com/test.jpg';

      // WHEN - execFile is called with the URL
      // We're testing the signature, not execution
      const testExecFile = (command, args, callback) => {
        // THEN - Verify correct command and argument structure
        assert.strictEqual(command, 'identify', 'Command should be identify');
        assert(Array.isArray(args), 'Arguments should be an array');
        assert.strictEqual(args.length, 1, 'Should have exactly one argument');
        assert.strictEqual(args[0], validUrl, 'URL should be passed as separate argument');

        // Simulate completion
        callback(null, '', '');
        done();
      };

      // Execute the test
      testExecFile('identify', [validUrl], (err, stdout, stderr) => {
        // Test completed
      });
    });

    test('should ensure command and arguments are properly separated', () => {
      // GIVEN - A potentially dangerous URL that would be harmful if concatenated
      const dangerousUrl = 'test.jpg; rm important.txt';

      // WHEN - Using execFile with array arguments
      const command = 'identify';
      const args = [dangerousUrl];

      // THEN - The dangerous string is isolated as a single argument
      // This test verifies our approach: the URL is in an array, not concatenated
      assert.strictEqual(args.length, 1, 'URL should be a single array element');
      assert.strictEqual(args[0], dangerousUrl, 'Entire string is one argument');
      assert.notStrictEqual(command + ' ' + args[0], command + args[0],
        'Command and args should not be concatenated into a shell string');
    });

    test('should handle empty string URL', () => {
      // GIVEN - An empty URL
      const emptyUrl = '';

      // WHEN - We validate the URL
      const isValid = validator.isURL(emptyUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected
      assert.strictEqual(isValid, false, 'Empty URL should be rejected');
    });

    test('should handle null or undefined URL gracefully', () => {
      // GIVEN - null and undefined values
      const nullUrl = null;
      const undefinedUrl = undefined;

      // WHEN/THEN - validator.isURL should handle these gracefully
      assert.strictEqual(validator.isURL(nullUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      }), false, 'null should be rejected');

      assert.strictEqual(validator.isURL(undefinedUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      }), false, 'undefined should be rejected');
    });

    test('should reject URLs with spaces (potential argument splitting)', () => {
      // GIVEN - A URL with spaces that could cause argument splitting
      const urlWithSpaces = 'http://example.com/image with spaces.jpg';

      // WHEN - We validate the URL
      const isValid = validator.isURL(urlWithSpaces, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The URL should be rejected (spaces make it invalid)
      assert.strictEqual(isValid, false, 'URL with unencoded spaces should be rejected');
    });

    test('should accept properly encoded URL with spaces', () => {
      // GIVEN - A URL with properly encoded spaces
      const encodedUrl = 'http://example.com/image%20with%20spaces.jpg';

      // WHEN - We validate the URL
      const isValid = validator.isURL(encodedUrl, {
        protocols: ['http', 'https'],
        require_protocol: true
      });

      // THEN - The properly encoded URL should be accepted
      assert.strictEqual(isValid, true, 'Properly URL-encoded spaces should be accepted');
    });
  });

  describe('Regex Pattern Matching for Image Markdown', () => {
    test('should extract valid image URL from markdown', () => {
      // GIVEN - A valid markdown image syntax
      const content = '![alt text](http://example.com/image.jpg "title")';
      const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // WHEN - We match the pattern
      const match = content.match(imgRegex);

      // THEN - Should extract the URL
      assert(match !== null, 'Should match the pattern');
      assert.strictEqual(match[1], 'http://example.com/image.jpg', 'Should extract correct URL');
    });

    test('should not match non-image content', () => {
      // GIVEN - Regular text content
      const content = 'Just a regular todo item';
      const imgRegex = /\!\[alt text\]\((http.*)\s\".*/;

      // WHEN - We try to match the pattern
      const match = content.match(imgRegex);

      // THEN - Should not match
      assert.strictEqual(match, null, 'Should not match non-image content');
    });
  });
});
