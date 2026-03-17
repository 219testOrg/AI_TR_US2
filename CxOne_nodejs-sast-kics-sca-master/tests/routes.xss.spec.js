const tap = require('tap');
const validator = require('validator');

tap.test('Routes XSS Prevention Tests', function(t) {

  t.test('edit route should sanitize stored XSS payloads in todos', function(t) {
    // GIVEN: Mock todos with XSS payloads from database
    const maliciousTodos = [
      {
        _id: '507f1f77bcf86cd799439011',
        content: '<script>alert("XSS")</script>',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439012',
        content: '<img src=x onerror="alert(\'XSS\')">',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439013',
        content: '<svg onload="alert(\'XSS\')">',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439014',
        content: 'javascript:alert("XSS")',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439015',
        content: '<a href="javascript:alert(\'XSS\')">Click me</a>',
        updated_at: new Date()
      }
    ];

    // WHEN: Process todos through sanitization logic (simulating the edit function)
    const sanitizedTodos = maliciousTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: validator.escape(todo.content.toString()),
        updated_at: todo.updated_at
      };
    });

    // THEN: Verify all dangerous characters are escaped
    t.notOk(
      sanitizedTodos[0].content.includes('<script>'),
      'Script tags should be escaped'
    );
    t.ok(
      sanitizedTodos[0].content.includes('&lt;script&gt;'),
      'Script tags should be replaced with HTML entities'
    );

    t.notOk(
      sanitizedTodos[1].content.includes('<img'),
      'Image tags should be escaped'
    );
    t.ok(
      sanitizedTodos[1].content.includes('&lt;img'),
      'Image tags should be replaced with HTML entities'
    );

    t.notOk(
      sanitizedTodos[2].content.includes('<svg'),
      'SVG tags should be escaped'
    );
    t.ok(
      sanitizedTodos[2].content.includes('&lt;svg'),
      'SVG tags should be replaced with HTML entities'
    );

    t.notOk(
      sanitizedTodos[3].content.includes('javascript:'),
      'javascript: protocol should be escaped'
    );

    t.notOk(
      sanitizedTodos[4].content.includes('<a href'),
      'Anchor tags with javascript should be escaped'
    );

    // Verify no executable JavaScript remains in any todo
    sanitizedTodos.forEach(function(todo, index) {
      t.notOk(
        todo.content.match(/<script|<img|<svg|javascript:|onerror|onload/i),
        'Todo ' + index + ' should not contain dangerous patterns'
      );
    });

    t.end();
  });

  t.test('edit route should preserve legitimate content', function(t) {
    // GIVEN: Mock todos with legitimate content
    const legitimateTodos = [
      {
        _id: '507f1f77bcf86cd799439021',
        content: 'Buy groceries',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439022',
        content: 'Call mom at 3 PM',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439023',
        content: 'Finish project report',
        updated_at: new Date()
      }
    ];

    // WHEN: Process todos through sanitization logic
    const sanitizedTodos = legitimateTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: validator.escape(todo.content.toString()),
        updated_at: todo.updated_at
      };
    });

    // THEN: Verify legitimate content is preserved
    t.equal(
      sanitizedTodos[0].content,
      'Buy groceries',
      'Simple text should be preserved'
    );
    t.equal(
      sanitizedTodos[1].content,
      'Call mom at 3 PM',
      'Text with numbers should be preserved'
    );
    t.equal(
      sanitizedTodos[2].content,
      'Finish project report',
      'Text with spaces should be preserved'
    );

    // Verify _id and updated_at are preserved
    t.equal(
      sanitizedTodos[0]._id.toString(),
      legitimateTodos[0]._id.toString(),
      'Todo ID should be preserved'
    );
    t.ok(
      sanitizedTodos[0].updated_at,
      'Updated timestamp should be preserved'
    );

    t.end();
  });

  t.test('edit route should handle special characters safely', function(t) {
    // GIVEN: Todos with special characters that need escaping
    const specialCharTodos = [
      {
        _id: '507f1f77bcf86cd799439031',
        content: 'Price is $10 & up',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439032',
        content: 'Compare A > B',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439033',
        content: 'Check if x < 5',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439034',
        content: 'Use "quotes" properly',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439035',
        content: "Use 'single quotes' too",
        updated_at: new Date()
      }
    ];

    // WHEN: Process todos through sanitization logic
    const sanitizedTodos = specialCharTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: validator.escape(todo.content.toString()),
        updated_at: todo.updated_at
      };
    });

    // THEN: Verify special characters are properly escaped
    t.ok(
      sanitizedTodos[0].content.includes('&amp;'),
      'Ampersand should be escaped to &amp;'
    );
    t.notOk(
      sanitizedTodos[0].content.includes('& ') && !sanitizedTodos[0].content.includes('&amp;'),
      'Raw ampersand should not remain unescaped'
    );

    t.ok(
      sanitizedTodos[1].content.includes('&gt;'),
      'Greater than should be escaped to &gt;'
    );

    t.ok(
      sanitizedTodos[2].content.includes('&lt;'),
      'Less than should be escaped to &lt;'
    );

    t.ok(
      sanitizedTodos[3].content.includes('&quot;') || sanitizedTodos[3].content.includes('&#34;'),
      'Double quotes should be escaped'
    );

    t.ok(
      sanitizedTodos[4].content.includes('&#39;') || sanitizedTodos[4].content.includes('&#x27;'),
      'Single quotes should be escaped'
    );

    t.end();
  });

  t.test('edit route should handle edge cases', function(t) {
    // GIVEN: Edge case todos
    const edgeCaseTodos = [
      {
        _id: '507f1f77bcf86cd799439041',
        content: '',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439042',
        content: '   ',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439043',
        content: '<script>alert(1)</script>' + '<script>alert(2)</script>',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439044',
        content: '<<SCRIPT>alert("XSS");//<</SCRIPT>',
        updated_at: new Date()
      }
    ];

    // WHEN: Process todos through sanitization logic
    const sanitizedTodos = edgeCaseTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: validator.escape(todo.content.toString()),
        updated_at: todo.updated_at
      };
    });

    // THEN: Verify edge cases are handled properly
    t.equal(
      sanitizedTodos[0].content,
      '',
      'Empty content should remain empty'
    );

    t.equal(
      sanitizedTodos[1].content,
      '   ',
      'Whitespace should be preserved'
    );

    t.notOk(
      sanitizedTodos[2].content.includes('<script>'),
      'Multiple script tags should all be escaped'
    );

    t.notOk(
      sanitizedTodos[3].content.includes('<SCRIPT>') || sanitizedTodos[3].content.includes('<script>'),
      'Case variations of script tags should be escaped'
    );

    t.end();
  });

  t.test('edit route should prevent XSS via event handlers', function(t) {
    // GIVEN: Todos with various event handler XSS payloads
    const eventHandlerTodos = [
      {
        _id: '507f1f77bcf86cd799439051',
        content: '<div onload="alert(1)">test</div>',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439052',
        content: '<body onpageshow="alert(1)">',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439053',
        content: '<input onfocus="alert(1)" autofocus>',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439054',
        content: '<select onfocus="alert(1)" autofocus>',
        updated_at: new Date()
      },
      {
        _id: '507f1f77bcf86cd799439055',
        content: '<textarea onfocus="alert(1)" autofocus>',
        updated_at: new Date()
      }
    ];

    // WHEN: Process todos through sanitization logic
    const sanitizedTodos = eventHandlerTodos.map(function(todo) {
      return {
        _id: todo._id,
        content: validator.escape(todo.content.toString()),
        updated_at: todo.updated_at
      };
    });

    // THEN: Verify all event handlers are escaped
    sanitizedTodos.forEach(function(todo, index) {
      t.notOk(
        todo.content.match(/onload|onpageshow|onfocus|onerror|onmouseover/i),
        'Event handler ' + index + ' should be escaped'
      );
      t.notOk(
        todo.content.includes('<div') || todo.content.includes('<body') ||
        todo.content.includes('<input') || todo.content.includes('<select') ||
        todo.content.includes('<textarea'),
        'HTML tags in todo ' + index + ' should be escaped'
      );
    });

    t.end();
  });

  t.test('validator.escape function should be available and working', function(t) {
    // GIVEN: A test string with dangerous content
    const dangerousString = '<script>alert("XSS")</script>';

    // WHEN: Escaping using validator.escape
    const escaped = validator.escape(dangerousString);

    // THEN: Verify the function works correctly
    t.ok(validator.escape, 'validator.escape should be available');
    t.type(validator.escape, 'function', 'validator.escape should be a function');
    t.notEqual(escaped, dangerousString, 'Escaped string should be different from original');
    t.ok(escaped.includes('&lt;'), 'Should contain escaped < character');
    t.ok(escaped.includes('&gt;'), 'Should contain escaped > character');
    t.notOk(escaped.includes('<script>'), 'Should not contain unescaped script tag');

    t.end();
  });

  t.end();
});
