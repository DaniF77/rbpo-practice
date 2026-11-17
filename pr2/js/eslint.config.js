const security = require('eslint-plugin-security');
module.exports = [
  security.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: { sourceType: 'commonjs', ecmaVersion: 2022,
      globals: { require: 'readonly', process: 'readonly', console: 'readonly' } },
    rules: { 'no-eval': 'error', 'no-implied-eval': 'error', 'no-unused-vars': 'warn' },
  },
];
