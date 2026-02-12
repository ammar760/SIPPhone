const path = require('path');

module.exports = {
  mode: 'production',
  entry: './src/entry.js',
  output: {
    filename: 'jssip-bundle.js',
    path: path.resolve(__dirname, 'dist'),
  },
  resolve: {
    fallback: {
      // JsSIP references some Node.js builtins which aren't needed in browser
      "fs": false,
      "net": false,
      "tls": false,
    }
  }
};
