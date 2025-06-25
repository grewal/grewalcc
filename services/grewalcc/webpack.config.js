const path = require('path');

module.exports = {
  entry: './index.js',  // The main entry point of your application
  output: {
    filename: 'bundle.js', // The name of the bundled output file
    path: path.resolve(__dirname, 'dist'), // Output directory (we'll create this)
  },
  mode: 'development', // Use 'production' for optimized builds
};
