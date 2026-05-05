module.exports = {
  default: {
    requireModule: ['ts-node/register'],
    require: ['features/**/*.ts', 'features/**/*.js'],
    paths: ['features/**/*.feature'],
    formatOptions: { snippetInterface: 'synchronous' },
  },
};
