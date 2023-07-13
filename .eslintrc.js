module.exports = {
    extends: ['prettier', 'plugin:vue/vue3-recommended'],
    plugins: ['prettier', 'simple-import-sort'],
    rules: {
        'prettier/prettier': ['error']
    },
    parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module'
    },
    parser: 'vue-eslint-parser'
};
