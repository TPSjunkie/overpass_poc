// frontend/jest.config.js
export const testEnvironment = "jsdom";

export default {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  transform: {
    '^.+\\.(ts|tsx)?$': 'ts-jest',
    '^.+\\.(js|jsx)$': 'babel-jest',
  },
  transformIgnorePatterns: ['/node_modules/(?!@ngrx|(?!deck.gl)|ng-dynamic)'],
};



