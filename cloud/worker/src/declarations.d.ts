// Text-module imports configured via the `rules` entry in wrangler.jsonc.
// The browser script ships as admin.js.txt: wrangler's built-in ESModule rule
// for .js outranks custom Text rules, so a .js extension cannot be imported
// as text.
declare module '*.html' {
  const text: string;
  export default text;
}
declare module '*.txt' {
  const text: string;
  export default text;
}
