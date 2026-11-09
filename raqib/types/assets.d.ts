/**
 * Ambient declarations for the assets that the bundler inlines.
 */
declare module 'virtual:fonts' {
  /** base64-encoded woff2 payloads, keyed by face name. */
  export const fonts: Record<string, string>;
}

declare module '*.html' {
  const content: string;
  export default content;
}

declare module '*.css' {
  const content: string;
  export default content;
}

declare module '*.ui.js' {
  const content: string;
  export default content;
}
