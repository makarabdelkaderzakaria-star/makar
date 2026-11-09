/**
 * Ambient declarations for the assets that the bundler inlines.
 */
declare module 'virtual:fonts' {
  /** base64-encoded woff2 payloads, keyed by face name. */
  export const fonts: Record<string, string>;
}

declare module 'virtual:worker' {
  /**
   * The source of the search worker, inlined into the bundle.
   *
   * A single-file executable has no file beside it, so the worker is written
   * out to a temporary file the first time it is needed.
   */
  export const workerSource: string;
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
