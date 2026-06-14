declare module '*.csv?raw' {
  const content: string;
  export default content;
}

declare module '*.csv' {
  const src: string;
  export default src;
}
