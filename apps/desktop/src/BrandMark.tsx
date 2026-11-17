// The app's mark, drawn by scripts/icons.mjs: change it there.
export function BrandMark({ size }: { size: number }) {
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 2048 2048"><rect width="2048" height="2048" rx="460" fill="#DDA45B"/><g transform="translate(1024 1024) scale(1.12) translate(-1024 -1024)"><path d="M1024 341Q774 520 424 555C420 1205 544 1471 1024 1706C1504 1471 1628 1205 1624 555Q1274 520 1024 341Z" fill="#17130E"/><g fill="#17130E"><circle cx="570" cy="1285" r="170"/><circle cx="1478" cy="1285" r="170"/></g><path d="M1024 508L570 1285H1478Z" fill="none" stroke="#F4ECE0" strokeWidth="64" strokeLinejoin="round"/><g fill="#F4ECE0"><circle cx="1024" cy="508" r="110"/><circle cx="570" cy="1285" r="110"/><circle cx="1478" cy="1285" r="110"/></g><path d="M972 1026A111 111 0 1 1 1076 1026L1119 1228H929Z" fill="#DDA45B"/></g></svg>
  );
}
