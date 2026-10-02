// What the extension's background and the script it puts into a page say
// to each other, over a connection that lasts as long as the page's
// document does.

/** Asks the page's script to find the login form and name its document. */
export type Prepare = { type: "prepare" };

/** Hands the owner's choice to the page's script. */
export type Fill = { type: "fill"; documentId: string; origin: string; username: string; password: string };

export type ToPage = Prepare | Fill;

export type Field = "username" | "password";

/** What the page's script found. No fields means there is nothing to fill. */
export type Prepared = { type: "prepared"; documentId: string; origin: string; fields: Field[] };

/** Which fields were filled; none if the fill was not for this document. */
export type Filled = { type: "filled"; fields: Field[] };

export type FromPage = Prepared | Filled;

declare global {
  /** In a document the page's script was put into: that document's name. */
  // eslint-disable-next-line no-var
  var osmFillDocument: string | undefined;
}
