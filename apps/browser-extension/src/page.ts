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

const FIELDS: readonly unknown[] = ["username", "password"] satisfies Field[];

/** Whether `fields` names fields of a login form, each at most once. */
function areFields(fields: unknown): fields is Field[] {
  return Array.isArray(fields) && fields.every((field) => FIELDS.includes(field)) && new Set(fields).size === fields.length;
}

/** Whether `message` is the page's script saying what it found. */
export function isPrepared(message: unknown): message is Prepared {
  const value = message as Partial<Prepared> | null;
  return typeof value === "object" && value !== null && value.type === "prepared"
    && typeof value.documentId === "string" && /^[A-Za-z0-9-]{1,64}$/.test(value.documentId)
    && typeof value.origin === "string"
    && areFields(value.fields);
}

/** Whether `message` is the page's script saying which fields it filled. */
export function isFilled(message: unknown): message is Filled {
  const value = message as Partial<Filled> | null;
  return typeof value === "object" && value !== null && value.type === "filled" && areFields(value.fields);
}

declare global {
  /** In a document the page's script was put into: that document's name. */
  // eslint-disable-next-line no-var
  var osmFillDocument: string | undefined;
}
