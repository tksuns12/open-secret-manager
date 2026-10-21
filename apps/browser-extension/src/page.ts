// What the extension's background and the script it puts into a page say
// to each other, over a connection that lasts as long as the page's
// document does: the page itself, or, for a card, a frame in it.

import { CARD_FIELDS, type CardField, type CardValues } from "./protocol.ts";

/** Asks the page's script to find the login form and the card form, and name its document. */
export type Prepare = { type: "prepare" };

/** Hands the owner's choice to the page's script. */
export type Fill = { type: "fill"; documentId: string; origin: string; username: string; password: string };

/** Hands the owner's card to the script of one document: only the values of the fields it found, the others empty. */
export type FillCard = { type: "fill_card"; documentId: string; origin: string; card: CardValues };

export type ToPage = Prepare | Fill | FillCard;

export type Field = "username" | "password";

/**
 * What the page's script found: the fields of a login form (in the page
 * itself only) and of a card form. None of either means there is nothing
 * to fill. `origin` is the document's own.
 */
export type Prepared = { type: "prepared"; documentId: string; origin: string; fields: Field[]; card: CardField[] };

/** Which fields were filled; none if the fill was not for this document. */
export type Filled = { type: "filled"; fields: Field[] };

/** Which of a card's fields were filled; none if the fill was not for this document. */
export type FilledCard = { type: "filled_card"; fields: CardField[] };

export type FromPage = Prepared | Filled | FilledCard;

const FIELDS: readonly unknown[] = ["username", "password"] satisfies Field[];

/** Whether `fields` names fields of a login form, each at most once. */
function areFields(fields: unknown): fields is Field[] {
  return Array.isArray(fields) && fields.every((field) => FIELDS.includes(field)) && new Set(fields).size === fields.length;
}

/** Whether `fields` names fields of a card form, each at most once; none is allowed. */
function areSomeCardFields(fields: unknown): fields is CardField[] {
  return Array.isArray(fields) && fields.every((field) => CARD_FIELDS.includes(field)) && new Set(fields).size === fields.length;
}

/** Whether `message` is the page's script saying what it found. */
export function isPrepared(message: unknown): message is Prepared {
  const value = message as Partial<Prepared> | null;
  return typeof value === "object" && value !== null && value.type === "prepared" && Object.keys(value).length === 5
    && typeof value.documentId === "string" && /^[A-Za-z0-9-]{1,64}$/.test(value.documentId)
    && typeof value.origin === "string"
    && areFields(value.fields)
    && areSomeCardFields(value.card);
}

/** Whether `message` is the page's script saying which of a card's fields it filled. */
export function isFilledCard(message: unknown): message is FilledCard {
  const value = message as Partial<FilledCard> | null;
  return typeof value === "object" && value !== null && value.type === "filled_card" && areSomeCardFields(value.fields);
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
