/** Small DOM helpers. No model logic lives here. */

export const escape = (value: unknown): string =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c]!,
  );

export function el<T extends HTMLElement = HTMLElement>(
  selector: string,
  root: ParentNode = document,
): T {
  const node = root.querySelector<T>(selector);
  if (!node) throw new Error(`missing element ${selector}`);
  return node;
}

export function field(
  id: string,
  label: string,
  value: string,
  attributes = 'type="text" inputmode="decimal"',
): string {
  return `<div class="field"><label for="${id}">${escape(label)}</label><input id="${id}" ${attributes} value="${escape(value)}" autocomplete="off" spellcheck="false" /></div>`;
}

export function select(
  id: string,
  label: string,
  options: readonly (readonly [string, string])[],
  selected: string,
): string {
  const body = options
    .map(
      ([v, text]) =>
        `<option value="${escape(v)}"${v === selected ? " selected" : ""}>${escape(text)}</option>`,
    )
    .join("");
  return `<div class="field"><label for="${id}">${escape(label)}</label><select id="${id}">${body}</select></div>`;
}

export function checkbox(id: string, label: string, checked: boolean): string {
  return `<div class="field"><label for="${id}">${escape(label)}</label><input id="${id}" type="checkbox"${checked ? " checked" : ""} /></div>`;
}

export function metrics(
  values: readonly (readonly [string, unknown])[],
): string {
  return `<div class="metrics">${values
    .map(
      ([label, value]) =>
        `<div class="metric"><strong>${escape(value)}</strong><span>${escape(label)}</span></div>`,
    )
    .join("")}</div>`;
}

export function table(
  headers: readonly string[],
  rows: readonly (readonly unknown[])[],
  label: string,
  id = "",
): string {
  // Every cell carries its column name. Below the stacking breakpoint the
  // table becomes a list of labelled rows, so a transcript this wide never
  // needs a horizontal scroller on a phone. Cells clipped inside a scroller
  // are reported by accessibility tooling as obscured, which makes them
  // unmeasurable rather than merely awkward.
  return `<div class="table-wrap" tabindex="0" role="region" aria-label="${escape(label)}"${id ? ` id="${escape(id)}"` : ""}><table><caption class="sr-only">${escape(label)}</caption><thead><tr>${headers
    .map((h) => `<th scope="col">${escape(h)}</th>`)
    .join("")}</tr></thead><tbody>${rows
    .map(
      (row) =>
        `<tr>${row
          .map(
            (cell, index) =>
              `<td data-label="${escape(headers[index] ?? "")}">${escape(cell)}</td>`,
          )
          .join("")}</tr>`,
    )
    .join("")}</tbody></table></div>`;
}

export function verdict(
  kind: "ok" | "bad" | "warn",
  title: string,
  body: string,
  marker = "",
): string {
  return `<div class="verdict ${kind}"${marker ? ` data-verdict="${escape(marker)}"` : ""}><strong>${escape(title)}</strong><p>${escape(body)}</p></div>`;
}
