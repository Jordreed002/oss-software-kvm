import { useCallback, useState } from "react";

export type SortDir = "asc" | "desc";

/** Click-to-sort state for a table column set. Clicking the active column
 *  flips the direction; clicking another column switches to it, descending. */
export function useSort<K extends string>(initialKey: K, initialDir: SortDir) {
  const [key, setKey] = useState<K>(initialKey);
  const [dir, setDir] = useState<SortDir>(initialDir);
  const toggle = useCallback(
    (clicked: K) => {
      if (clicked === key) {
        setDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setKey(clicked);
        setDir("desc");
      }
    },
    [key],
  );
  return { key, dir, toggle };
}

/** A `<th>` whose label is a sort button. Shows ▲/▼ on the active column and a
 *  faint ↕ hint on the others so the whole header row reads as interactive. */
export function SortTh({
  text,
  active,
  dir,
  onClick,
}: {
  text: string;
  active: boolean;
  dir: SortDir;
  onClick: () => void;
}) {
  return (
    <th scope="col">
      <button type="button" className={`dash-sort${active ? " active" : ""}`} onClick={onClick}>
        {text}
        <span className="dash-sort-arrow" aria-hidden="true">{active ? (dir === "asc" ? "▲" : "▼") : "↕"}</span>
      </button>
    </th>
  );
}
