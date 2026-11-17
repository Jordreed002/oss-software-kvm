import { useRef, type KeyboardEvent, type ReactNode } from "react";

export interface NavItem<Id extends string> {
  id: Id;
  label: string;
  icon?: ReactNode;
  hint?: string;
}

/** Vertical tab list with roving tabindex: Up/Down (and Left/Right) move,
 *  Home/End jump, selection follows focus. */
export function SectionNav<Id extends string>({
  label,
  items,
  selected,
  onSelect,
  idPrefix,
}: {
  label: string;
  items: readonly NavItem<Id>[];
  selected: Id;
  onSelect: (id: Id) => void;
  idPrefix: string;
}) {
  const refs = useRef(new Map<Id, HTMLButtonElement>());

  const move = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = items.findIndex((item) => item.id === selected);
    let next: number;
    switch (event.key) {
      case "ArrowDown":
      case "ArrowRight":
        next = (index + 1) % items.length;
        break;
      case "ArrowUp":
      case "ArrowLeft":
        next = (index - 1 + items.length) % items.length;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = items.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    const id = items[next].id;
    onSelect(id);
    refs.current.get(id)?.focus();
  };

  return (
    <div className="u-nav" role="tablist" aria-label={label} aria-orientation="vertical" onKeyDown={move}>
      {items.map((item) => {
        const active = item.id === selected;
        return (
          <button
            key={item.id}
            ref={(node) => {
              if (node) refs.current.set(item.id, node);
              else refs.current.delete(item.id);
            }}
            type="button"
            role="tab"
            id={`${idPrefix}-tab-${item.id}`}
            aria-selected={active}
            aria-controls={`${idPrefix}-panel`}
            tabIndex={active ? 0 : -1}
            className="u-nav-item"
            onClick={() => onSelect(item.id)}
          >
            {item.icon}
            <span className="u-nav-label">{item.label}</span>
            {item.hint ? <span className="u-nav-hint" aria-hidden="true">{item.hint}</span> : null}
          </button>
        );
      })}
    </div>
  );
}
