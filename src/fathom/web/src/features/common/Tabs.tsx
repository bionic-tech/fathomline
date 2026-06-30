// Accessible tab set (WAI-ARIA tabs pattern): a horizontal tablist + one visible panel. Used to
// break long settings pages into sections. Active panel content is rendered lazily (only the
// selected tab mounts), so heavy panels don't all render at once. Left/Right/Home/End move focus.

import { useId, useRef, useState } from "react";

export interface TabDef {
  id: string;
  label: string;
  content: JSX.Element;
}

export function Tabs({
  tabs,
  ariaLabel,
  initialId,
}: {
  tabs: TabDef[];
  ariaLabel: string;
  initialId?: string;
}): JSX.Element {
  const base = useId();
  const [active, setActive] = useState<string>(initialId ?? tabs[0]?.id ?? "");
  const btnRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  if (tabs.length === 0) return <></>;
  const activeId = tabs.some((t) => t.id === active) ? active : tabs[0].id;

  const onKeyDown = (e: React.KeyboardEvent, index: number): void => {
    const last = tabs.length - 1;
    let next = -1;
    if (e.key === "ArrowRight") next = index === last ? 0 : index + 1;
    else if (e.key === "ArrowLeft") next = index === 0 ? last : index - 1;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = last;
    if (next >= 0) {
      e.preventDefault();
      const id = tabs[next].id;
      setActive(id);
      btnRefs.current[id]?.focus();
    }
  };

  return (
    <div className="fathom-tabset">
      <div role="tablist" aria-label={ariaLabel} className="fathom-tablist">
        {tabs.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              btnRefs.current[t.id] = el;
            }}
            type="button"
            role="tab"
            id={`${base}-tab-${t.id}`}
            aria-controls={`${base}-panel-${t.id}`}
            aria-selected={activeId === t.id}
            tabIndex={activeId === t.id ? 0 : -1}
            className={`fathom-tab ${activeId === t.id ? "fathom-tab-active" : ""}`}
            onClick={() => setActive(t.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tabs.map((t) => (
        <div
          key={t.id}
          role="tabpanel"
          id={`${base}-panel-${t.id}`}
          aria-labelledby={`${base}-tab-${t.id}`}
          hidden={activeId !== t.id}
          className="fathom-tabpanel"
        >
          {activeId === t.id ? t.content : null}
        </div>
      ))}
    </div>
  );
}
