// Accessible data-table alternative for every chart (frontend ADD §9, WCAG 2.1 AA).
//
// Charts are not the only way to read the numbers: each chart renders this table alongside it
// (visually hidden by default, exposed via a "show data" toggle and always in the a11y tree).

import type { DataTable as DataTableModel } from "./chartOptions";

export interface DataTableProps {
  table: DataTableModel;
  /** When true the table is visually shown; it is always present for screen readers. */
  visible?: boolean;
}

export function DataTable({ table, visible = false }: DataTableProps): JSX.Element {
  return (
    <table className={visible ? "fathom-data-table" : "sr-only"} aria-label={table.caption}>
      <caption>{table.caption}</caption>
      <thead>
        <tr>
          {table.headers.map((h) => (
            <th key={h} scope="col">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {table.rows.map((row, r) => (
          <tr key={r}>
            {row.map((cell, c) => (
              <td key={c}>{cell}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
