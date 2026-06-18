// Placeholder for the dependent surfaces not built by the viewer task (Duplicates/Scans/
// Agents/Audit/Settings). Duplicates + RemediationWizard hook into the separate remediation
// gated write-mode component (ADR-011, AR-0006), which the viewer does NOT build.

export interface PlaceholderProps {
  title: string;
}

export function Placeholder({ title }: PlaceholderProps): JSX.Element {
  return (
    <section aria-labelledby="ph-title">
      <h1 id="ph-title">{title}</h1>
      <p>This surface is delivered by a dependent component and is not part of the viewer.</p>
    </section>
  );
}
