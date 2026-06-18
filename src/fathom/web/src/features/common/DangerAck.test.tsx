import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DangerAck } from "./DangerAck";

describe("DangerAck", () => {
  it("keeps Confirm disabled until the exact host name is typed", () => {
    const onConfirm = vi.fn();
    render(
      <DangerAck
        hostName="nas-1"
        paths={["/etc/passwd", "/mnt/docker_data/x"]}
        actionLabel="quarantine"
        pending={false}
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );
    const confirm = screen.getByRole("button", { name: /confirm quarantine/i });
    expect(confirm).toBeDisabled();

    const input = screen.getByLabelText(/type the host name/i);
    fireEvent.change(input, { target: { value: "wrong" } });
    expect(confirm).toBeDisabled();

    fireEvent.change(input, { target: { value: "nas-1" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalledWith("nas-1");
  });

  it("warns about high-risk (OS/service) paths", () => {
    render(
      <DangerAck
        hostName="h1"
        paths={["/etc/passwd"]}
        actionLabel="quarantine"
        pending={false}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByRole("alert").textContent).toMatch(/step-up mfa is required/i);
  });
});
