// Settings page (ADD 13): the account panel, per-user MFA (TOTP) enrolment, and the admin-only
// Users & roles tab. Covers that the MFA enrol flow reveals the QR + confirm form, and that the
// user-management tab is gated on manage_users (hidden for a viewer, shown for an admin).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../../api/client";

const { apiGet, apiPost, apiDelete } = vi.hoisted(() => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
  apiDelete: vi.fn(),
}));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost, apiDelete };
});

const { Settings } = await import("./Settings");

const ME_VIEWER = {
  subject: "alice",
  source: "local",
  display_name: "Alice",
  groups: [],
  grants: [{ role: "viewer", scope_kind: "global", host_id: null, volume_id: null }],
  mfa_fresh: false,
  mfa_enrolled: false,
};
const ME_ADMIN = {
  ...ME_VIEWER,
  subject: "root",
  grants: [{ role: "admin", scope_kind: "global", host_id: null, volume_id: null }],
};

const ME_ENROLLED = { ...ME_VIEWER, mfa_enrolled: true };

const PROVISIONING_URI =
  "otpauth://totp/Fathom:alice?secret=JBSWY3DPEHPK3PXP&issuer=Fathom";

const USER_BOB = {
  id: 5,
  subject: "bob",
  source: "local",
  display_name: "Bob",
  is_active: true,
};
const ASSIGNMENT = {
  id: 11,
  user_id: 5,
  role: "operator",
  scope_kind: "global",
  host_id: null,
  volume_id: null,
};
const VOLUME = {
  id: 3,
  host_id: 1,
  mountpoint: "/mnt/data",
  fs_type: "ext4",
  device: "/dev/sda1",
  transport: "sata",
  raid_role: null,
  total: 100,
  used: 50,
  free: 50,
};

function meRouter(me: object) {
  return (url: string) => (url.startsWith("/auth/me") ? Promise.resolve(me) : Promise.resolve([]));
}

// Admin GET router for the Users & roles tab: /auth/me → admin; the assignments sub-resource is
// matched BEFORE the bare /users list (the path startsWith("/users") otherwise swallows it).
function adminRouter({
  users = [] as object[],
  assignments = [] as object[],
  volumes = [] as object[],
} = {}) {
  return (url: string) => {
    if (url.startsWith("/auth/me")) return Promise.resolve(ME_ADMIN);
    if (url.includes("/assignments")) return Promise.resolve(assignments);
    if (url.startsWith("/users")) return Promise.resolve(users);
    if (url.startsWith("/volumes")) return Promise.resolve(volumes);
    return Promise.resolve([]);
  };
}

// Render as admin, open the Users & roles tab, and expand the first user's assignment editor.
async function openAssignmentEditor(): Promise<void> {
  fireEvent.click(await screen.findByRole("tab", { name: /users & roles/i }));
  fireEvent.click(await screen.findByRole("button", { name: "Manage" }));
}

function wrap(node: JSX.Element): ReturnType<typeof render> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(() => vi.clearAllMocks());

describe("Settings page", () => {
  it("shows the account subject and an MFA setup button; no Users tab for a viewer", async () => {
    apiGet.mockImplementation(meRouter(ME_VIEWER));
    wrap(<Settings />);

    expect(await screen.findByText("alice")).toBeInTheDocument(); // the principal subject
    expect(screen.getByRole("button", { name: /set up mfa/i })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: /users & roles/i })).not.toBeInTheDocument();
  });

  it("reveals the QR + confirm form after starting MFA enrolment", async () => {
    apiGet.mockImplementation(meRouter(ME_VIEWER));
    apiPost.mockResolvedValue({
      provisioning_uri: "otpauth://totp/Fathom:alice?secret=JBSWY3DPEHPK3PXP&issuer=Fathom",
    });
    wrap(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /set up mfa/i }));

    // The enrol response renders the confirm form + the hand-entry secret.
    expect(await screen.findByRole("button", { name: /verify & enable/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/mfa enrolment qr code/i)).toBeInTheDocument();
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
  });

  it("exposes the Users & roles tab for an admin (manage_users)", async () => {
    apiGet.mockImplementation(meRouter(ME_ADMIN));
    wrap(<Settings />);

    expect(await screen.findByRole("tab", { name: /users & roles/i })).toBeInTheDocument();
  });

  // --- MFA enrol → verify (UC-mfa-2/4, UC-auth-4/5, EC-mfa-2/3) -----------------------------

  it("verifies a 6-digit code: calls useMfaVerify and shows 'MFA enabled.'", async () => {
    apiGet.mockImplementation(meRouter(ME_VIEWER));
    apiPost.mockResolvedValue({ provisioning_uri: PROVISIONING_URI });
    wrap(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /set up mfa/i }));
    fireEvent.change(await screen.findByLabelText("Code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: /verify & enable/i }));

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith("/auth/mfa/verify", { code: "123456" }),
    );
    expect(await screen.findByText(/MFA enabled\./i)).toBeInTheDocument();
  });

  it("shows an alert when the verification code is rejected", async () => {
    apiGet.mockImplementation(meRouter(ME_VIEWER));
    apiPost.mockImplementation((url: string) =>
      url === "/auth/mfa/enroll"
        ? Promise.resolve({ provisioning_uri: PROVISIONING_URI })
        : Promise.reject(new ApiError(400, { title: "bad code" })),
    );
    wrap(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /set up mfa/i }));
    fireEvent.change(await screen.findByLabelText("Code"), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: /verify & enable/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid code/i);
  });

  it("keeps 'Verify & enable' disabled until the code is at least 6 digits", async () => {
    apiGet.mockImplementation(meRouter(ME_VIEWER));
    apiPost.mockResolvedValue({ provisioning_uri: PROVISIONING_URI });
    wrap(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /set up mfa/i }));
    const verifyBtn = await screen.findByRole("button", { name: /verify & enable/i });
    expect(verifyBtn).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Code"), { target: { value: "12345" } });
    expect(verifyBtn).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Code"), { target: { value: "123456" } });
    expect(verifyBtn).toBeEnabled();
  });

  it("shows 'enabled' status and a re-enrol button when MFA is already enrolled", async () => {
    apiGet.mockImplementation(meRouter(ME_ENROLLED));
    wrap(<Settings />);

    expect(
      await screen.findByRole("button", { name: /re-enrol authenticator/i }),
    ).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
  });

  // ACTUAL-BEHAVIOUR (EC-mfa-19): MfaSetup reads whoami directly and is NOT wrapped in QueryState
  // (only MyAccount is). So the MFA card + button render immediately even while whoami is loading.
  it("renders the MFA setup button even while whoami is still loading (no QueryState gate)", () => {
    apiGet.mockImplementation((url: string) =>
      url.startsWith("/auth/me") ? new Promise(() => {}) : Promise.resolve([]),
    );
    wrap(<Settings />);

    expect(screen.getByRole("button", { name: /set up mfa/i })).toBeInTheDocument();
    // MyAccount, which DOES gate on QueryState, shows the loading state at the same time.
    expect(screen.getByRole("status")).toHaveTextContent(/loading/i);
  });

  // --- admin Users & roles: assignment editor (UC-rbac-3..6, EC-rbac-3/12/13) ---------------

  it("shows 'No role assignments.' when an expanded user has no grants", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB], assignments: [] }));
    wrap(<Settings />);
    await openAssignmentEditor();

    expect(await screen.findByText(/no role assignments/i)).toBeInTheDocument();
  });

  it("lists an existing assignment and revokes it via useDeleteAssignment", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB], assignments: [ASSIGNMENT] }));
    apiDelete.mockResolvedValue(undefined);
    wrap(<Settings />);
    await openAssignmentEditor();

    expect(await screen.findByText("operator")).toBeInTheDocument(); // the role badge
    fireEvent.click(screen.getByRole("button", { name: /revoke/i }));

    await waitFor(() =>
      expect(apiDelete).toHaveBeenCalledWith("/users/5/assignments/11"),
    );
  });

  it("grants a global-scoped role with the default-scope body", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB] }));
    apiPost.mockResolvedValue({});
    wrap(<Settings />);
    await openAssignmentEditor();

    fireEvent.click(await screen.findByRole("button", { name: "Grant" }));

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith("/users/5/assignments", {
        role: "viewer",
        scope_kind: "global",
        host_id: null,
        volume_id: null,
      }),
    );
  });

  it("grants a host-scoped role carrying the entered host id", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB] }));
    apiPost.mockResolvedValue({});
    wrap(<Settings />);
    await openAssignmentEditor();

    fireEvent.change(await screen.findByLabelText("Scope"), { target: { value: "host" } });
    fireEvent.change(await screen.findByLabelText(/host id/i), { target: { value: "7" } });
    fireEvent.click(screen.getByRole("button", { name: "Grant" }));

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith("/users/5/assignments", {
        role: "viewer",
        scope_kind: "host",
        host_id: 7,
        volume_id: null,
      }),
    );
  });

  it("grants a volume-scoped role chosen from the volumes dropdown", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB], volumes: [VOLUME] }));
    apiPost.mockResolvedValue({});
    wrap(<Settings />);
    await openAssignmentEditor();

    fireEvent.change(await screen.findByLabelText("Scope"), { target: { value: "volume" } });
    await screen.findByRole("option", { name: "/mnt/data" }); // dropdown fed from useVolumes
    fireEvent.change(screen.getByLabelText("Volume"), { target: { value: "3" } });
    fireEvent.click(screen.getByRole("button", { name: "Grant" }));

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith("/users/5/assignments", {
        role: "viewer",
        scope_kind: "volume",
        host_id: null,
        volume_id: 3,
      }),
    );
  });

  it("renders the inline error when a grant is rejected (422)", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB] }));
    apiPost.mockRejectedValue(new ApiError(422, { detail: "host_id required for host scope" }));
    wrap(<Settings />);
    await openAssignmentEditor();

    fireEvent.click(await screen.findByRole("button", { name: "Grant" }));

    expect(await screen.findByText(/host_id required for host scope/i)).toBeInTheDocument();
  });

  // ACTUAL-BEHAVIOUR (EC-rbac-12/13): Grant is gated ONLY on create.isPending — NOT on a selected
  // host/volume. With scope=volume and nothing picked it stays enabled and submits volume_id null
  // (the server is authoritative and 422s). The gap's "disabled until selected" is not implemented.
  it("does not gate Grant on selection — submits volume_id null when no volume is picked", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB], volumes: [VOLUME] }));
    apiPost.mockResolvedValue({});
    wrap(<Settings />);
    await openAssignmentEditor();

    fireEvent.change(await screen.findByLabelText("Scope"), { target: { value: "volume" } });
    const grant = screen.getByRole("button", { name: "Grant" });
    expect(grant).toBeEnabled();
    fireEvent.click(grant);

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith("/users/5/assignments", {
        role: "viewer",
        scope_kind: "volume",
        host_id: null,
        volume_id: null,
      }),
    );
  });

  // --- admin Users & roles: create-user form (POST /users; UC-rbac-1, EC-rbac-2) ------------

  const NEW_USER = {
    id: 9,
    subject: "carol",
    source: "local",
    display_name: null,
    is_active: true,
  };

  it("shows the create-user form on the Users & roles tab for an admin", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB] }));
    wrap(<Settings />);

    fireEvent.click(await screen.findByRole("tab", { name: /users & roles/i }));

    expect(await screen.findByRole("button", { name: /create user/i })).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("does not show the create-user form for a viewer (no Users & roles tab)", async () => {
    apiGet.mockImplementation(meRouter(ME_VIEWER));
    wrap(<Settings />);

    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /create user/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Username")).not.toBeInTheDocument();
  });

  it("submits the create-user POST with the username + password body", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB] }));
    apiPost.mockResolvedValue(NEW_USER);
    wrap(<Settings />);

    fireEvent.click(await screen.findByRole("tab", { name: /users & roles/i }));
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "carol" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret-password" } });
    fireEvent.click(screen.getByRole("button", { name: /create user/i }));

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith("/users", {
        username: "carol",
        password: "secret-password",
      }),
    );
  });

  it("shows an inline 'User already exists.' error on a 409", async () => {
    apiGet.mockImplementation(adminRouter({ users: [USER_BOB] }));
    apiPost.mockRejectedValue(new ApiError(409, { detail: "user exists" }));
    wrap(<Settings />);

    fireEvent.click(await screen.findByRole("tab", { name: /users & roles/i }));
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "bob" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret-password" } });
    fireEvent.click(screen.getByRole("button", { name: /create user/i }));

    expect(await screen.findByText(/user already exists/i)).toBeInTheDocument();
  });

  it("clears the form and lists the new user after a successful create", async () => {
    // Stateful list: POST appends, so the invalidation-driven refetch returns the new user.
    const userList: object[] = [];
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/auth/me")) return Promise.resolve(ME_ADMIN);
      if (url.includes("/assignments")) return Promise.resolve([]);
      if (url.startsWith("/users")) return Promise.resolve([...userList]);
      return Promise.resolve([]);
    });
    apiPost.mockImplementation((_url: string, body: { username: string }) => {
      userList.push({ ...NEW_USER, subject: body.username });
      return Promise.resolve(NEW_USER);
    });
    wrap(<Settings />);

    fireEvent.click(await screen.findByRole("tab", { name: /users & roles/i }));
    const usernameInput = (await screen.findByLabelText("Username")) as HTMLInputElement;
    fireEvent.change(usernameInput, { target: { value: "carol" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret-password" } });
    fireEvent.click(screen.getByRole("button", { name: /create user/i }));

    // Form clears on success…
    await waitFor(() => expect(usernameInput.value).toBe(""));
    // …and the new user appears in the table after the admin-users refetch.
    expect(await screen.findByText("carol")).toBeInTheDocument();
  });
});
