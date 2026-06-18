// Login surface (frontend ADD §5/§12). Username + password -> POST /api/v1/auth/login, which
// mints the httpOnly Secure session cookie server-side (no token is returned or stored client
// side). On success we invalidate the whoami query so the auth guard re-reads the principal,
// then navigate to /dashboard. On failure we show a sanitised inline error (no stack trace).

import { useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";

import { ApiError } from "../api/client";
import { login } from "./session";

export function LoginPage(): JSX.Element {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login({ username, password });
      // Force the guard's whoami() to re-run against the freshly-minted cookie.
      await queryClient.invalidateQueries({ queryKey: ["whoami"] });
      navigate("/dashboard", { replace: true });
    } catch (err) {
      // Surface a sanitised message only (frontend ADD §11 — never render a stack trace).
      const message =
        err instanceof ApiError && err.status === 401
          ? "Incorrect username or password."
          : "Sign in failed. Please try again.";
      setError(message);
      setSubmitting(false);
    }
  }

  return (
    <main className="fathom-login">
      <form
        className="fathom-login-card"
        aria-labelledby="login-title"
        onSubmit={(e) => void onSubmit(e)}
      >
        <h1 id="login-title" className="fathom-login-title">
          Sign in to Fathomline
        </h1>

        {error ? (
          <p role="alert" className="fathom-login-error">
            {error}
          </p>
        ) : null}

        <label className="fathom-field">
          <span>Username</span>
          <input
            name="username"
            type="text"
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>

        <label className="fathom-field">
          <span>Password</span>
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>

        <button type="submit" className="fathom-login-submit" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
