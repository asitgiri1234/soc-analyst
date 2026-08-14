"use client";

/**
 * A dialog for the short forms that create things.
 *
 * Native `<dialog>` rather than a hand-rolled overlay: the browser already
 * implements the focus trap, the top layer, and Escape-to-close, and a
 * reimplementation of those is where accessibility usually gets lost.
 *
 * Closing is only ever the caller's decision -- `onClose` is called and the
 * dialog stays open until the parent says otherwise -- so a submission in
 * flight cannot be dismissed out from under itself.
 */

import { useEffect, useRef, type ReactNode } from "react";

export function Modal({
  open,
  title,
  description,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;

    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  // Escape fires the dialog's own `cancel`; route it through the same path as
  // the close button so the parent stays the single source of truth.
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;

    const handleCancel = (event: Event) => {
      event.preventDefault();
      onClose();
    };
    dialog.addEventListener("cancel", handleCancel);
    return () => dialog.removeEventListener("cancel", handleCancel);
  }, [onClose]);

  return (
    <dialog
      ref={ref}
      className="w-full max-w-lg rounded-xl border border-soc-border bg-soc-surface p-0 text-soc-text backdrop:bg-black/60 open:animate-none"
    >
      <div className="flex items-start justify-between gap-4 border-b border-soc-border px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold tracking-wide uppercase">{title}</h2>
          {description && <p className="mt-1 text-xs text-soc-muted">{description}</p>}
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="rounded-lg px-2 py-1 text-soc-muted transition-colors hover:bg-soc-hover hover:text-soc-text"
        >
          ✕
        </button>
      </div>
      <div className="px-5 py-4">{children}</div>
    </dialog>
  );
}

/** A labelled field. */
export function Field({
  label,
  htmlFor,
  hint,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-sm font-medium text-soc-text">
        {label}
      </label>
      {children}
      {hint && <p className="text-xs text-soc-faint">{hint}</p>}
    </div>
  );
}

export const inputClass =
  "w-full rounded-lg border border-soc-border bg-soc-base px-3 py-2 text-sm text-soc-text placeholder:text-soc-faint focus:border-soc-accent focus:outline-none";

export function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p
      role="alert"
      className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-300"
    >
      {message}
    </p>
  );
}

/** The primary action in a form or toolbar. */
export function PrimaryButton({
  children,
  disabled,
  type = "button",
  onClick,
}: {
  children: ReactNode;
  disabled?: boolean;
  type?: "button" | "submit";
  onClick?: () => void;
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className="flex items-center justify-center gap-2 rounded-lg bg-sky-500 px-3 py-2 text-sm font-medium text-slate-950 transition-colors hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
    >
      {children}
    </button>
  );
}

export function SecondaryButton({
  children,
  onClick,
  disabled,
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-lg border border-soc-border px-3 py-2 text-sm text-soc-text transition-colors hover:bg-soc-hover disabled:cursor-not-allowed disabled:opacity-50"
    >
      {children}
    </button>
  );
}
