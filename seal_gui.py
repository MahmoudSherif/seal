#!/usr/bin/env python3
"""
seal-gui — desktop GUI for the seal file & folder encryption tool.

Place this file in the same directory as seal.py and run:
    python3 seal_gui.py

Or make it executable (chmod +x seal_gui.py) and double-click it from
your file manager. Requires Python 3 with Tkinter (preinstalled on most
distros; on Debian/Ubuntu/WSL: sudo apt install python3-tk).
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional, Tuple

# Find seal.py next to this script so the GUI doesn't need to be installed
# as a package.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    import seal as core
except ImportError:
    msg = (
        "Cannot find seal.py.\n\n"
        "Place seal.py in the same folder as this GUI script and try again."
    )
    try:
        root = tk.Tk(); root.withdraw()
        messagebox.showerror("seal-gui", msg)
    except Exception:
        sys.stderr.write(msg + "\n")
    sys.exit(2)


class SealApp:
    PAD = 10

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("seal — file & folder encryption")
        root.geometry("680x600")
        root.minsize(560, 500)

        # state
        self.mode = tk.StringVar(value="encrypt")
        self.show_pw = tk.BooleanVar(value=False)
        self.overwrite = tk.BooleanVar(value=False)
        self.hide_name = tk.BooleanVar(value=False)
        self.output_dir = tk.StringVar(value=str(Path.cwd()))
        self.password = tk.StringVar()
        self.confirm = tk.StringVar()
        self.status = tk.StringVar(value="Ready.")
        self.progress_val = tk.DoubleVar(value=0.0)

        self.entries: List[Path] = []
        self.last_dir: str = str(Path.cwd())
        self.worker: Optional[threading.Thread] = None
        self.msgs: "queue.Queue[Tuple[str, object]]" = queue.Queue()

        self._build_ui()
        self._poll_msgs()

    # ---------- UI construction ----------
    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=self.PAD)
        outer.pack(fill="both", expand=True)

        # Mode
        mode_frame = ttk.LabelFrame(outer, text="Action", padding=self.PAD)
        mode_frame.pack(fill="x")
        ttk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode,
                        value="encrypt", command=self._on_mode_change
                        ).pack(side="left", padx=(0, 18))
        ttk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode,
                        value="decrypt", command=self._on_mode_change
                        ).pack(side="left")

        # Files / folders list
        items_frame = ttk.LabelFrame(outer, text="Files and folders",
                                     padding=self.PAD)
        items_frame.pack(fill="both", expand=True, pady=(self.PAD, 0))

        list_box = ttk.Frame(items_frame)
        list_box.pack(fill="both", expand=True)

        sb = ttk.Scrollbar(list_box, orient="vertical")
        sb.pack(side="right", fill="y")

        self.tree = ttk.Treeview(
            list_box, columns=("kind", "path"), show="headings",
            selectmode="extended", yscrollcommand=sb.set, height=8)
        self.tree.heading("kind", text="Kind")
        self.tree.heading("path", text="Path")
        self.tree.column("kind", width=80, stretch=False, anchor="w")
        self.tree.column("path", width=480, stretch=True, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb.config(command=self.tree.yview)

        btns = ttk.Frame(items_frame)
        btns.pack(fill="x", pady=(8, 0))
        self.add_files_btn = ttk.Button(btns, text="Add files...",
                                        command=self._add_files)
        self.add_files_btn.pack(side="left")
        self.add_folder_btn = ttk.Button(btns, text="Add folder...",
                                         command=self._add_folder)
        self.add_folder_btn.pack(side="left", padx=6)
        ttk.Button(btns, text="Remove selected",
                   command=self._remove_selected).pack(side="left", padx=(20, 6))
        ttk.Button(btns, text="Clear", command=self._clear).pack(side="left")

        # Output dir
        out_frame = ttk.Frame(outer)
        out_frame.pack(fill="x", pady=(self.PAD, 0))
        ttk.Label(out_frame, text="Output folder:").pack(side="left")
        ttk.Entry(out_frame, textvariable=self.output_dir
                  ).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(out_frame, text="Browse...",
                   command=self._browse_output).pack(side="left")

        # Password
        pw_frame = ttk.LabelFrame(outer, text="Password", padding=self.PAD)
        pw_frame.pack(fill="x", pady=(self.PAD, 0))

        r1 = ttk.Frame(pw_frame); r1.pack(fill="x")
        ttk.Label(r1, text="Password:", width=10).pack(side="left")
        self.pw_entry = ttk.Entry(r1, textvariable=self.password, show="•")
        self.pw_entry.pack(side="left", fill="x", expand=True)

        r2 = ttk.Frame(pw_frame); r2.pack(fill="x", pady=(6, 0))
        ttk.Label(r2, text="Confirm:", width=10).pack(side="left")
        self.confirm_entry = ttk.Entry(r2, textvariable=self.confirm, show="•")
        self.confirm_entry.pack(side="left", fill="x", expand=True)

        opts = ttk.Frame(pw_frame); opts.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(opts, text="Show password", variable=self.show_pw,
                        command=self._toggle_show).pack(side="left")
        ttk.Checkbutton(opts, text="Overwrite existing output",
                        variable=self.overwrite).pack(side="left", padx=(18, 0))

        opts2 = ttk.Frame(pw_frame); opts2.pack(fill="x", pady=(4, 0))
        self.hide_name_check = ttk.Checkbutton(
            opts2, text="Hide original filename (encrypt, single files only)",
            variable=self.hide_name)
        self.hide_name_check.pack(side="left")
        ttk.Button(opts2, text="Generate password",
                   command=self._generate_password).pack(side="right")

        # Action + progress
        self.go_btn = ttk.Button(outer, text="Encrypt", command=self._start)
        self.go_btn.pack(fill="x", pady=(self.PAD, 0))

        self.progress = ttk.Progressbar(outer, variable=self.progress_val,
                                        maximum=100)
        self.progress.pack(fill="x", pady=(8, 0))

        ttk.Label(outer, textvariable=self.status, anchor="w",
                  foreground="#555").pack(fill="x", pady=(4, 0))

    # ---------- UI callbacks ----------
    def _on_mode_change(self) -> None:
        if self.mode.get() == "encrypt":
            self.go_btn.config(text="Encrypt")
            self.confirm_entry.state(["!disabled"])
            self.add_folder_btn.state(["!disabled"])
            self.hide_name_check.state(["!disabled"])
        else:
            self.go_btn.config(text="Decrypt")
            self.confirm_entry.state(["disabled"])
            self.confirm.set("")
            # Decrypt only takes .seal files, not folders.
            self.add_folder_btn.state(["disabled"])
            # hide-name is only meaningful when encrypting; the kind is
            # already in the header for decrypt.
            self.hide_name.set(False)
            self.hide_name_check.state(["disabled"])

    def _generate_password(self) -> None:
        pw = core.generate_passphrase(words=5)
        self.password.set(pw)
        self.confirm.set(pw)
        # Make it visible so the user can read what was generated.
        self.show_pw.set(True)
        self._toggle_show()
        self.status.set(f"Generated 5-word passphrase (~50 bits of entropy). Save it before closing.")

    def _toggle_show(self) -> None:
        ch = "" if self.show_pw.get() else "•"
        self.pw_entry.config(show=ch)
        self.confirm_entry.config(show=ch)

    def _add_files(self) -> None:
        if self.mode.get() == "encrypt":
            paths = filedialog.askopenfilenames(
                title="Select files to encrypt", initialdir=self.last_dir)
        else:
            paths = filedialog.askopenfilenames(
                title="Select .seal files to decrypt",
                initialdir=self.last_dir,
                filetypes=[("Sealed files", "*.seal"), ("All files", "*.*")])
        if not paths:
            return
        for p in paths:
            self._add_entry(Path(p))
        self.last_dir = str(Path(paths[0]).parent)

    def _add_folder(self) -> None:
        if self.mode.get() != "encrypt":
            return  # disabled in decrypt mode
        d = filedialog.askdirectory(
            title="Select folder to encrypt", initialdir=self.last_dir)
        if not d:
            return
        self._add_entry(Path(d))
        self.last_dir = str(Path(d).parent)

    def _add_entry(self, path: Path) -> None:
        if path in self.entries:
            return
        self.entries.append(path)
        kind = "📁 folder" if path.is_dir() else "📄 file"
        self.tree.insert("", "end", values=(kind, str(path)))

    def _remove_selected(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        # Map tree item ids back to entry indices.
        all_items = self.tree.get_children("")
        indices = sorted({all_items.index(iid) for iid in sel}, reverse=True)
        for i in indices:
            del self.entries[i]
            self.tree.delete(all_items[i])

    def _clear(self) -> None:
        self.entries.clear()
        for iid in self.tree.get_children(""):
            self.tree.delete(iid)

    def _browse_output(self) -> None:
        d = filedialog.askdirectory(
            initialdir=self.output_dir.get() or str(Path.cwd()))
        if d:
            self.output_dir.set(d)

    # ---------- main job ----------
    def _start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        if not self.entries:
            messagebox.showwarning("Nothing to do",
                                   "Add at least one file or folder first.")
            return
        out_dir = Path(self.output_dir.get() or ".").expanduser()
        if not out_dir.is_dir():
            messagebox.showerror("Bad output folder", f"Not a folder:\n{out_dir}")
            return
        pw = self.password.get().encode("utf-8")
        if not pw:
            messagebox.showerror("Password", "Password cannot be empty.")
            return
        mode = self.mode.get()
        if mode == "encrypt":
            if pw != self.confirm.get().encode("utf-8"):
                messagebox.showerror("Password", "Passwords do not match.")
                return

        # Verify input paths still exist.
        missing = [str(e) for e in self.entries if not e.exists()]
        if missing:
            messagebox.showerror(
                "Missing input",
                "These paths no longer exist:\n\n" + "\n".join(missing))
            return

        # Determine hide_name and validate it applies.
        hide_name = self.hide_name.get() and mode == "encrypt"
        if hide_name:
            # hide_name only makes sense for files, not folders.
            folder_inputs = [e for e in self.entries if e.is_dir()]
            if folder_inputs:
                messagebox.showerror(
                    "Hide name not supported for folders",
                    "Hide-name mode applies only to single files. "
                    "Uncheck it or remove these folders first:\n\n"
                    + "\n".join(f"  • {f}" for f in folder_inputs))
                return

        # Compute targets up-front to detect collisions cleanly.
        try:
            targets = [self._target_for(src, out_dir, mode, hide_name=hide_name)
                       for src in self.entries]
        except Exception as e:
            messagebox.showerror("Bad input", str(e))
            return

        # Check for two inputs producing the same output path.
        seen: dict = {}
        clashes = []
        for src, tgt in zip(self.entries, targets):
            if tgt in seen:
                clashes.append((seen[tgt], src, tgt))
            else:
                seen[tgt] = src
        if clashes:
            details = "\n".join(
                f"  • {a.name}  +  {b.name}  →  {t.name}" for a, b, t in clashes)
            messagebox.showerror(
                "Output name collision",
                "Two or more inputs would write to the same output:\n\n"
                + details)
            return

        # Existing-output check (skipped if overwrite is on).
        if not self.overwrite.get():
            existing = [t for t in targets if t.exists()]
            if existing:
                messagebox.showerror(
                    "Output already exists",
                    "These outputs already exist (tick "
                    "'Overwrite existing output' to replace them):\n\n"
                    + "\n".join(f"  • {t}" for t in existing))
                return

        self.go_btn.config(state="disabled")
        self.progress_val.set(0)
        self.status.set("Starting...")

        self.worker = threading.Thread(
            target=self._run_job,
            args=(mode, list(self.entries), targets, pw,
                  self.overwrite.get(), hide_name),
            daemon=True)
        self.worker.start()

    @staticmethod
    def _target_for(src: Path, out_dir: Path, mode: str,
                    *, hide_name: bool = False) -> Path:
        if mode == "encrypt":
            if hide_name:
                # Generate a non-revealing output name with a short random tag
                # so multiple files don't collide.
                tag = os.urandom(3).hex()
                return out_dir / f"vault-{tag}.seal"
            return out_dir / (src.name + ".seal")
        # decrypt
        if src.suffix == ".seal":
            return out_dir / src.stem
        return out_dir / (src.name + ".dec")

    def _run_job(self, mode: str, sources: List[Path], targets: List[Path],
                 pw: bytes, force: bool, hide_name: bool = False) -> None:
        ok = 0
        failed: List[Tuple[str, str]] = []
        n = len(sources)
        for i, (src, tgt) in enumerate(zip(sources, targets)):
            label = "encrypt" if mode == "encrypt" else "decrypt"
            self.msgs.put(("status",
                           f"[{i + 1}/{n}] {label}ing {src.name}..."))
            self.msgs.put(("progress", 100.0 * i / n))
            try:
                if mode == "encrypt":
                    core.encrypt_path(src, tgt, pw, force=force,
                                      hide_name=hide_name)
                else:
                    core.decrypt_path(src, tgt, pw, force=force)
                ok += 1
            except Exception as e:
                failed.append((src.name, str(e)))

        self.msgs.put(("progress", 100.0))
        self.msgs.put(("done", (ok, n, failed, mode)))

    # ---------- main-thread message pump ----------
    def _poll_msgs(self) -> None:
        try:
            while True:
                kind, payload = self.msgs.get_nowait()
                if kind == "status":
                    self.status.set(payload)  # type: ignore[arg-type]
                elif kind == "progress":
                    self.progress_val.set(payload)  # type: ignore[arg-type]
                elif kind == "done":
                    ok, n, failed, mode = payload  # type: ignore[misc]
                    self.go_btn.config(state="normal")
                    if failed:
                        details = "\n".join(
                            f"  • {name}: {err}" for name, err in failed)
                        messagebox.showerror(
                            "Finished with errors",
                            f"{ok}/{n} {mode}ed successfully.\n\n"
                            f"Failures:\n{details}")
                        self.status.set(
                            f"Done: {ok}/{n} ok, {len(failed)} failed.")
                    else:
                        verb = "Encrypted" if mode == "encrypt" else "Decrypted"
                        messagebox.showinfo(
                            "Done", f"{verb} {n} item(s) successfully.")
                        self.status.set(f"Done: {ok}/{n} ok.")
        except queue.Empty:
            pass
        self.root.after(80, self._poll_msgs)


def main() -> None:
    root = tk.Tk()
    try:
        style = ttk.Style()
        for theme in ("clam", "alt", "default"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
    except Exception:
        pass
    SealApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
