import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import random
import string
import math
import time

# Simple Tooltip Helper (ttk-safe)
class Tooltip:
    def __init__(self, widget, text, delay=600):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._id = None
        self.tipwindow = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._unschedule)
        widget.bind("<ButtonPress>", self._unschedule)

    def _schedule(self, _event=None):
        self._unschedule()
        self._id = self.widget.after(self.delay, self._show)

    def _unschedule(self, _event=None):
        if self._id:
            self.widget.after_cancel(self._id)
            self._id = None
        self._hide()

    def _show(self):
        if self.tipwindow or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw, text=self.text, justify=tk.LEFT,
            background="#111827", foreground="#e5e7eb",
            relief=tk.SOLID, borderwidth=1,
            padx=8, pady=5, font=("Segoe UI", 9)
        )
        label.pack()

    def _hide(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

# Main App
class PasswordStrengthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Assessment Tool")
        self.root.geometry("720x520")
        self.root.minsize(600, 460)
        self.root.resizable(True, True)

        # Global style
        self.style = ttk.Style(self.root)
        try:
            self.root.call("tk", "scaling", 1.2)
        except Exception:
            pass
        self._configure_styles()

        # Make outer grid 3x3 to keep center frame always in the middle
        for i in range(3):
            self.root.grid_rowconfigure(i, weight=1)
            self.root.grid_columnconfigure(i, weight=1)

        # Center frame (the only content area)
        self.center = ttk.Frame(self.root, padding=(18, 18, 18, 12), style="Card.TFrame")
        self.center.grid(row=1, column=1, sticky="nsew")

        # Inner grid for content layout
        for r in range(10):
            self.center.grid_rowconfigure(r, weight=0)
        # Allow some breathing room at the bottom
        self.center.grid_rowconfigure(9, weight=1)
        self.center.grid_columnconfigure(0, weight=1)
        self.center.grid_columnconfigure(1, weight=1)

        self._build_header()
        self._build_password_row()
        self._build_strength_ui()
        self._build_criteria_checklist()
        self._build_actions()
        self._build_statusbar()

        # Live updates
        self.password_entry.bind("<KeyRelease>", self._on_keyup)

        # Shortcuts
        self.root.bind("<Return>", lambda e: self.check_strength())
        self.root.bind("<Escape>", lambda e: self.confirm_exit())
        self.root.bind("<Control-g>", lambda e: self.generate_password())
        self.root.bind("<Control-c>", lambda e: self.copy_to_clipboard())

        self._set_status("Ready.")

    # UI Builders
    def _build_header(self):
        title = ttk.Label(self.center, text="Password Strength Assessment", style="Title.TLabel")
        subtitle = ttk.Label(
            self.center,
            text="Check complexity, get real-time feedback, and generate strong passwords.",
            style="Subtle.TLabel"
        )
        title.grid(row=0, column=0, columnspan=2, sticky="n", pady=(2, 2))
        subtitle.grid(row=1, column=0, columnspan=2, sticky="n", pady=(0, 12))

    def _build_password_row(self):
        row = 2
        lbl = ttk.Label(self.center, text="Enter Password:", style="Label.TLabel")
        lbl.grid(row=row, column=0, sticky="e", padx=(0, 8), pady=(4, 4))

        wrap = ttk.Frame(self.center)
        wrap.grid(row=row, column=1, sticky="ew", pady=(4, 4))
        self.center.grid_columnconfigure(1, weight=1)
        wrap.grid_columnconfigure(0, weight=1)

        self.password_entry = ttk.Entry(wrap, show="*", width=36, font=("Segoe UI", 11))
        self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self.toggle_button = ttk.Button(wrap, text="👁️", width=3, command=self.toggle_password)
        self.toggle_button.grid(row=0, column=1)
        Tooltip(self.toggle_button, "Show / Hide password (toggle)")

        # Info button
        self.info_button = ttk.Button(wrap, text="ℹ️", width=3, command=self._show_help)
        self.info_button.grid(row=0, column=2, padx=(6, 0))
        Tooltip(self.info_button, "How strength is calculated")

    def _build_strength_ui(self):
        row = 3
        self.strength_meter = ttk.Progressbar(self.center, mode="determinate", maximum=100, length=420)
        self.strength_meter.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(6, 2))

        self.feedback_label = ttk.Label(self.center, text="", style="Feedback.TLabel")
        self.feedback_label.grid(row=row+1, column=0, columnspan=2, pady=(0, 10))

    def _build_criteria_checklist(self):
        row = 5
        cap = ttk.Label(self.center, text="Requirements Checklist", style="Caption.TLabel")
        cap.grid(row=row-1, column=0, columnspan=2, pady=(0, 4))

        self.criteria_frame = ttk.Frame(self.center)
        self.criteria_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        self.criteria = {
            "length": ttk.Label(self.criteria_frame, text="⛔ At least 8 characters", style="Criteria.TLabel"),
            "upper": ttk.Label(self.criteria_frame, text="⛔ Uppercase letter (A-Z)", style="Criteria.TLabel"),
            "lower": ttk.Label(self.criteria_frame, text="⛔ Lowercase letter (a-z)", style="Criteria.TLabel"),
            "digit": ttk.Label(self.criteria_frame, text="⛔ Number (0-9)", style="Criteria.TLabel"),
            "special": ttk.Label(self.criteria_frame, text="⛔ Special character (!@#$...)", style="Criteria.TLabel"),
        }
        # Two columns layout
        self.criteria["length"].grid(row=0, column=0, sticky="w", padx=4, pady=2)
        self.criteria["upper"].grid(row=1, column=0, sticky="w", padx=4, pady=2)
        self.criteria["lower"].grid(row=2, column=0, sticky="w", padx=4, pady=2)
        self.criteria["digit"].grid(row=0, column=1, sticky="w", padx=4, pady=2)
        self.criteria["special"].grid(row=1, column=1, sticky="w", padx=4, pady=2)

    def _build_actions(self):
        row = 6
        btns = ttk.Frame(self.center)
        btns.grid(row=row, column=0, columnspan=2, pady=(6, 12))

        self.check_button = ttk.Button(btns, text="Check Strength", command=self.check_strength, style="Primary.TButton")
        self.generate_button = ttk.Button(btns, text="Generate Password", command=self.generate_password)
        self.copy_button = ttk.Button(btns, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.save_button = ttk.Button(btns, text="Save Result", command=self.save_password)
        self.clear_button = ttk.Button(btns, text="Clear", command=self.clear_fields)
        self.exit_button = ttk.Button(btns, text="Exit", command=self.confirm_exit, style="Danger.TButton")

        # Grid with spacing
        for i, b in enumerate((self.check_button, self.generate_button, self.copy_button,
                               self.save_button, self.clear_button, self.exit_button)):
            b.grid(row=0, column=i, padx=4, pady=4)
        # Tooltips
        Tooltip(self.check_button, "Evaluate the current password (Enter)")
        Tooltip(self.generate_button, "Generate a strong random password (Ctrl+G)")
        Tooltip(self.copy_button, "Copy current password to clipboard (Ctrl+C)")
        Tooltip(self.save_button, "Save password & strength to a file")
        Tooltip(self.clear_button, "Clear password & results")
        Tooltip(self.exit_button, "Close the application (Esc)")

        # Options row under actions
        opt = ttk.Frame(self.center)
        opt.grid(row=row+1, column=0, columnspan=2, pady=(0, 2))
        ttk.Label(opt, text="Generator Options:", style="Caption.TLabel").grid(row=0, column=0, padx=(0, 6))
        self.len_var = tk.IntVar(value=12)
        self.chk_upper = tk.BooleanVar(value=True)
        self.chk_lower = tk.BooleanVar(value=True)
        self.chk_digit = tk.BooleanVar(value=True)
        self.chk_special = tk.BooleanVar(value=True)

        ttk.Spinbox(opt, from_=8, to=64, width=5, textvariable=self.len_var).grid(row=0, column=1)
        ttk.Checkbutton(opt, text="Upper", variable=self.chk_upper).grid(row=0, column=2, padx=4)
        ttk.Checkbutton(opt, text="Lower", variable=self.chk_lower).grid(row=0, column=3, padx=4)
        ttk.Checkbutton(opt, text="Digits", variable=self.chk_digit).grid(row=0, column=4, padx=4)
        ttk.Checkbutton(opt, text="Special", variable=self.chk_special).grid(row=0, column=5, padx=4)

    def _build_statusbar(self):
        row = 8
        # Removed the separator line that was causing the visual issue
        self.status_label = ttk.Label(self.center, text="Status: —", style="Status.TLabel")
        self.status_label.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))

    # Styles
    def _configure_styles(self):
        # Theme-friendly palettes
        self.style.configure("Title.TLabel", font=("Segoe UI Semibold", 18))
        self.style.configure("Subtle.TLabel", font=("Segoe UI", 10), foreground="#6b7280")
        self.style.configure("Label.TLabel", font=("Segoe UI", 11))
        self.style.configure("Feedback.TLabel", font=("Segoe UI", 11, "italic"))
        self.style.configure("Caption.TLabel", font=("Segoe UI Semibold", 10))
        self.style.configure("Criteria.TLabel", font=("Segoe UI", 10))
        self.style.configure("Status.TLabel", font=("Segoe UI", 10), foreground="#2563eb")

        # Card-like frame (works with default theme)
        self.style.configure("Card.TFrame", background=self._bg_color())

        # Buttons
        self.style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))
        self.style.configure("Danger.TButton", foreground="#b91c1c")

        # Colored progress bar styles
        self.style.configure("Red.Horizontal.TProgressbar", troughcolor="#f3f4f6", background="#ef4444")
        self.style.configure("Orange.Horizontal.TProgressbar", troughcolor="#f3f4f6", background="#fb923c")
        self.style.configure("Yellow.Horizontal.TProgressbar", troughcolor="#f3f4f6", background="#f59e0b")
        self.style.configure("Green.Horizontal.TProgressbar", troughcolor="#f3f4f6", background="#22c55e")

    def _bg_color(self):
        # A neutral background that fits most Tk themes
        return "#f8fafc"

    # Event handlers and logic
    def toggle_password(self):
        if self.password_entry.cget("show") == "":
            self.password_entry.config(show="*")
            self.toggle_button.config(text="👁️")
            self._set_status("Password hidden.")
        else:
            self.password_entry.config(show="")
            self.toggle_button.config(text="🙈")
            self._set_status("Password visible (be careful).")

    def _on_keyup(self, _event=None):
        self._update_live_feedback()

    def _update_live_feedback(self):
        pwd = self.password_entry.get()
        if not pwd:
            self._reset_feedback()
            return
        score, detail, entropy_bits = self._evaluate_password(pwd)
        self._apply_strength_visuals(score, detail, entropy_bits)

    def check_strength(self):
        pwd = self.password_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Password field cannot be empty.")
            return
        score, detail, entropy_bits = self._evaluate_password(pwd)
        self._apply_strength_visuals(score, detail, entropy_bits)
        messagebox.showinfo("Strength Result",
                            f"Verdict: {score}\nEntropy: ~{entropy_bits:.1f} bits\n\n{detail}")
        self._set_status(f"Password strength checked: {score}")

    def _reset_feedback(self):
        self.strength_meter["value"] = 0
        self.strength_meter.configure(style="Red.Horizontal.TProgressbar")
        self.feedback_label.configure(text="")
        for k in self.criteria:
            self.criteria[k].configure(text=self._crit_text(k, False))
        self._set_status("Waiting for input...")

    def _crit_text(self, key, ok):
        prefix = "✅" if ok else "⛔"
        mapping = {
            "length": "At least 8 characters",
            "upper": "Uppercase letter (A-Z)",
            "lower": "Lowercase letter (a-z)",
            "digit": "Number (0-9)",
            "special": "Special character (!@#$...)",
        }
        return f"{prefix} {mapping[key]}"

    def _evaluate_password(self, password: str):
        # Checks
        has_len = len(password) >= 8
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        specials = string.punctuation
        has_special = any(c in specials for c in password)

        # Update checklist
        self.criteria["length"].configure(text=self._crit_text("length", has_len))
        self.criteria["upper"].configure(text=self._crit_text("upper", has_upper))
        self.criteria["lower"].configure(text=self._crit_text("lower", has_lower))
        self.criteria["digit"].configure(text=self._crit_text("digit", has_digit))
        self.criteria["special"].configure(text=self._crit_text("special", has_special))

        # Scoring
        checks = [has_len, has_upper, has_lower, has_digit, has_special]
        raw = sum(checks)  # 0..5
        length_bonus = min(max(len(password) - 12, 0), 8)  # small bonus for >12 chars
        score_points = raw * 20 + length_bonus * 2  # max ~ 5*20 + 16 = 116 → cap later

        # Entropy estimation (very rough): log2(pool^length) = length*log2(pool)
        pool = 0
        if has_lower: pool += 26
        if has_upper: pool += 26
        if has_digit: pool += 10
        if has_special: pool += len(specials)
        # Always count at least lowercase to avoid 0
        if pool == 0:
            pool = 26
        entropy_bits = len(password) * math.log2(pool)

        # Verdict based on points + entropy
        score_points = min(score_points, 100)
        if score_points < 35 or entropy_bits < 35:
            verdict = "Weak"
            detail = "Add length and mix of upper/lower/digits/specials."
        elif score_points < 60 or entropy_bits < 50:
            verdict = "Medium"
            detail = "Good start. Increase length and add more character types."
        elif score_points < 85 or entropy_bits < 70:
            verdict = "Strong"
            detail = "Solid password. Longer length further improves security."
        else:
            verdict = "Very Strong"
            detail = "Excellent! Consider using a password manager for unique passwords."

        return verdict, detail, entropy_bits

    def _apply_strength_visuals(self, verdict, detail, entropy_bits):
        mapping = {
            "Weak":  (20, "Red.Horizontal.TProgressbar", "#ef4444"),
            "Medium": (50, "Orange.Horizontal.TProgressbar", "#fb923c"),
            "Strong": (80, "Yellow.Horizontal.TProgressbar", "#f59e0b"),
            "Very Strong": (100, "Green.Horizontal.TProgressbar", "#22c55e"),
        }
        val, style, color = mapping[verdict]
        self.strength_meter.configure(style=style)
        self.strength_meter["value"] = val
        self.feedback_label.configure(
            text=f"{verdict} — {detail}  (Entropy ≈ {entropy_bits:.1f} bits)"
        )
        self._set_status(f"Live: {verdict}")

    def generate_password(self):
        length = max(8, int(self.len_var.get() or 12))
        pools = []
        if self.chk_upper.get(): pools.append(string.ascii_uppercase)
        if self.chk_lower.get(): pools.append(string.ascii_lowercase)
        if self.chk_digit.get(): pools.append(string.digits)
        if self.chk_special.get(): pools.append(string.punctuation)

        if not pools:
            messagebox.showerror("Error", "Select at least one character set (Upper/Lower/Digits/Special).")
            return

        # Ensure all selected categories appear at least once
        chars = [random.choice(pool) for pool in pools]
        all_chars = "".join(pools)
        while len(chars) < length:
            chars.append(random.choice(all_chars))
        random.shuffle(chars)
        pwd = "".join(chars[:length])

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, pwd)
        self._set_status("Generated a strong password.")
        self._update_live_feedback()

    def copy_to_clipboard(self):
        pwd = self.password_entry.get()
        if not pwd:
            messagebox.showerror("Error", "No password to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        self._set_status("Password copied to clipboard.")

    def save_password(self):
        pwd = self.password_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Password field cannot be empty.")
            return
        verdict_text = self.feedback_label.cget("text")
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        default_name = f"password_strength_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        path = filedialog.asksaveasfilename(
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Timestamp: {ts}\nPassword: {pwd}\nResult: {verdict_text}\n")
            self._set_status(f"Saved to {path}")
            messagebox.showinfo("Saved", f"Password result saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save:\n{e}")

    def clear_fields(self):
        self.password_entry.delete(0, tk.END)
        self._reset_feedback()
        self._set_status("Cleared.")

    def confirm_exit(self):
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.root.destroy()

    def _show_help(self):
        message = (
            "How we calculate strength:\n"
            "• Checks for length (≥ 8), uppercase, lowercase, digits, and special characters.\n"
            "• Estimates entropy based on the character pool and length.\n"
            "• Color meter: Red (Weak) → Orange (Medium) → Yellow (Strong) → Green (Very Strong).\n\n"
            "Tips:\n"
            "• Use 12–16+ characters.\n"
            "• Mix upper/lowercase, digits, and special characters.\n"
            "• Prefer unique passwords per site; consider a password manager."
        )
        messagebox.showinfo("Help", message)

    def _set_status(self, text):
        self.status_label.configure(text=f"Status: {text}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthApp(root)
    root.mainloop()