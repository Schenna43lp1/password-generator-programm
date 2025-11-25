import tkinter as tk
from tkinter import messagebox
import random
import string
from dataclasses import dataclass
from typing import Set
from enum import Enum


class CharType(Enum):
    """Enum für Zeichentypen."""
    UPPERCASE = (string.ascii_uppercase, "Großbuchstaben", "A-Z")
    LOWERCASE = (string.ascii_lowercase, "Kleinbuchstaben", "a-z")
    DIGITS = (string.digits, "Zahlen", "0-9")
    SPECIAL = (string.punctuation, "Sonderzeichen", "!@#$...")

    def __init__(self, chars: str, label: str, hint: str):
        self.chars = chars
        self.label = label
        self.hint = hint


@dataclass
class Theme:
    """Dark Mode Theme Konfiguration."""
    bg_primary: str = "#1e1e2e"
    bg_secondary: str = "#2a2a3e"
    bg_hover: str = "#3a3a4e"
    bg_dark: str = "#15151f"
    accent: str = "#7c3aed"
    accent_hover: str = "#9333ea"
    text_primary: str = "#e0e0e0"
    text_secondary: str = "#a0a0a0"
    success: str = "#10b981"
    danger: str = "#ef4444"
    warning: str = "#f59e0b"


class PasswordGenerator:
    """Kern-Logik für Passwort-Generierung."""

    MIN_LENGTH = 8
    MAX_LENGTH = 64
    DEFAULT_LENGTH = 16

    @staticmethod
    def generate(length: int, char_types: Set[CharType]) -> str:
        """
        Generiert ein sicheres Passwort.

        Args:
            length: Länge des Passworts
            char_types: Set von CharType Enums

        Returns:
            Generiertes Passwort

        Raises:
            ValueError: Wenn keine Zeichentypen ausgewählt wurden
        """
        if not char_types:
            raise ValueError("Mindestens ein Zeichentyp muss ausgewählt werden")

        char_pool = ''.join(ct.chars for ct in char_types)

        # Sicherstellen, dass mindestens ein Zeichen jedes Typs vorhanden ist
        password = [random.choice(ct.chars) for ct in char_types]

        # Auffüllen auf gewünschte Länge
        remaining = length - len(password)
        password.extend(random.choice(char_pool) for _ in range(remaining))

        # Zufällig mischen
        random.shuffle(password)

        return ''.join(password)

    @staticmethod
    def calculate_strength(password: str) -> tuple[int, str]:
        """
        Berechnet die Stärke eines Passworts.

        Returns:
            Tuple von (Stärke 0-100, Beschreibung)
        """
        if not password:
            return 0, "Kein Passwort"

        strength = 0
        length = len(password)

        # Länge bewerten
        strength += min(length * 2, 40)

        # Zeichenvielfalt bewerten
        if any(c.isupper() for c in password):
            strength += 15
        if any(c.islower() for c in password):
            strength += 15
        if any(c.isdigit() for c in password):
            strength += 15
        if any(c in string.punctuation for c in password):
            strength += 15

        # Beschreibung
        if strength >= 80:
            return strength, "Sehr stark 💪"
        elif strength >= 60:
            return strength, "Stark 👍"
        elif strength >= 40:
            return strength, "Mittel ⚠️"
        else:
            return strength, "Schwach ⚠️"


class ModernButton(tk.Button):
    """Custom Button mit Hover-Effekt."""

    def __init__(self, parent, theme: Theme, hover_color: str = None, **kwargs):
        self.theme = theme
        self.default_bg = kwargs.get('bg', theme.bg_hover)
        self.hover_bg = hover_color or theme.bg_dark

        super().__init__(
            parent,
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
            activebackground=self.hover_bg,
            **kwargs
        )

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, e):
        if self['state'] != tk.DISABLED:
            self.config(bg=self.hover_bg)

    def _on_leave(self, e):
        if self['state'] != tk.DISABLED:
            self.config(bg=self.default_bg)


class PasswordGeneratorGUI:
    """Hauptanwendung mit GUI."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.theme = Theme()
        self.generator = PasswordGenerator()
        self.char_vars = {}

        self._setup_window()
        self._create_widgets()

    def _setup_window(self):
        """Initialisiert das Hauptfenster."""
        self.root.title("Passwort-Generator Pro")
        self.root.geometry("600x650")
        self.root.resizable(False, False)
        self.root.configure(bg=self.theme.bg_primary)

    def _create_widgets(self):
        """Erstellt alle GUI-Komponenten."""
        main_frame = tk.Frame(self.root, bg=self.theme.bg_primary, padx=40, pady=35)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_header(main_frame)
        self._create_length_section(main_frame)
        self._create_options_section(main_frame)
        self._create_generate_button(main_frame)
        self._create_result_section(main_frame)
        self._create_strength_indicator(main_frame)

    def _create_header(self, parent):
        """Erstellt Header mit Titel."""
        header = tk.Frame(parent, bg=self.theme.bg_primary)
        header.pack(pady=(0, 30))

        tk.Label(
            header,
            text="🔐 Passwort-Generator Pro",
            font=("Segoe UI", 26, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_primary
        ).pack()

        tk.Label(
            header,
            text="Erstelle sichere Passwörter in Sekunden",
            font=("Segoe UI", 11),
            fg=self.theme.text_secondary,
            bg=self.theme.bg_primary
        ).pack(pady=(8, 0))

    def _create_length_section(self, parent):
        """Erstellt Längen-Slider."""
        container = self._create_section_container(parent)

        header = tk.Frame(container, bg=self.theme.bg_secondary)
        header.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            header,
            text="Passwortlänge",
            font=("Segoe UI", 12, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_secondary
        ).pack(side=tk.LEFT)

        self.length_var = tk.IntVar(value=self.generator.DEFAULT_LENGTH)
        self.length_label = tk.Label(
            header,
            text=str(self.generator.DEFAULT_LENGTH),
            font=("Segoe UI", 12, "bold"),
            fg=self.theme.accent,
            bg=self.theme.bg_secondary
        )
        self.length_label.pack(side=tk.RIGHT)

        self.length_slider = tk.Scale(
            container,
            from_=self.generator.MIN_LENGTH,
            to=self.generator.MAX_LENGTH,
            variable=self.length_var,
            orient=tk.HORIZONTAL,
            command=self._update_length_label,
            bg=self.theme.bg_secondary,
            fg=self.theme.text_primary,
            troughcolor=self.theme.bg_hover,
            activebackground=self.theme.accent,
            highlightthickness=0,
            bd=0,
            showvalue=0
        )
        self.length_slider.pack(fill=tk.X)

    def _create_options_section(self, parent):
        """Erstellt Checkbox-Optionen."""
        container = self._create_section_container(parent)

        tk.Label(
            container,
            text="Zeichenarten",
            font=("Segoe UI", 12, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_secondary
        ).pack(anchor=tk.W, pady=(0, 12))

        for char_type in CharType:
            var = tk.BooleanVar(value=True)
            self.char_vars[char_type] = var

            tk.Checkbutton(
                container,
                text=f"✓ {char_type.label} ({char_type.hint})",
                variable=var,
                font=("Segoe UI", 11),
                fg=self.theme.text_primary,
                bg=self.theme.bg_secondary,
                activebackground=self.theme.bg_secondary,
                activeforeground=self.theme.text_primary,
                selectcolor=self.theme.accent,
                highlightthickness=0,
                bd=0
            ).pack(anchor=tk.W, pady=4)

    def _create_generate_button(self, parent):
        """Erstellt Generieren-Button."""
        self.gen_button = ModernButton(
            parent,
            self.theme,
            text="⚡ PASSWORT GENERIEREN",
            command=self._generate_password,
            font=("Segoe UI", 12, "bold"),
            bg=self.theme.accent,
            fg="white",
            hover_color=self.theme.accent_hover,
            pady=14
        )
        self.gen_button.pack(fill=tk.X, pady=(25, 0))

    def _create_result_section(self, parent):
        """Erstellt Ergebnis-Anzeige."""
        container = self._create_section_container(parent)

        tk.Label(
            container,
            text="Generiertes Passwort",
            font=("Segoe UI", 11),
            fg=self.theme.text_secondary,
            bg=self.theme.bg_secondary
        ).pack(anchor=tk.W, pady=(0, 10))

        self.password_text = tk.Text(
            container,
            height=3,
            font=("Consolas", 13, "bold"),
            wrap=tk.WORD,
            bg=self.theme.bg_hover,
            fg=self.theme.success,
            insertbackground=self.theme.text_primary,
            relief=tk.FLAT,
            bd=0,
            padx=12,
            pady=12,
            state=tk.DISABLED
        )
        self.password_text.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

        # Action Buttons
        btn_frame = tk.Frame(container, bg=self.theme.bg_secondary)
        btn_frame.pack(fill=tk.X)

        self.copy_button = ModernButton(
            btn_frame,
            self.theme,
            text="📋 Kopieren",
            command=self._copy_password,
            font=("Segoe UI", 10, "bold"),
            bg=self.theme.bg_hover,
            fg=self.theme.text_primary,
            state=tk.DISABLED,
            pady=10
        )
        self.copy_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.clear_button = ModernButton(
            btn_frame,
            self.theme,
            text="🗑️ Löschen",
            command=self._clear_password,
            font=("Segoe UI", 10, "bold"),
            bg=self.theme.bg_hover,
            fg=self.theme.text_primary,
            state=tk.DISABLED,
            pady=10
        )
        self.clear_button.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _create_strength_indicator(self, parent):
        """Erstellt Stärke-Anzeige."""
        container = tk.Frame(parent, bg=self.theme.bg_secondary, pady=15, padx=18)
        container.pack(fill=tk.X, pady=(20, 0))

        tk.Label(
            container,
            text="Passwortstärke",
            font=("Segoe UI", 10),
            fg=self.theme.text_secondary,
            bg=self.theme.bg_secondary
        ).pack(anchor=tk.W, pady=(0, 8))

        # Progress Bar
        progress_bg = tk.Frame(container, bg=self.theme.bg_hover, height=8)
        progress_bg.pack(fill=tk.X, pady=(0, 8))

        self.strength_bar = tk.Frame(progress_bg, bg=self.theme.text_secondary, height=8)
        self.strength_bar.place(x=0, y=0, relwidth=0, relheight=1)

        self.strength_label = tk.Label(
            container,
            text="Generiere ein Passwort",
            font=("Segoe UI", 10, "bold"),
            fg=self.theme.text_secondary,
            bg=self.theme.bg_secondary
        )
        self.strength_label.pack(anchor=tk.W)

    def _create_section_container(self, parent):
        """Erstellt einen Section-Container."""
        container = tk.Frame(
            parent,
            bg=self.theme.bg_secondary,
            pady=18,
            padx=18
        )
        container.pack(fill=tk.X, pady=(0, 20))
        return container

    def _update_length_label(self, value):
        """Aktualisiert Label bei Slider-Änderung."""
        self.length_label.config(text=str(int(float(value))))

    def _generate_password(self):
        """Generiert ein neues Passwort."""
        try:
            selected_types = {ct for ct, var in self.char_vars.items() if var.get()}

            if not selected_types:
                messagebox.showwarning(
                    "Warnung",
                    "Bitte wähle mindestens eine Zeichenart aus!",
                    parent=self.root
                )
                return

            length = self.length_var.get()
            password = self.generator.generate(length, selected_types)

            # Popup mit generiertem Passwort
            popup = tk.Toplevel(self.root)
            popup.title("Generiertes Passwort")
            popup.geometry("500x300")
            popup.configure(bg=self.theme.bg_primary)
            popup.transient(self.root)
            popup.grab_set()

            # Zentrieren
            popup.update_idletasks()
            x = (popup.winfo_screenwidth() // 2) - (popup.winfo_width() // 2)
            y = (popup.winfo_screenheight() // 2) - (popup.winfo_height() // 2)
            popup.geometry(f"+{x}+{y}")

            # Content
            content = tk.Frame(popup, bg=self.theme.bg_primary, padx=30, pady=30)
            content.pack(fill=tk.BOTH, expand=True)

            tk.Label(
                content,
                text="✅ Passwort erfolgreich generiert!",
                font=("Segoe UI", 16, "bold"),
                fg=self.theme.success,
                bg=self.theme.bg_primary
            ).pack(pady=(0, 20))

            # Passwort anzeigen
            pw_frame = tk.Frame(content, bg=self.theme.bg_secondary, pady=15, padx=15)
            pw_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

            tk.Label(
                pw_frame,
                text="Dein Passwort:",
                font=("Segoe UI", 10),
                fg=self.theme.text_secondary,
                bg=self.theme.bg_secondary
            ).pack(anchor=tk.W, pady=(0, 10))

            pw_text = tk.Text(
                pw_frame,
                height=3,
                font=("Consolas", 14, "bold"),
                wrap=tk.WORD,
                bg=self.theme.bg_hover,
                fg=self.theme.success,
                relief=tk.FLAT,
                bd=0,
                padx=12,
                pady=12
            )
            pw_text.pack(fill=tk.BOTH, expand=True)
            pw_text.insert("1.0", password)
            pw_text.config(state=tk.DISABLED)

            # Stärke anzeigen
            strength, description = self.generator.calculate_strength(password)
            if strength >= 80:
                color = self.theme.success
            elif strength >= 60:
                color = self.theme.accent
            elif strength >= 40:
                color = self.theme.warning
            else:
                color = self.theme.danger

            tk.Label(
                content,
                text=f"Stärke: {description}",
                font=("Segoe UI", 12, "bold"),
                fg=color,
                bg=self.theme.bg_primary
            ).pack(pady=(0, 20))

            # Buttons
            btn_frame = tk.Frame(content, bg=self.theme.bg_primary)
            btn_frame.pack(fill=tk.X)

            def copy_and_close():
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                popup.destroy()
                messagebox.showinfo("Erfolg", "Passwort wurde kopiert!", parent=self.root)

            ModernButton(
                btn_frame,
                self.theme,
                text="📋 Kopieren & Schließen",
                command=copy_and_close,
                font=("Segoe UI", 11, "bold"),
                bg=self.theme.accent,
                fg="white",
                hover_color=self.theme.accent_hover,
                pady=12
            ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

            ModernButton(
                btn_frame,
                self.theme,
                text="❌ Schließen",
                command=popup.destroy,
                font=("Segoe UI", 11, "bold"),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_primary,
                hover_color=self.theme.bg_hover,
                pady=12
            ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        except Exception as e:
            import traceback
            error_msg = f"Fehler beim Generieren:\n\n{str(e)}\n\n{traceback.format_exc()}"
            messagebox.showerror("Fehler", error_msg, parent=self.root)

    def _update_strength_indicator(self, password: str):
        """Aktualisiert die Stärke-Anzeige."""
        strength, description = self.generator.calculate_strength(password)

        # Farbe basierend auf Stärke
        if strength >= 80:
            color = self.theme.success
        elif strength >= 60:
            color = self.theme.accent
        elif strength >= 40:
            color = self.theme.warning
        else:
            color = self.theme.danger

        # Animierte Aktualisierung der Progress Bar
        self.strength_bar.config(bg=color)
        self.strength_bar.place(relwidth=strength / 100)

        self.strength_label.config(text=description, fg=color)

    def _copy_password(self):
        """Kopiert Passwort in Zwischenablage."""
        password = self.password_text.get(1.0, tk.END).strip()
        if password:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(password)

                # Visuelles Feedback
                original = self.copy_button.cget("text")
                original_bg = self.copy_button.cget("bg")
                self.copy_button.config(text="✓ Kopiert!", bg=self.theme.success)
                self.root.after(1500, lambda: self.copy_button.config(
                    text=original, bg=original_bg
                ))
            except Exception as e:
                messagebox.showerror("Fehler", f"Kopieren fehlgeschlagen: {e}")

    def _clear_password(self):
        """Löscht das angezeigte Passwort."""
        self.password_text.config(state=tk.NORMAL)
        self.password_text.delete(1.0, tk.END)
        self.password_text.config(state=tk.DISABLED)
        self.copy_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.DISABLED)
        self.strength_bar.place(relwidth=0)
        self.strength_label.config(
            text="Generiere ein Passwort",
            fg=self.theme.text_secondary
        )


def main():
    """Haupteinstiegspunkt der Anwendung."""
    root = tk.Tk()
    app = PasswordGeneratorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()