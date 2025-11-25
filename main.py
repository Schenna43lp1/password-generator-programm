"""Moderner Passwort-Generator mit GUI.

Ein sicherer Passwort-Generator mit tkinter GUI, der kryptographisch sichere
Passwörter mit konfigurierbarer Länge und Zeichenarten erstellt.
Autor: Markus Stuefer
Datum: 25-11-2025
"""
import tkinter as tk
from tkinter import messagebox, filedialog
import secrets
import string
import math
from dataclasses import dataclass
from typing import Set, Tuple, List, Optional
from enum import Enum
from datetime import datetime


class CharType(Enum):
    """Enum für Zeichentypen."""
    UPPERCASE = (string.ascii_uppercase, "Großbuchstaben", "A-Z")
    LOWERCASE = (string.ascii_lowercase, "Kleinbuchstaben", "a-z")
    DIGITS = (string.digits, "Zahlen", "0-9")
    SPECIAL = (string.punctuation, "Sonderzeichen", "!@#$...")
    WHITESPACE = (" ", "Leerzeichen", " ")

    def __init__(self, chars: str, label: str, hint: str):
        self.chars = chars
        self.label = label
        self.hint = hint


@dataclass(frozen=True)
class Theme:
    """Theme Konfiguration.
    
    Immutable Dataclass mit allen Farbdefinitionen für das UI.
    """
    bg_primary: str = "#0f0f23"
    bg_secondary: str = "#1a1a2e"
    bg_hover: str = "#252541"
    bg_dark: str = "#0a0a16"
    accent: str = "#6366f1"
    accent_hover: str = "#818cf8"
    accent_light: str = "#a5b4fc"
    text_primary: str = "#f0f0f0"
    text_secondary: str = "#94a3b8"
    success: str = "#22c55e"
    danger: str = "#ef4444"
    warning: str = "#f59e0b"
    border: str = "#2d3748"
    name: str = "dark"


@dataclass(frozen=True)
class LightTheme(Theme):
    """Light Mode Theme."""
    bg_primary: str = "#f8fafc"
    bg_secondary: str = "#ffffff"
    bg_hover: str = "#f1f5f9"
    bg_dark: str = "#e2e8f0"
    accent: str = "#6366f1"
    accent_hover: str = "#4f46e5"
    accent_light: str = "#818cf8"
    text_primary: str = "#0f172a"
    text_secondary: str = "#64748b"
    success: str = "#10b981"
    danger: str = "#ef4444"
    warning: str = "#f59e0b"
    border: str = "#cbd5e1"
    name: str = "light"


class PasswordGenerator:
    """Kern-Logik für Passwort-Generierung."""

    MIN_LENGTH = 8
    MAX_LENGTH = 100
    DEFAULT_LENGTH = 16
    
    # Cache für Character-Pools
    _char_pool_cache = {}

    @staticmethod
    def generate(length: int, char_types: Set[CharType]) -> str:
        """
        Generiert ein kryptographisch sicheres Passwort.

        Args:
            length: Länge des Passworts (MIN_LENGTH bis MAX_LENGTH)
            char_types: Set von CharType Enums

        Returns:
            Generiertes Passwort

        Raises:
            ValueError: Wenn keine Zeichentypen ausgewählt wurden oder
                       Länge außerhalb des gültigen Bereichs liegt
        """
        if not char_types:
            raise ValueError("Mindestens ein Zeichentyp muss ausgewählt werden")
        
        if not PasswordGenerator.MIN_LENGTH <= length <= PasswordGenerator.MAX_LENGTH:
            raise ValueError(
                f"Länge muss zwischen {PasswordGenerator.MIN_LENGTH} "
                f"und {PasswordGenerator.MAX_LENGTH} liegen"
            )

        # Cache-Key für char_pool
        cache_key = frozenset(char_types)
        if cache_key not in PasswordGenerator._char_pool_cache:
            PasswordGenerator._char_pool_cache[cache_key] = ''.join(ct.chars for ct in char_types)
        
        char_pool = PasswordGenerator._char_pool_cache[cache_key]
        char_types_list = list(char_types)

        # Sicherstellen, dass mindestens ein Zeichen jedes Typs vorhanden ist
        password = [secrets.choice(ct.chars) for ct in char_types_list]

        # Auffüllen auf gewünschte Länge - optimiert mit list comprehension
        remaining = length - len(password)
        if remaining > 0:
            password.extend(secrets.choice(char_pool) for _ in range(remaining))

        # Kryptographisch sicher mischen
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    # Vorkompilierte Sets für schnellere Prüfungen
    _UPPERCASE_SET = frozenset(string.ascii_uppercase)
    _LOWERCASE_SET = frozenset(string.ascii_lowercase)
    _DIGIT_SET = frozenset(string.digits)
    _PUNCTUATION_SET = frozenset(string.punctuation)

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """
        Berechnet die Entropie eines Passworts in Bits.
        
        Args:
            password: Das zu analysierende Passwort
            
        Returns:
            Entropie in Bits
        """
        if not password:
            return 0.0
        
        # Bestimme den Zeichenraum
        charset_size = 0
        password_set = set(password)
        
        if password_set & PasswordGenerator._LOWERCASE_SET:
            charset_size += 26
        if password_set & PasswordGenerator._UPPERCASE_SET:
            charset_size += 26
        if password_set & PasswordGenerator._DIGIT_SET:
            charset_size += 10
        if password_set & PasswordGenerator._PUNCTUATION_SET:
            charset_size += len(string.punctuation)
        if ' ' in password_set:
            charset_size += 1
        
        # Entropie = log2(charset_size^length)
        if charset_size > 0:
            entropy = len(password) * math.log2(charset_size)
            return round(entropy, 2)
        return 0.0

    @staticmethod
    def calculate_strength(password: str) -> Tuple[int, str]:
        """
        Berechnet die Stärke eines Passworts.
        
        Args:
            password: Das zu bewertende Passwort
            
        Returns:
            Tuple aus (Stärke-Score 0-100, Beschreibung)
        """
        if not password:
            return 0, "Kein Passwort"

        strength = 0
        length = len(password)

        # Länge bewerten
        strength += min(length * 2, 40)

        # Zeichenvielfalt bewerten - single pass durch password
        password_set = set(password)
        if password_set & PasswordGenerator._UPPERCASE_SET:
            strength += 15
        if password_set & PasswordGenerator._LOWERCASE_SET:
            strength += 15
        if password_set & PasswordGenerator._DIGIT_SET:
            strength += 15
        if password_set & PasswordGenerator._PUNCTUATION_SET:
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


class PasswordPreset:
    """Vordefinierte Einstellungen für verschiedene Anwendungsfälle."""
    
    PRESETS = {
        "Standard": {
            "length": 16,
            "types": {CharType.UPPERCASE, CharType.LOWERCASE, CharType.DIGITS, CharType.SPECIAL}
        },
        "Einfach": {
            "length": 12,
            "types": {CharType.UPPERCASE, CharType.LOWERCASE, CharType.DIGITS}
        },
        "Komplex": {
            "length": 24,
            "types": {CharType.UPPERCASE, CharType.LOWERCASE, CharType.DIGITS, CharType.SPECIAL}
        },
        "PIN": {
            "length": 6,
            "types": {CharType.DIGITS}
        },
        "Passphrase": {
            "length": 20,
            "types": {CharType.UPPERCASE, CharType.LOWERCASE, CharType.WHITESPACE}
        }
    }


class ToolTip:
    """Tooltip für Widgets."""
    
    def __init__(self, widget: tk.Widget, text: str, theme: Theme) -> None:
        self.widget = widget
        self.text = text
        self.theme = theme
        self.tooltip_window = None
        
        widget.bind("<Enter>", self._show_tooltip)
        widget.bind("<Leave>", self._hide_tooltip)
    
    def _show_tooltip(self, event: tk.Event = None) -> None:
        """Zeigt Tooltip an."""
        if self.tooltip_window or not self.text:
            return
        
        # Verzögertes Rendern für bessere Performance
        def create_tooltip():
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
            
            self.tooltip_window = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            tw.wm_geometry(f"+{x}+{y}")
            
            label = tk.Label(
                tw,
                text=self.text,
                justify=tk.LEFT,
                background=self.theme.bg_hover,
                foreground=self.theme.text_primary,
                relief=tk.SOLID,
                borderwidth=1,
                font=("Segoe UI", 9),
                padx=8,
                pady=4
            )
            label.pack()
        
        self.widget.after_idle(create_tooltip)
    
    def _hide_tooltip(self, event: tk.Event = None) -> None:
        """Versteckt Tooltip."""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None


class ModernButton(tk.Button):
    """Custom Button mit Hover-Effekt.
    
    Erweiterter tkinter Button mit animierten Hover-Effekten und
    Theme-Integration.
    """

    def __init__(self, parent: tk.Widget, theme: Theme, 
                 hover_color: str = None, **kwargs) -> None:
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

    def _on_enter(self, event: tk.Event) -> None:
        """Event-Handler für Maus-Enter."""
        if self['state'] != tk.DISABLED:
            self.config(bg=self.hover_bg)

    def _on_leave(self, event: tk.Event) -> None:
        """Event-Handler für Maus-Leave."""
        if self['state'] != tk.DISABLED:
            self.config(bg=self.default_bg)


class PasswordGeneratorGUI:
    """Hauptanwendung mit GUI.
    
    Tkinter-basierte grafische Benutzeroberfläche für den Passwort-Generator.
    Verwaltet alle UI-Komponenten, Benutzerinteraktionen und die Integration
    mit der PasswordGenerator-Klasse.
    """

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.theme = Theme()
        self.generator = PasswordGenerator()
        self.char_vars = {}
        self.password_history: List[Tuple[str, datetime]] = []
        self.current_password: Optional[str] = None

        self._setup_window()
        self._create_widgets()

    def _setup_window(self) -> None:
        """Initialisiert das Hauptfenster."""
        self.root.title("🔐 Passwort-Generator Pro")
        self.root.geometry("700x720")
        self.root.resizable(False, False)
        self.root.configure(bg=self.theme.bg_primary)
        
        # Fenster zentrieren
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f"+{x}+{y}")
        
        # Icon setzen (falls vorhanden)
        try:
            self.root.iconbitmap(default='icon.ico')
        except tk.TclError:
            pass  # Icon nicht gefunden, ignorieren
        
        # Keyboard Shortcuts
        self.root.bind('<Control-g>', lambda e: self._generate_password())
        self.root.bind('<Control-c>', lambda e: self._copy_password())
        self.root.bind('<Control-s>', lambda e: self._save_password())
        self.root.bind('<Control-h>', lambda e: self._show_history())
        self.root.bind('<Control-t>', lambda e: self._toggle_theme())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<Escape>', lambda e: self.root.quit())

    def _create_widgets(self) -> None:
        """Erstellt alle GUI-Komponenten."""
        main_frame = tk.Frame(self.root, bg=self.theme.bg_primary, padx=45, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_header(main_frame)
        self._create_length_section(main_frame)
        self._create_options_section(main_frame)
        self._create_generate_button(main_frame)
        self._create_result_section(main_frame)
        self._create_strength_indicator(main_frame)

    def _create_header(self, parent: tk.Frame) -> None:
        """Erstellt Header mit Titel."""
        header = tk.Frame(parent, bg=self.theme.bg_primary)
        header.pack(pady=(0, 35))

        tk.Label(
            header,
            text="🔐 Passwort-Generator Pro",
            font=("Segoe UI", 28, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_primary
        ).pack()

        tk.Label(
            header,
            text="Erstelle kryptographisch sichere Passwörter",
            font=("Segoe UI", 12),
            fg=self.theme.text_secondary,
            bg=self.theme.bg_primary
        ).pack(pady=(10, 5))
        
        shortcuts_text = "Shortcuts: Ctrl+G=Generieren | Ctrl+C=Kopieren | Ctrl+S=Speichern | Ctrl+H=Historie | Ctrl+T=Theme"
        tk.Label(
            header,
            text=shortcuts_text,
            font=("Segoe UI", 9),
            fg=self.theme.accent_light,
            bg=self.theme.bg_primary
        ).pack(pady=(5, 0))
        
        # Theme Toggle Button
        self.theme_toggle_btn = ModernButton(
            header,
            self.theme,
            text="🌙 Dark Mode" if self.theme.name == "dark" else "☀️ Light Mode",
            command=self._toggle_theme,
            font=("Segoe UI", 9),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_secondary,
            pady=6
        )
        self.theme_toggle_btn.pack(pady=(10, 0))

    def _create_length_section(self, parent: tk.Frame) -> None:
        """Erstellt Längen-Slider."""
        container = self._create_section_container(parent)

        header = tk.Frame(container, bg=self.theme.bg_secondary)
        header.pack(fill=tk.X, pady=(0, 15))

        length_title = tk.Label(
            header,
            text="📏 Passwortlänge",
            font=("Segoe UI", 13, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_secondary
        )
        length_title.pack(side=tk.LEFT)
        ToolTip(length_title, "Empfohlen: Mindestens 12 Zeichen für gute Sicherheit", self.theme)

        self.length_var = tk.IntVar(value=self.generator.DEFAULT_LENGTH)
        self.length_label = tk.Label(
            header,
            text=str(self.generator.DEFAULT_LENGTH),
            font=("Segoe UI", 14, "bold"),
            fg=self.theme.accent,
            bg=self.theme.bg_secondary,
            width=4
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
            showvalue=0,
            length=550
        )
        self.length_slider.pack(fill=tk.X, padx=5)

    def _create_options_section(self, parent: tk.Frame) -> None:
        """Erstellt Checkbox-Optionen."""
        container = self._create_section_container(parent)

        # Preset-Auswahl Header
        preset_header = tk.Frame(container, bg=self.theme.bg_secondary)
        preset_header.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(
            preset_header,
            text="🎯 Vorlagen",
            font=("Segoe UI", 13, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_secondary
        ).pack(side=tk.LEFT)
        
        # Preset Buttons
        preset_frame = tk.Frame(container, bg=self.theme.bg_secondary)
        preset_frame.pack(fill=tk.X, pady=(0, 20))
        
        for preset_name in PasswordPreset.PRESETS.keys():
            btn = ModernButton(
                preset_frame,
                self.theme,
                text=preset_name,
                command=lambda p=preset_name: self._apply_preset(p),
                font=("Segoe UI", 9),
                bg=self.theme.bg_hover,
                fg=self.theme.text_primary,
                pady=6
            )
            btn.pack(side=tk.LEFT, padx=2)
            ToolTip(btn, f"Lädt Vorlage: {preset_name}", self.theme)

        tk.Label(
            container,
            text="🔤 Zeichenarten",
            font=("Segoe UI", 13, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_secondary
        ).pack(anchor=tk.W, pady=(15, 15))

        tooltips = {
            CharType.UPPERCASE: "Verwende Großbuchstaben für mehr Komplexität",
            CharType.LOWERCASE: "Verwende Kleinbuchstaben als Basis",
            CharType.DIGITS: "Füge Zahlen für zusätzliche Sicherheit hinzu",
            CharType.SPECIAL: "Sonderzeichen erhöhen die Stärke erheblich",
            CharType.WHITESPACE: "Leerzeichen für besonders sichere Passphrasen"
        }

        for char_type in CharType:
            var = tk.BooleanVar(value=True if char_type != CharType.WHITESPACE else False)
            self.char_vars[char_type] = var

            cb = tk.Checkbutton(
                container,
                text=f"  {char_type.label} ({char_type.hint})",
                variable=var,
                font=("Segoe UI", 11),
                fg=self.theme.text_primary,
                bg=self.theme.bg_secondary,
                activebackground=self.theme.bg_secondary,
                activeforeground=self.theme.text_primary,
                selectcolor=self.theme.accent,
                highlightthickness=0,
                bd=0,
                cursor="hand2"
            )
            cb.pack(anchor=tk.W, pady=6)
            ToolTip(cb, tooltips[char_type], self.theme)

    def _create_generate_button(self, parent: tk.Frame) -> None:
        """Erstellt Generieren-Button."""
        self.gen_button = ModernButton(
            parent,
            self.theme,
            text="⚡ PASSWORT GENERIEREN",
            command=self._generate_password,
            font=("Segoe UI", 13, "bold"),
            bg=self.theme.accent,
            fg="white",
            hover_color=self.theme.accent_hover,
            pady=16
        )
        self.gen_button.pack(fill=tk.X, pady=(30, 0))
        ToolTip(self.gen_button, "Oder drücke Ctrl+G", self.theme)

    def _create_result_section(self, parent: tk.Frame) -> None:
        """Erstellt Ergebnis-Anzeige."""
        container = self._create_section_container(parent)

        tk.Label(
            container,
            text="💾 Generiertes Passwort",
            font=("Segoe UI", 12, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_secondary
        ).pack(anchor=tk.W, pady=(0, 12))

        # Text Widget mit Scrollbar
        text_frame = tk.Frame(container, bg=self.theme.bg_hover)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        scrollbar = tk.Scrollbar(text_frame, bg=self.theme.bg_hover)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.password_text = tk.Text(
            text_frame,
            height=3,
            font=("Consolas", 14, "bold"),
            wrap=tk.WORD,
            bg=self.theme.bg_hover,
            fg=self.theme.success,
            insertbackground=self.theme.text_primary,
            relief=tk.FLAT,
            bd=0,
            padx=15,
            pady=15,
            state=tk.DISABLED,
            yscrollcommand=scrollbar.set
        )
        self.password_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.password_text.yview)

        # Action Buttons
        btn_frame = tk.Frame(container, bg=self.theme.bg_secondary)
        btn_frame.pack(fill=tk.X)

        self.copy_button = ModernButton(
            btn_frame,
            self.theme,
            text="📋 Kopieren",
            command=self._copy_password,
            font=("Segoe UI", 11, "bold"),
            bg=self.theme.bg_hover,
            fg=self.theme.text_primary,
            state=tk.DISABLED,
            pady=12
        )
        self.copy_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        ToolTip(self.copy_button, "Kopiert das Passwort in die Zwischenablage", self.theme)

        self.clear_button = ModernButton(
            btn_frame,
            self.theme,
            text="🗑️ Löschen",
            command=self._clear_password,
            font=("Segoe UI", 11, "bold"),
            bg=self.theme.bg_hover,
            fg=self.theme.text_primary,
            state=tk.DISABLED,
            pady=12
        )
        self.clear_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        ToolTip(self.clear_button, "Löscht das angezeigte Passwort", self.theme)
        
        # Weitere Buttons
        btn_frame2 = tk.Frame(container, bg=self.theme.bg_secondary)
        btn_frame2.pack(fill=tk.X, pady=(8, 0))
        
        self.save_button = ModernButton(
            btn_frame2,
            self.theme,
            text="💾 Speichern",
            command=self._save_password,
            font=("Segoe UI", 11, "bold"),
            bg=self.theme.bg_hover,
            fg=self.theme.text_primary,
            state=tk.DISABLED,
            pady=12
        )
        self.save_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        ToolTip(self.save_button, "Speichert das Passwort in einer Datei (Ctrl+S)", self.theme)
        
        self.history_button = ModernButton(
            btn_frame2,
            self.theme,
            text="📜 Historie",
            command=self._show_history,
            font=("Segoe UI", 11, "bold"),
            bg=self.theme.bg_hover,
            fg=self.theme.text_primary,
            pady=12
        )
        self.history_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ToolTip(self.history_button, "Zeigt die letzten 10 generierten Passwörter (Ctrl+H)", self.theme)

    def _create_strength_indicator(self, parent: tk.Frame) -> None:
        """Erstellt Stärke-Anzeige."""
        container = tk.Frame(parent, bg=self.theme.bg_secondary, pady=18, padx=20)
        container.pack(fill=tk.X, pady=(25, 0))

        tk.Label(
            container,
            text="⚡ Passwortstärke",
            font=("Segoe UI", 11, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_secondary
        ).pack(anchor=tk.W, pady=(0, 10))

        # Progress Bar mit Border
        progress_container = tk.Frame(container, bg=self.theme.border, height=12)
        progress_container.pack(fill=tk.X, pady=(0, 10))
        
        progress_bg = tk.Frame(progress_container, bg=self.theme.bg_hover, height=10)
        progress_bg.place(x=1, y=1, relwidth=0.998, relheight=0.8)

        self.strength_bar = tk.Frame(progress_bg, bg=self.theme.text_secondary, height=10)
        self.strength_bar.place(x=0, y=0, relwidth=0, relheight=1)

        self.strength_label = tk.Label(
            container,
            text="Generiere ein Passwort",
            font=("Segoe UI", 11, "bold"),
            fg=self.theme.text_secondary,
            bg=self.theme.bg_secondary
        )
        self.strength_label.pack(anchor=tk.W)
        
        # Entropy Label
        self.entropy_label = tk.Label(
            container,
            text="",
            font=("Segoe UI", 9),
            fg=self.theme.text_secondary,
            bg=self.theme.bg_secondary
        )
        self.entropy_label.pack(anchor=tk.W, pady=(5, 0))

    def _create_section_container(self, parent: tk.Frame) -> tk.Frame:
        """Erstellt einen Section-Container."""
        # Border Container
        border_frame = tk.Frame(
            parent,
            bg=self.theme.border,
            padx=1,
            pady=1
        )
        border_frame.pack(fill=tk.X, pady=(0, 22))
        
        # Inner Container
        container = tk.Frame(
            border_frame,
            bg=self.theme.bg_secondary,
            pady=20,
            padx=20
        )
        container.pack(fill=tk.X)
        return container

    def _apply_preset(self, preset_name: str) -> None:
        """Wendet ein Preset an."""
        preset = PasswordPreset.PRESETS.get(preset_name)
        if preset:
            self.length_var.set(preset["length"])
            for char_type, var in self.char_vars.items():
                var.set(char_type in preset["types"])
    
    def _update_length_label(self, value: str) -> None:
        """Aktualisiert Label bei Slider-Änderung."""
        # Direkte Integer-Konvertierung ohne String-Zwischenschritt
        int_value = int(float(value))
        if not hasattr(self, '_last_length_value') or self._last_length_value != int_value:
            self._last_length_value = int_value
            self.length_label.config(text=str(int_value))

    def _generate_password(self) -> None:
        """Generiert ein neues Passwort und zeigt es in einem Popup an."""
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
            
            # Zu Historie hinzufügen
            self.password_history.append((password, datetime.now()))
            if len(self.password_history) > 10:
                self.password_history.pop(0)
            
            self.current_password = password
            
            # Passwort im Hauptfenster anzeigen
            self.password_text.config(state=tk.NORMAL)
            self.password_text.delete(1.0, tk.END)
            self.password_text.insert(1.0, password)
            self.password_text.config(state=tk.DISABLED)
            
            # Buttons aktivieren
            self.copy_button.config(state=tk.NORMAL)
            self.clear_button.config(state=tk.NORMAL)
            self.save_button.config(state=tk.NORMAL)
            
            # Stärke-Anzeige aktualisieren
            self._update_strength_indicator(password)

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

            # Stärke und Entropy anzeigen
            strength, description = self.generator.calculate_strength(password)
            entropy = self.generator.calculate_entropy(password)
            
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
            ).pack(pady=(0, 5))
            
            tk.Label(
                content,
                text=f"Entropie: {entropy} Bits",
                font=("Segoe UI", 10),
                fg=self.theme.text_secondary,
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

        except ValueError as e:
            messagebox.showwarning(
                "Ungültige Eingabe",
                str(e),
                parent=self.root
            )
        except Exception as e:
            import traceback
            error_msg = f"Unerwarteter Fehler:\n\n{str(e)}\n\n{traceback.format_exc()}"
            messagebox.showerror("Fehler", error_msg, parent=self.root)

    def _update_strength_indicator(self, password: str) -> None:
        """Aktualisiert die Stärke-Anzeige."""
        strength, description = self.generator.calculate_strength(password)
        entropy = self.generator.calculate_entropy(password)

        # Farbe basierend auf Stärke - optimiert mit dict-lookup
        color_map = {
            (80, 101): self.theme.success,
            (60, 80): self.theme.accent,
            (40, 60): self.theme.warning,
            (0, 40): self.theme.danger
        }
        
        color = next(c for (low, high), c in color_map.items() if low <= strength < high)

        # Batch-Update für bessere Performance
        relwidth = strength / 100
        self.strength_bar.place_configure(relwidth=relwidth)
        self.strength_bar.config(bg=color)
        self.strength_label.config(text=description, fg=color)
        
        # Entropy anzeigen
        entropy_text = f"Entropie: {entropy} Bits"
        if entropy >= 80:
            entropy_desc = " (Ausgezeichnet)"
        elif entropy >= 60:
            entropy_desc = " (Gut)"
        elif entropy >= 40:
            entropy_desc = " (Akzeptabel)"
        else:
            entropy_desc = " (Schwach)"
        
        self.entropy_label.config(text=entropy_text + entropy_desc, fg=color)

    def _copy_password(self) -> None:
        """Kopiert Passwort in Zwischenablage."""
        password = self.password_text.get(1.0, tk.END).strip()
        if password:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                self.root.update()  # Clipboard sofort flushen

                # Visuelles Feedback - gecachte Werte
                if not hasattr(self, '_copy_button_original_text'):
                    self._copy_button_original_text = self.copy_button.cget("text")
                    self._copy_button_original_bg = self.copy_button.cget("bg")
                
                self.copy_button.config(text="✓ Kopiert!", bg=self.theme.success)
                self.root.after(1500, lambda: self.copy_button.config(
                    text=self._copy_button_original_text, 
                    bg=self._copy_button_original_bg
                ))
            except Exception as e:
                messagebox.showerror(
                    "Fehler",
                    f"Kopieren fehlgeschlagen: {e}",
                    parent=self.root
                )

    def _clear_password(self) -> None:
        """Löscht das angezeigte Passwort."""
        # Batch-Update für bessere Performance
        self.password_text.config(state=tk.NORMAL)
        self.password_text.delete(1.0, tk.END)
        self.password_text.config(state=tk.DISABLED)
        
        self.current_password = None
        
        # Batch-Button-Update
        self.copy_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        
        # Strength-Reset
        self.strength_bar.place_configure(relwidth=0)
        self.strength_label.config(
            text="Generiere ein Passwort",
            fg=self.theme.text_secondary
        )
        self.entropy_label.config(text="")
        
        # Force UI update
        self.root.update_idletasks()
    
    def _save_password(self) -> None:
        """Speichert das aktuelle Passwort in eine Datei."""
        if not self.current_password:
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text-Dateien", "*.txt"), ("Alle Dateien", "*.*")],
            title="Passwort speichern"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Generiertes Passwort\n")
                    f.write(f"Datum: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
                    f.write(f"Länge: {len(self.current_password)}\n")
                    entropy = self.generator.calculate_entropy(self.current_password)
                    f.write(f"Entropie: {entropy} Bits\n")
                    f.write(f"\nPasswort:\n{self.current_password}\n")
                
                messagebox.showinfo(
                    "Erfolg",
                    f"Passwort wurde gespeichert in:\n{file_path}",
                    parent=self.root
                )
            except Exception as e:
                messagebox.showerror(
                    "Fehler",
                    f"Speichern fehlgeschlagen: {e}",
                    parent=self.root
                )
    
    def _show_history(self) -> None:
        """Zeigt die Passwort-Historie an."""
        if not self.password_history:
            messagebox.showinfo(
                "Historie",
                "Keine Passwörter in der Historie.",
                parent=self.root
            )
            return
        
        # Historie-Popup
        history_popup = tk.Toplevel(self.root)
        history_popup.title("📜 Passwort-Historie")
        history_popup.geometry("600x500")
        history_popup.configure(bg=self.theme.bg_primary)
        history_popup.transient(self.root)
        
        # Zentrieren
        history_popup.update_idletasks()
        x = (history_popup.winfo_screenwidth() // 2) - (history_popup.winfo_width() // 2)
        y = (history_popup.winfo_screenheight() // 2) - (history_popup.winfo_height() // 2)
        history_popup.geometry(f"+{x}+{y}")
        
        content = tk.Frame(history_popup, bg=self.theme.bg_primary, padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(
            content,
            text="Letzte 10 generierte Passwörter",
            font=("Segoe UI", 14, "bold"),
            fg=self.theme.text_primary,
            bg=self.theme.bg_primary
        ).pack(pady=(0, 15))
        
        # Scrollable Frame
        canvas = tk.Canvas(content, bg=self.theme.bg_primary, highlightthickness=0)
        scrollbar = tk.Scrollbar(content, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.theme.bg_primary)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Historie-Einträge
        for i, (pwd, timestamp) in enumerate(reversed(self.password_history)):
            frame = tk.Frame(scrollable_frame, bg=self.theme.bg_secondary, pady=10, padx=15)
            frame.pack(fill=tk.X, pady=5)
            
            time_str = timestamp.strftime("%H:%M:%S")
            tk.Label(
                frame,
                text=f"{len(self.password_history) - i}. {time_str}",
                font=("Segoe UI", 9),
                fg=self.theme.text_secondary,
                bg=self.theme.bg_secondary
            ).pack(anchor=tk.W)
            
            pwd_text = tk.Text(
                frame,
                height=2,
                font=("Consolas", 10),
                wrap=tk.WORD,
                bg=self.theme.bg_hover,
                fg=self.theme.text_primary,
                relief=tk.FLAT,
                bd=0,
                padx=10,
                pady=5
            )
            pwd_text.pack(fill=tk.X, pady=(5, 5))
            pwd_text.insert("1.0", pwd)
            pwd_text.config(state=tk.DISABLED)
            
            def copy_from_history(p=pwd):
                self.root.clipboard_clear()
                self.root.clipboard_append(p)
                messagebox.showinfo("Erfolg", "Passwort kopiert!", parent=history_popup)
            
            ModernButton(
                frame,
                self.theme,
                text="📋 Kopieren",
                command=copy_from_history,
                font=("Segoe UI", 9),
                bg=self.theme.bg_hover,
                fg=self.theme.text_primary,
                pady=5
            ).pack(anchor=tk.E)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ModernButton(
            content,
            self.theme,
            text="Schließen",
            command=history_popup.destroy,
            font=("Segoe UI", 11, "bold"),
            bg=self.theme.accent,
            fg="white",
            pady=10
        ).pack(pady=(15, 0), fill=tk.X)
    
    def _toggle_theme(self) -> None:
        """Wechselt zwischen Dark und Light Mode."""
        if self.theme.name == "dark":
            self.theme = LightTheme()
        else:
            self.theme = Theme()
        
        # UI neu aufbauen
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self._create_widgets()
        self.root.configure(bg=self.theme.bg_primary)


def main() -> None:
    """Haupteinstiegspunkt der Anwendung."""
    try:
        root = tk.Tk()
        app = PasswordGeneratorGUI(root)
        root.mainloop()
    except Exception as e:
        import traceback
        print(f"Kritischer Fehler beim Start der Anwendung:\n{e}\n")
        print(traceback.format_exc())
        import sys
        sys.exit(1)


if __name__ == "__main__":
    main()