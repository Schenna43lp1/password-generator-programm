import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip


class PasswortGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Passwort-Generator")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        # Styling
        style = ttk.Style()
        style.theme_use('clam')

        self.erstelle_gui()

    def erstelle_gui(self):
        # Hauptframe
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Titel
        titel = ttk.Label(main_frame, text="Passwort-Generator",
                          font=("Arial", 18, "bold"))
        titel.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # Länge-Slider
        ttk.Label(main_frame, text="Passwortlänge:",
                  font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=5)

        self.laenge_var = tk.IntVar(value=12)
        self.laenge_label = ttk.Label(main_frame, text="12",
                                      font=("Arial", 10, "bold"))
        self.laenge_label.grid(row=1, column=1, sticky=tk.E, pady=5)

        self.laenge_slider = ttk.Scale(main_frame, from_=6, to=32,
                                       variable=self.laenge_var,
                                       orient=tk.HORIZONTAL,
                                       command=self.update_laenge)
        self.laenge_slider.grid(row=2, column=0, columnspan=2,
                                sticky=(tk.W, tk.E), pady=(0, 15))

        # Checkboxen
        self.gross_var = tk.BooleanVar(value=True)
        self.klein_var = tk.BooleanVar(value=True)
        self.zahlen_var = tk.BooleanVar(value=True)
        self.sonder_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(main_frame, text="Großbuchstaben (A-Z)",
                        variable=self.gross_var).grid(row=3, column=0,
                                                      sticky=tk.W, pady=3)
        ttk.Checkbutton(main_frame, text="Kleinbuchstaben (a-z)",
                        variable=self.klein_var).grid(row=4, column=0,
                                                      sticky=tk.W, pady=3)
        ttk.Checkbutton(main_frame, text="Zahlen (0-9)",
                        variable=self.zahlen_var).grid(row=5, column=0,
                                                       sticky=tk.W, pady=3)
        ttk.Checkbutton(main_frame, text="Sonderzeichen (!@#$...)",
                        variable=self.sonder_var).grid(row=6, column=0,
                                                       sticky=tk.W, pady=3)

        # Generieren-Button
        self.gen_button = ttk.Button(main_frame, text="Passwort generieren",
                                     command=self.generiere_passwort)
        self.gen_button.grid(row=7, column=0, columnspan=2,
                             pady=(20, 10), sticky=(tk.W, tk.E))

        # Ergebnis-Textfeld
        self.passwort_text = tk.Text(main_frame, height=3, width=40,
                                     font=("Courier", 12), wrap=tk.WORD)
        self.passwort_text.grid(row=8, column=0, columnspan=2,
                                pady=(0, 10), sticky=(tk.W, tk.E))

        # Button-Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=9, column=0, columnspan=2, sticky=(tk.W, tk.E))

        self.kopieren_button = ttk.Button(button_frame, text="Kopieren",
                                          command=self.kopiere_passwort,
                                          state=tk.DISABLED)
        self.kopieren_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        self.loeschen_button = ttk.Button(button_frame, text="Löschen",
                                          command=self.loesche_passwort,
                                          state=tk.DISABLED)
        self.loeschen_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))

    def update_laenge(self, wert):
        self.laenge_label.config(text=str(int(float(wert))))

    def generiere_passwort(self):
        zeichen_pool = ""

        if self.gross_var.get():
            zeichen_pool += string.ascii_uppercase
        if self.klein_var.get():
            zeichen_pool += string.ascii_lowercase
        if self.zahlen_var.get():
            zeichen_pool += string.digits
        if self.sonder_var.get():
            zeichen_pool += string.punctuation

        if not zeichen_pool:
            messagebox.showwarning("Warnung",
                                   "Bitte wähle mindestens eine Zeichenart aus!")
            return

        laenge = int(self.laenge_var.get())
        passwort = ''.join(random.choice(zeichen_pool) for _ in range(laenge))

        self.passwort_text.delete(1.0, tk.END)
        self.passwort_text.insert(1.0, passwort)

        self.kopieren_button.config(state=tk.NORMAL)
        self.loeschen_button.config(state=tk.NORMAL)

    def kopiere_passwort(self):
        passwort = self.passwort_text.get(1.0, tk.END).strip()
        if passwort:
            try:
                pyperclip.copy(passwort)
                messagebox.showinfo("Erfolg", "Passwort in Zwischenablage kopiert!")
            except:
                # Fallback ohne pyperclip
                self.root.clipboard_clear()
                self.root.clipboard_append(passwort)
                messagebox.showinfo("Erfolg", "Passwort in Zwischenablage kopiert!")

    def loesche_passwort(self):
        self.passwort_text.delete(1.0, tk.END)
        self.kopieren_button.config(state=tk.DISABLED)
        self.loeschen_button.config(state=tk.DISABLED)


def main():
    root = tk.Tk()
    app = PasswortGenerator(root)
    root.mainloop()


if __name__ == "__main__":
    main()