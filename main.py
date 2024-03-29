import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinterdnd2 import DND_FILES, TkinterDnD
from contextlib import redirect_stdout
from Crypto import validate_certificate_chain
import io
# Couleurs pour le mode clair
light_mode_background = "#ffffff"
light_mode_foreground = "#000000"
light_mode_button = "#f0f0f0"
light_mode_text = "#000000"
light_mode_input_bg = "#ffffff"

# Couleurs pour le mode sombre
dark_mode_background = "#333333"
dark_mode_foreground = "#ffffff"
dark_mode_button = "#555555"
dark_mode_text = "#ffffff"
dark_mode_input_bg = "#444444"


class StdoutRedirector(object):
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)

    def flush(self):
        pass

def run_validation():
    file_format = file_format_var.get()
    file_paths = listbox.get(0, tk.END)
    if not file_paths:
        messagebox.showwarning("Warning", "Please add at least one certificate file.")
        return

    info_text.delete(1.0, tk.END)
    with redirect_stdout(StdoutRedirector(info_text)):
        validate_certificate_chain(file_paths, file_format)

def on_drop(event):
    filepaths = root.tk.splitlist(event.data)
    for filepath in filepaths:
        listbox.insert(tk.END, filepath)

def move_up():
    pos_list = listbox.curselection()
    for pos in pos_list:
        if pos > 0:
            text = listbox.get(pos)
            listbox.delete(pos)
            listbox.insert(pos - 1, text)
            listbox.select_set(pos - 1)

def move_down():
    pos_list = listbox.curselection()
    for pos in reversed(pos_list):
        if pos < listbox.size() - 1:
            text = listbox.get(pos)
            listbox.delete(pos)
            listbox.insert(pos + 1, text)
            listbox.select_set(pos + 1)

def open_file_dialog():
    filepaths = filedialog.askopenfilenames(filetypes=[("Certificate files", "*.pem *.der")])
    for filepath in filepaths:
        listbox.insert(tk.END, filepath)
def delete_selected():
    """Supprime les certificats sélectionnés de la Listbox."""
    for index in reversed(listbox.curselection()):
        listbox.delete(index)

def clear_all():
    """Efface tous les certificats de la Listbox."""
    listbox.delete(0, tk.END)

def toggle_theme():
    current_mode = theme_var.get()
    if current_mode == "Dark":
        # Appliquer le mode sombre
        new_mode = "Light"
        colors = {
            'background': dark_mode_background,
            'foreground': dark_mode_foreground,
            'button': dark_mode_button,
            'text': dark_mode_text,
            'input_bg': dark_mode_input_bg
        }
    else:
        # Appliquer le mode clair
        new_mode = "Dark"
        colors = {
            'background': light_mode_background,
            'foreground': light_mode_foreground,
            'button': light_mode_button,
            'text': light_mode_text,
            'input_bg': light_mode_input_bg
        }

    # Mise à jour des couleurs des widgets
    root.config(bg=colors['background'])
    frame_button.config(bg=colors['background'])  # Assume this is your frame for buttons
    frame_formats.config(bg=colors['background'])
    frame_top.config(bg=colors['background'])
    listbox.config(bg=colors['input_bg'], fg=colors['foreground'])
    info_text.config(bg=colors['input_bg'], fg=colors['foreground'])
    
    verify_button.config(bg=colors['button'], fg=colors['text'])
    up_button.config(bg=colors['button'], fg=colors['text'])
    down_button.config(bg=colors['button'], fg=colors['text'])
    delete_button.config(bg=colors['button'], fg=colors['text'])
    clear_button.config(bg=colors['button'], fg=colors['text'])
    add_button.config(bg=colors['button'], fg=colors['text'])  # Assuming you have this from file dialog function
    radio_pem.config(bg=colors['background'], fg=colors['foreground'], selectcolor=colors['background'])
    radio_der.config(bg=colors['background'], fg=colors['foreground'], selectcolor=colors['background'])
    theme_button.config(bg=colors['button'], fg=colors['text'], text=f"{new_mode} Mode")

    # Mise à jour de la variable de thème
    theme_var.set(new_mode)



# GUI setup
# Configuration de l'interface utilisateur
root = TkinterDnD.Tk()
# Déclaration et initialisation de frame_formats avant la fonction toggle_theme
frame_formats = tk.Frame(root)
frame_formats.pack(side=tk.TOP, pady=4)
root.title("Certificate Verifier")
root.geometry("800x600")

file_format_var = tk.StringVar(value='PEM')

theme_var = tk.StringVar(value="Light")  # Assurez-vous que cette ligne est avant toggle_theme

# Cadre pour les boutons et les options de format
frame_top = tk.Frame(root)
frame_top.pack(side=tk.TOP, fill=tk.X)

frame_button = tk.Frame(frame_top)
frame_button.pack(side=tk.LEFT, padx=10, pady=4)


# Bouton pour ajouter des certificats
add_button = tk.Button(frame_button, text="Add Certificate", command=open_file_dialog)
add_button.pack(side=tk.LEFT, anchor='w')

# Boutons radio pour choisir le format de certificat
radio_pem = tk.Radiobutton(frame_button, text="PEM", variable=file_format_var, value='PEM', indicatoron=False)
radio_der = tk.Radiobutton(frame_button, text="DER", variable=file_format_var, value='DER', indicatoron=False)
radio_pem.pack(side=tk.LEFT,  expand=True)
radio_der.pack(side=tk.LEFT,  expand=True)


# Ajout du bouton de basculement du thème à la frame top

theme_button = tk.Button(frame_top, text="Dark Mode", command=toggle_theme)
theme_button.pack(side=tk.RIGHT, pady=4)
# Listbox pour afficher les certificats chargés
listbox = tk.Listbox(root, selectmode=tk.EXTENDED, height=5)
listbox.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)  # L'utilisation de fill=tk.BOTH et expand=True permet au Listbox de remplir l'espace disponible.


button_frame = tk.Frame(root)
button_frame.pack(fill=tk.X, pady=5)

# Définition des boutons dans le cadre.
up_button = tk.Button(button_frame, text="Move Up", command=move_up)
down_button = tk.Button(button_frame, text="Move Down", command=move_down)
delete_button = tk.Button(button_frame, text="Delete Selected", command=delete_selected)
clear_button = tk.Button(button_frame, text="Clear All", command=clear_all)

# Configuration des boutons pour qu'ils se répartissent uniformément.
up_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
down_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
delete_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
clear_button.pack(side=tk.LEFT, fill=tk.X, expand=True)

# Autres éléments de l'interface utilisateur.
info_text = scrolledtext.ScrolledText(root, height=10)
info_text.pack(fill=tk.BOTH, expand=True, pady=10)
verify_button = tk.Button(root, text="Verify Certificates", command=run_validation)
verify_button.pack(side=tk.BOTTOM, pady=10)




root.drop_target_register(DND_FILES)
root.dnd_bind('<<Drop>>', on_drop)

root.mainloop()
