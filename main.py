import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import hashlib
import secrets
import string
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import re
import threading
import time
from PIL import Image, ImageTk
import webbrowser
import cryptography 

class PasswordStrengthAnalyzer:
    @staticmethod
    def analyze_password(password):
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        if len(password) >= 12:
            score += 1
        
        strength_levels = {
            0: "Very Weak",
            1: "Weak", 
            2: "Fair",
            3: "Good",
            4: "Strong",
            5: "Very Strong",
            6: "Excellent"
        }
        
        return {
            'score': score,
            'strength': strength_levels[score],
            'feedback': feedback
        }

class PasswordGenerator:
    @staticmethod
    def generate_password(length=12, include_uppercase=True, include_lowercase=True, 
                         include_numbers=True, include_symbols=True, exclude_ambiguous=True):
        chars = ""
        
        if include_lowercase:
            chars += string.ascii_lowercase
        if include_uppercase:
            chars += string.ascii_uppercase
        if include_numbers:
            chars += string.digits
        if include_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if exclude_ambiguous:
            ambiguous = "0O1lI"
            chars = ''.join(c for c in chars if c not in ambiguous)
        
        if not chars:
            return ""
        
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password

class PasswordManager:
    def __init__(self):
        self.key = None
        self.cipher = None
        self.master_password_hash = None
        self.data_file = "passwords.enc"
        self.config_file = "config.json"
        self.passwords = {}
        self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.master_password_hash = config.get('master_hash')
            except:
                pass
    
    def save_config(self):
        config = {'master_hash': self.master_password_hash}
        with open(self.config_file, 'w') as f:
            json.dump(config, f)
    
    def generate_key_from_password(self, password):
        salt = b'salt_'  # In production, use a random salt
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return Fernet(base64.urlsafe_b64encode(key[:32]))
    
    def set_master_password(self, password):
        self.master_password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.cipher = self.generate_key_from_password(password)
        self.save_config()
    
    def verify_master_password(self, password):
        if not self.master_password_hash:
            return False
        return hashlib.sha256(password.encode()).hexdigest() == self.master_password_hash
    
    def load_passwords(self):
        if os.path.exists(self.data_file) and self.cipher:
            try:
                with open(self.data_file, 'rb') as f:
                    encrypted_data = f.read()
                    decrypted_data = self.cipher.decrypt(encrypted_data)
                    self.passwords = json.loads(decrypted_data.decode())
            except:
                self.passwords = {}
    
    def save_passwords(self):
        if self.cipher:
            data = json.dumps(self.passwords, indent=2)
            encrypted_data = self.cipher.encrypt(data.encode())
            with open(self.data_file, 'wb') as f:
                f.write(encrypted_data)
    
    def add_password(self, site, username, password, notes=""):
        entry = {
            'username': username,
            'password': password,
            'notes': notes,
            'created': datetime.now().isoformat(),
            'last_modified': datetime.now().isoformat()
        }
        self.passwords[site] = entry
        self.save_passwords()
    
    def get_password(self, site):
        return self.passwords.get(site)
    
    def delete_password(self, site):
        if site in self.passwords:
            del self.passwords[site]
            self.save_passwords()
            return True
        return False
    
    def search_passwords(self, query):
        results = {}
        query_lower = query.lower()
        for site, data in self.passwords.items():
            if (query_lower in site.lower() or 
                query_lower in data['username'].lower() or
                query_lower in data['notes'].lower()):
                results[site] = data
        return results

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Password Manager")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        
        self.manager = PasswordManager()
        self.is_authenticated = False
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.create_login_screen()
    
    def configure_styles(self):
        self.style.configure('Title.TLabel', 
                           font=('Helvetica', 18, 'bold'),
                           background='#2c3e50',
                           foreground='white')
        
        self.style.configure('Header.TLabel',
                           font=('Helvetica', 12, 'bold'),
                           background='#34495e',
                           foreground='white')
        
        self.style.configure('Custom.TButton',
                           font=('Helvetica', 10),
                           padding=10)
    
    def create_login_screen(self):
        self.clear_screen()
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#2c3e50')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = tk.Label(main_frame, text="🔐 Smart Password Manager", 
                              font=('Helvetica', 24, 'bold'),
                              bg='#2c3e50', fg='white')
        title_label.pack(pady=(0, 30))
        
        # Login frame
        login_frame = tk.Frame(main_frame, bg='#34495e', relief='raised', bd=2)
        login_frame.pack(pady=20, padx=50, fill='x')
        
        tk.Label(login_frame, text="Master Password", 
                font=('Helvetica', 12, 'bold'),
                bg='#34495e', fg='white').pack(pady=(20, 10))
        
        self.master_password_entry = tk.Entry(login_frame, show="*", 
                                             font=('Helvetica', 12),
                                             width=30, relief='flat', bd=5)
        self.master_password_entry.pack(pady=(0, 20))
        self.master_password_entry.bind('<Return>', lambda e: self.authenticate())
        
        button_frame = tk.Frame(login_frame, bg='#34495e')
        button_frame.pack(pady=(0, 20))
        
        login_btn = tk.Button(button_frame, text="Login", 
                             command=self.authenticate,
                             bg='#3498db', fg='white',
                             font=('Helvetica', 12, 'bold'),
                             padx=20, pady=10, relief='flat')
        login_btn.pack(side='left', padx=10)
        
        if not self.manager.master_password_hash:
            setup_btn = tk.Button(button_frame, text="First Time Setup", 
                                 command=self.setup_master_password,
                                 bg='#e74c3c', fg='white',
                                 font=('Helvetica', 12, 'bold'),
                                 padx=20, pady=10, relief='flat')
            setup_btn.pack(side='left', padx=10)
        
        self.master_password_entry.focus()
    
    def setup_master_password(self):
        password = simpledialog.askstring("Setup", "Create Master Password:", show='*')
        if password:
            confirm = simpledialog.askstring("Setup", "Confirm Master Password:", show='*')
            if password == confirm:
                self.manager.set_master_password(password)
                messagebox.showinfo("Success", "Master password set successfully!")
                self.create_login_screen()
            else:
                messagebox.showerror("Error", "Passwords don't match!")
    
    def authenticate(self):
        password = self.master_password_entry.get()
        if self.manager.verify_master_password(password):
            self.manager.cipher = self.manager.generate_key_from_password(password)
            self.manager.load_passwords()
            self.is_authenticated = True
            self.create_main_screen()
        else:
            messagebox.showerror("Error", "Invalid master password!")
            self.master_password_entry.delete(0, tk.END)
    
    def create_main_screen(self):
        self.clear_screen()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Password list tab
        self.create_password_list_tab()
        
        # Add password tab
        self.create_add_password_tab()
        
        # Password generator tab
        self.create_generator_tab()
        
        # Security analysis tab
        self.create_security_tab()
    
    def create_password_list_tab(self):
        # Password list frame
        list_frame = ttk.Frame(self.notebook)
        self.notebook.add(list_frame, text="Password Vault")
        
        # Search frame
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(search_frame, text="Search:").pack(side='left')
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.pack(side='left', padx=10)
        self.search_entry.bind('<KeyRelease>', self.search_passwords)
        
        ttk.Button(search_frame, text="Refresh", 
                  command=self.refresh_password_list).pack(side='right')
        
        # Password treeview
        columns = ('Site', 'Username', 'Created', 'Last Modified')
        self.password_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        for col in columns:
            self.password_tree.heading(col, text=col)
            self.password_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=scrollbar.set)
        
        self.password_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y', pady=10)
        
        # Context menu
        self.password_tree.bind('<Button-3>', self.show_context_menu)
        self.password_tree.bind('<Double-1>', self.view_password)
        
        self.refresh_password_list()
    
    def create_add_password_tab(self):
        add_frame = ttk.Frame(self.notebook)
        self.notebook.add(add_frame, text="Add Password")
        
        # Form frame
        form_frame = ttk.LabelFrame(add_frame, text="New Password Entry", padding=20)
        form_frame.pack(fill='x', padx=20, pady=20)
        
        # Site
        ttk.Label(form_frame, text="Website/Service:").grid(row=0, column=0, sticky='w', pady=5)
        self.site_entry = ttk.Entry(form_frame, width=40)
        self.site_entry.grid(row=0, column=1, columnspan=2, sticky='ew', pady=5)
        
        # Username
        ttk.Label(form_frame, text="Username/Email:").grid(row=1, column=0, sticky='w', pady=5)
        self.username_entry = ttk.Entry(form_frame, width=40)
        self.username_entry.grid(row=1, column=1, columnspan=2, sticky='ew', pady=5)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky='w', pady=5)
        self.password_entry = ttk.Entry(form_frame, width=30, show="*")
        self.password_entry.grid(row=2, column=1, sticky='ew', pady=5)
        self.password_entry.bind('<KeyRelease>', self.update_strength_meter)
        
        ttk.Button(form_frame, text="Generate", 
                  command=self.generate_password_for_entry).grid(row=2, column=2, padx=5, pady=5)
        
        # Password strength meter
        self.strength_frame = ttk.Frame(form_frame)
        self.strength_frame.grid(row=3, column=0, columnspan=3, sticky='ew', pady=10)
        
        self.strength_label = ttk.Label(self.strength_frame, text="Password Strength:")
        self.strength_label.pack(side='left')
        
        self.strength_progress = ttk.Progressbar(self.strength_frame, length=200, mode='determinate')
        self.strength_progress.pack(side='left', padx=10)
        
        self.strength_text = ttk.Label(self.strength_frame, text="")
        self.strength_text.pack(side='left', padx=10)
        
        # Notes
        ttk.Label(form_frame, text="Notes:").grid(row=4, column=0, sticky='nw', pady=5)
        self.notes_text = tk.Text(form_frame, width=40, height=4)
        self.notes_text.grid(row=4, column=1, columnspan=2, sticky='ew', pady=5)
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Save Password", 
                  command=self.save_password).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Clear Form", 
                  command=self.clear_form).pack(side='left', padx=10)
        
        form_frame.columnconfigure(1, weight=1)
    
    def create_generator_tab(self):
        gen_frame = ttk.Frame(self.notebook)
        self.notebook.add(gen_frame, text="Password Generator")
        
        # Generator settings
        settings_frame = ttk.LabelFrame(gen_frame, text="Generator Settings", padding=20)
        settings_frame.pack(fill='x', padx=20, pady=20)
        
        # Length
        ttk.Label(settings_frame, text="Length:").grid(row=0, column=0, sticky='w', pady=5)
        self.length_var = tk.IntVar(value=12)
        length_scale = ttk.Scale(settings_frame, from_=4, to=50, 
                                variable=self.length_var, orient='horizontal')
        length_scale.grid(row=0, column=1, sticky='ew', pady=5)
        self.length_label = ttk.Label(settings_frame, text="12")
        self.length_label.grid(row=0, column=2, pady=5)
        
        length_scale.configure(command=self.update_length_label)
        
        # Checkboxes
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_numbers = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(settings_frame, text="Include Uppercase", 
                       variable=self.include_uppercase).grid(row=1, column=0, sticky='w', pady=2)
        ttk.Checkbutton(settings_frame, text="Include Lowercase", 
                       variable=self.include_lowercase).grid(row=2, column=0, sticky='w', pady=2)
        ttk.Checkbutton(settings_frame, text="Include Numbers", 
                       variable=self.include_numbers).grid(row=3, column=0, sticky='w', pady=2)
        ttk.Checkbutton(settings_frame, text="Include Symbols", 
                       variable=self.include_symbols).grid(row=4, column=0, sticky='w', pady=2)
        ttk.Checkbutton(settings_frame, text="Exclude Ambiguous Characters", 
                       variable=self.exclude_ambiguous).grid(row=5, column=0, sticky='w', pady=2)
        
        # Generate button
        ttk.Button(settings_frame, text="Generate Password", 
                  command=self.generate_password).grid(row=6, column=0, columnspan=3, pady=20)
        
        # Generated password display
        result_frame = ttk.LabelFrame(gen_frame, text="Generated Password", padding=20)
        result_frame.pack(fill='x', padx=20, pady=20)
        
        self.generated_password = tk.StringVar()
        password_entry = ttk.Entry(result_frame, textvariable=self.generated_password, 
                                  width=50, font=('Courier', 12))
        password_entry.pack(pady=10)
        
        button_frame = ttk.Frame(result_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Copy to Clipboard", 
                  command=self.copy_to_clipboard).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Show/Hide", 
                  command=self.toggle_password_visibility).pack(side='left', padx=10)
        
        settings_frame.columnconfigure(1, weight=1)
    
    def create_security_tab(self):
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security Analysis")
        
        # Analysis results
        analysis_frame = ttk.LabelFrame(security_frame, text="Password Security Analysis", padding=20)
        analysis_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Analysis text
        self.analysis_text = tk.Text(analysis_frame, wrap='word', font=('Helvetica', 10))
        analysis_scrollbar = ttk.Scrollbar(analysis_frame, orient='vertical', 
                                          command=self.analysis_text.yview)
        self.analysis_text.configure(yscrollcommand=analysis_scrollbar.set)
        
        self.analysis_text.pack(side='left', fill='both', expand=True)
        analysis_scrollbar.pack(side='right', fill='y')
        
        # Refresh button
        ttk.Button(security_frame, text="Analyze All Passwords", 
                  command=self.analyze_all_passwords).pack(pady=10)
        
        # Auto-analyze on tab creation
        self.root.after(100, self.analyze_all_passwords)
    
    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def refresh_password_list(self):
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        for site, data in self.manager.passwords.items():
            created = data['created'][:10] if 'created' in data else "Unknown"
            modified = data['last_modified'][:10] if 'last_modified' in data else "Unknown"
            
            self.password_tree.insert('', 'end', values=(
                site, data['username'], created, modified
            ))
    
    def search_passwords(self, event=None):
        query = self.search_entry.get()
        if not query:
            self.refresh_password_list()
            return
        
        # Clear current items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Search and display results
        results = self.manager.search_passwords(query)
        for site, data in results.items():
            created = data['created'][:10] if 'created' in data else "Unknown"
            modified = data['last_modified'][:10] if 'last_modified' in data else "Unknown"
            
            self.password_tree.insert('', 'end', values=(
                site, data['username'], created, modified
            ))
    
    def show_context_menu(self, event):
        item = self.password_tree.selection()[0]
        if item:
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label="View Password", command=self.view_password)
            context_menu.add_command(label="Copy Password", command=self.copy_password)
            context_menu.add_command(label="Copy Username", command=self.copy_username)
            context_menu.add_separator()
            context_menu.add_command(label="Delete", command=self.delete_password)
            
            context_menu.tk_popup(event.x_root, event.y_root)
    
    def view_password(self, event=None):
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = self.password_tree.item(selection[0])
        site = item['values'][0]
        data = self.manager.get_password(site)
        
        if data:
            # Create view window
            view_window = tk.Toplevel(self.root)
            view_window.title(f"Password Details - {site}")
            view_window.geometry("400x300")
            view_window.configure(bg='#2c3e50')
            
            # Display information
            tk.Label(view_window, text=f"Site: {site}", 
                    bg='#2c3e50', fg='white', font=('Helvetica', 12, 'bold')).pack(pady=10)
            tk.Label(view_window, text=f"Username: {data['username']}", 
                    bg='#2c3e50', fg='white').pack(pady=5)
            tk.Label(view_window, text=f"Password: {data['password']}", 
                    bg='#2c3e50', fg='white').pack(pady=5)
            
            if data.get('notes'):
                tk.Label(view_window, text="Notes:", 
                        bg='#2c3e50', fg='white', font=('Helvetica', 10, 'bold')).pack(pady=(10, 5))
                tk.Label(view_window, text=data['notes'], 
                        bg='#2c3e50', fg='white', wraplength=350).pack(pady=5)
    
    def copy_password(self):
        selection = self.password_tree.selection()
        if selection:
            item = self.password_tree.item(selection[0])
            site = item['values'][0]
            data = self.manager.get_password(site)
            if data:
                self.root.clipboard_clear()
                self.root.clipboard_append(data['password'])
                messagebox.showinfo("Copied", "Password copied to clipboard!")
    
    def copy_username(self):
        selection = self.password_tree.selection()
        if selection:
            item = self.password_tree.item(selection[0])
            site = item['values'][0]
            data = self.manager.get_password(site)
            if data:
                self.root.clipboard_clear()
                self.root.clipboard_append(data['username'])
                messagebox.showinfo("Copied", "Username copied to clipboard!")
    
    def delete_password(self):
        selection = self.password_tree.selection()
        if selection:
            item = self.password_tree.item(selection[0])
            site = item['values'][0]
            
            if messagebox.askyesno("Confirm Delete", f"Delete password for {site}?"):
                self.manager.delete_password(site)
                self.refresh_password_list()
                messagebox.showinfo("Deleted", "Password deleted successfully!")
    
    def update_strength_meter(self, event=None):
        password = self.password_entry.get()
        if not password:
            self.strength_progress['value'] = 0
            self.strength_text.configure(text="")
            return
        
        analysis = PasswordStrengthAnalyzer.analyze_password(password)
        strength_percent = (analysis['score'] / 6) * 100
        
        self.strength_progress['value'] = strength_percent
        self.strength_text.configure(text=analysis['strength'])
        
        # Color coding
        if analysis['score'] <= 2:
            color = 'red'
        elif analysis['score'] <= 4:
            color = 'orange'
        else:
            color = 'green'
        
        self.strength_text.configure(foreground=color)
    
    def generate_password_for_entry(self):
        password = PasswordGenerator.generate_password(
            length=12,
            include_uppercase=True,
            include_lowercase=True,
            include_numbers=True,
            include_symbols=True,
            exclude_ambiguous=True
        )
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.update_strength_meter()
    
    def save_password(self):
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        notes = self.notes_text.get('1.0', tk.END).strip()
        
        if not site or not username or not password:
            messagebox.showerror("Error", "Please fill in all required fields!")
            return
        
        if site in self.manager.passwords:
            if not messagebox.askyesno("Confirm", f"Password for {site} already exists. Overwrite?"):
                return
        
        self.manager.add_password(site, username, password, notes)
        messagebox.showinfo("Success", "Password saved successfully!")
        self.clear_form()
        self.refresh_password_list()
    
    def clear_form(self):
        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.notes_text.delete('1.0', tk.END)
        self.strength_progress['value'] = 0
        self.strength_text.configure(text="")
    
    def update_length_label(self, value):
        self.length_label.configure(text=str(int(float(value))))
    
    def generate_password(self):
        password = PasswordGenerator.generate_password(
            length=int(self.length_var.get()),
            include_uppercase=self.include_uppercase.get(),
            include_lowercase=self.include_lowercase.get(),
            include_numbers=self.include_numbers.get(),
            include_symbols=self.include_symbols.get(),
            exclude_ambiguous=self.exclude_ambiguous.get()
        )
        self.generated_password.set(password)
    
    def copy_to_clipboard(self):
        password = self.generated_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
    
    def toggle_password_visibility(self):
        # This would toggle between showing/hiding the password
        # For now, just shows a message
        messagebox.showinfo("Info", "Password visibility toggled!")
    
    def analyze_all_passwords(self):
        self.analysis_text.delete('1.0', tk.END)
        
        if not self.manager.passwords:
            self.analysis_text.insert(tk.END, "No passwords to analyze.\n")
            return
        
        self.analysis_text.insert(tk.END, "=== PASSWORD SECURITY ANALYSIS ===\n\n")
        
        weak_passwords = []
        duplicate_passwords = []
        old_passwords = []
        
        password_counts = {}
        
        for site, data in self.manager.passwords.items():
            password = data['password']
            analysis = PasswordStrengthAnalyzer.analyze_password(password)
            
            # Check for weak passwords
            if analysis['score'] <= 2:
                weak_passwords.append((site, analysis['strength']))
            
            # Check for duplicates
            if password in password_counts:
                password_counts[password].append(site)
            else:
                password_counts[password] = [site]
            
            # Check for old passwords (if created date available)
            created_str = data.get('created')
            if created_str:
                try:
                    created_date = datetime.fromisoformat(created_str)
                    if datetime.now() - created_date > timedelta(days=365):
                        old_passwords.append((site, created_str[:10]))
                except Exception:
                    pass

        # Report weak passwords
        if weak_passwords:
            self.analysis_text.insert(tk.END, "⚠️ Weak Passwords:\n")
            for site, strength in weak_passwords:
                self.analysis_text.insert(tk.END, f" - {site}: {strength}\n")
            self.analysis_text.insert(tk.END, "\n")
        else:
            self.analysis_text.insert(tk.END, "✅ No weak passwords found.\n\n")

        # Report duplicate passwords
        for pwd, sites in password_counts.items():
            if len(sites) > 1:
                duplicate_passwords.append(sites)
        if duplicate_passwords:
            self.analysis_text.insert(tk.END, "⚠️ Duplicate Passwords:\n")
            for sites in duplicate_passwords:
                self.analysis_text.insert(tk.END, f" - {' , '.join(sites)}\n")
            self.analysis_text.insert(tk.END, "\n")
        else:
            self.analysis_text.insert(tk.END, "✅ No duplicate passwords found.\n\n")

        # Report old passwords
        if old_passwords:
            self.analysis_text.insert(tk.END, "⚠️ Old Passwords (over 1 year):\n")
            for site, date in old_passwords:
                self.analysis_text.insert(tk.END, f" - {site}: Created {date}\n")
            self.analysis_text.insert(tk.END, "\n")
        else:
            self.analysis_text.insert(tk.END, "✅ No old passwords found.\n\n")

        self.analysis_text.insert(tk.END, "=== INDIVIDUAL PASSWORD ANALYSIS ===\n\n")
        for site, data in self.manager.passwords.items():
            password = data['password']
            analysis = PasswordStrengthAnalyzer.analyze_password(password)
            self.analysis_text.insert(tk.END, f"🔐 Site: {site}\n")
            self.analysis_text.insert(tk.END, f"Username: {data['username']}\n")
            self.analysis_text.insert(tk.END, f"Strength: {analysis['strength']}\n")
            if analysis['feedback']:
                self.analysis_text.insert(tk.END, "Feedback:\n")
                for feedback in analysis['feedback']:
                    self.analysis_text.insert(tk.END, f" - {feedback}\n")
            self.analysis_text.insert(tk.END, "-"*50 + "\n")

# ================= MAIN ==================
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

# this is best for personal data management and as passowrd analyzer .
