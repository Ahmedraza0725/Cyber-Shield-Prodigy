import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import hashlib

class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption and Decryption Tool")
        self.root.geometry("600x450")
        self.root.resizable(True, True)
        
        self.original_image = None
        self.encrypted_image = None
        self.image_path = None
        self.current_state = "uploaded"  # uploaded, encrypted, decrypted

        # Create UI elements
        self.create_widgets()

    def create_widgets(self):
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Upload Button
        self.upload_button = tk.Button(main_frame, text="📁 Upload Image", command=self.upload_image,
                                      height=2, width=20, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.upload_button.pack(pady=10)

        # === Encryption Key Frame (Centered) ===
        key_frame = tk.Frame(main_frame)
        key_frame.pack(pady=10, fill=tk.X)

        self.key_label = tk.Label(key_frame, text="Encryption Key:", font=("Arial", 10))
        self.key_label.pack()

        key_input_frame = tk.Frame(key_frame)
        key_input_frame.pack(pady=5)

        self.key_entry = tk.Entry(key_input_frame, show='*', font=("Arial", 10), width=30)
        self.key_entry.pack(side=tk.LEFT, padx=(0, 5))

        self.toggle_key_button = tk.Button(key_input_frame, text="👁️", command=self.toggle_key_visibility,
                                          width=3, font=("Arial", 10))
        self.toggle_key_button.pack(side=tk.LEFT)

        # Button Frame
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=15)

        self.encrypt_button = tk.Button(button_frame, text="🔒 Encrypt", command=self.encrypt_image,
                                       height=2, width=12, bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
        self.encrypt_button.pack(side=tk.LEFT, padx=5)

        self.decrypt_button = tk.Button(button_frame, text="🔓 Decrypt", command=self.decrypt_image,
                                       height=2, width=12, bg="#FF9800", fg="white", font=("Arial", 10, "bold"))
        self.decrypt_button.pack(side=tk.LEFT, padx=5)

        self.save_button = tk.Button(button_frame, text="💾 Save", command=self.save_image,
                                    height=2, width=12, bg="#607D8B", fg="white", font=("Arial", 10, "bold"))
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.view_button = tk.Button(main_frame, text="👀 Click this button to view the uploaded image", 
                                    command=self.view_image, height=2, width=40, bg="#9C27B0", fg="white", 
                                    font=("Arial", 10, "bold"))
        self.view_button.pack(pady=15)

        self.status_label = tk.Label(main_frame, text="Status: No image uploaded", 
                                    font=("Arial", 9), fg="gray")
        self.status_label.pack(pady=5)

    def upload_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if self.image_path:
            try:
                self.original_image = Image.open(self.image_path).convert("RGB")
                self.encrypted_image = None
                self.current_state = "uploaded"
                messagebox.showinfo("Success", "Image uploaded successfully")
                self.view_button.config(text="👀 Click to view the uploaded image")
                self.status_label.config(
                    text=f"Status: Image uploaded - {self.original_image.size[0]}x{self.original_image.size[1]}"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open image: {str(e)}")

    def toggle_key_visibility(self):
        if self.key_entry.cget('show') == '*':
            self.key_entry.config(show='')
            self.toggle_key_button.config(text="🙈")
        else:
            self.key_entry.config(show='*')
            self.toggle_key_button.config(text="👁️")

    def encrypt_image(self):
        if self.original_image is None:
            messagebox.showerror("Error", "Please upload an image first.")
            return

        key = self.key_entry.get()
        if not key:
            messagebox.showerror("Error", "Please enter an encryption key.")
            return

        try:
            img_array = np.array(self.original_image, dtype=np.uint8)
            
            key_hash = hashlib.sha256(key.encode()).digest()
            key_array = np.frombuffer(key_hash * (img_array.size // len(key_hash) + 1), dtype=np.uint8)
            key_array = key_array[:img_array.size].reshape(img_array.shape)
            
            encrypted_array = img_array ^ key_array
            encrypted_array = np.rot90(encrypted_array, k=2)
            encrypted_array = (encrypted_array.astype(np.int16) + 50) % 256
            encrypted_array = encrypted_array.astype(np.uint8)

            self.encrypted_image = Image.fromarray(encrypted_array)
            self.current_state = "encrypted"
            
            messagebox.showinfo("Success", "Image encrypted successfully!\nThe image is now completely scrambled.")
            self.view_button.config(text="👀 Click to view the encrypted image")
            self.status_label.config(text="Status: Image encrypted - Completely scrambled")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_image(self):
        if self.encrypted_image is None:
            messagebox.showerror("Error", "Please encrypt an image first.")
            return

        key = self.key_entry.get()
        if not key:
            messagebox.showerror("Error", "Please enter the encryption key.")
            return

        try:
            encrypted_array = np.array(self.encrypted_image, dtype=np.uint8)
            
            key_hash = hashlib.sha256(key.encode()).digest()
            key_array = np.frombuffer(key_hash * (encrypted_array.size // len(key_hash) + 1), dtype=np.uint8)
            key_array = key_array[:encrypted_array.size].reshape(encrypted_array.shape)
            
            decrypted_array = (encrypted_array.astype(np.int16) - 50) % 256
            decrypted_array = np.rot90(decrypted_array, k=2)
            decrypted_array = decrypted_array.astype(np.uint8) ^ key_array

            self.original_image = Image.fromarray(decrypted_array)
            self.current_state = "decrypted"
            
            messagebox.showinfo("Success", "Image decrypted successfully!")
            self.view_button.config(text="👀 Click to view the decrypted image")
            self.status_label.config(text="Status: Image decrypted - Restored to original")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}\nMake sure you're using the correct key.")

    def save_image(self):
        if self.current_state == "encrypted" and self.encrypted_image is not None:
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg"), ("BMP files", "*.bmp")]
            )
            if save_path:
                try:
                    self.encrypted_image.save(save_path)
                    messagebox.showinfo("Success", f"Image saved successfully as:\n{save_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save image: {str(e)}")
        elif self.current_state == "decrypted" and self.original_image is not None:
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg"), ("BMP files", "*.bmp")]
            )
            if save_path:
                try:
                    self.original_image.save(save_path)
                    messagebox.showinfo("Success", f"Image saved successfully as:\n{save_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save image: {str(e)}")
        else:
            messagebox.showerror("Error", "No image to save.")

    def view_image(self):
        try:
            if self.current_state == "uploaded" and self.original_image:
                self.original_image.show()
            elif self.current_state == "encrypted" and self.encrypted_image:
                self.encrypted_image.show()
            elif self.current_state == "decrypted" and self.original_image:
                self.original_image.show()
            else:
                messagebox.showerror("Error", "No image to display.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to display image: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
