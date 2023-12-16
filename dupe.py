import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import hashlib
import os
import shutil
import mimetypes
import subprocess
from datetime import datetime
from PIL import Image, ImageTk
from send2trash import send2trash

def calculate_partial_md5(file_path, num_bytes=2):
    """Calculate a partial MD5 hash for a given file."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        data = f.read(num_bytes * 64)  # Read only a portion of the file
        md5.update(data)
    return md5.hexdigest()[:num_bytes]  # Return only the first few characters

def find_potential_duplicates(folder_path, progress_update_func):
    partial_hashes = {}
    potential_duplicates = []

    files_list = list(os.walk(folder_path))
    total_files = sum(len(files) for _, _, files in files_list)
    processed_files = 0

    # Define file extensions for each category
    IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']
    VIDEO_EXTENSIONS = ['.mp4', '.avi', '.mov', '.wmv', '.flv']
    AUDIO_EXTENSIONS = ['.mp3', '.wav', '.aac', '.flac', '.ogg']

    # Determine whether any file type filters are active
    filter_active = image_var.get() or video_var.get() or audio_var.get()

    # Initial scan with partial hash
    for dirpath, dirs, files in files_list:
        for filename in files:
            ext = os.path.splitext(filename)[1].lower() if filter_active else None

            # Determine if the file should be processed
            process_file = (
                (image_var.get() and ext in IMAGE_EXTENSIONS) or
                (video_var.get() and ext in VIDEO_EXTENSIONS) or
                (audio_var.get() and ext in AUDIO_EXTENSIONS) or
                not filter_active
            )

            if process_file:
                file_path = os.path.join(dirpath, filename)
                file_hash = calculate_partial_md5(file_path)
                if file_hash in partial_hashes:
                    partial_hashes[file_hash].append(file_path)
                else:
                    partial_hashes[file_hash] = [file_path]

                # Update progress
                processed_files += 1
                progress_update_func(processed_files, total_files, filename)

    # Identify groups with more than one file as potential duplicates
    for paths in partial_hashes.values():
        if len(paths) > 1:
            potential_duplicates.extend(paths)

    return potential_duplicates



def confirm_duplicates(file_paths, progress_update_func):
    full_hash_dict = {}
    confirmed_duplicates = {}

    processed_files = 0
    total_files = len(file_paths)

    # Full hash comparison for potential duplicates
    for file_path in file_paths:
        filename = os.path.basename(file_path)
        file_hash = calculate_md5(file_path)
        if file_hash in full_hash_dict:
            if file_hash not in confirmed_duplicates:
                confirmed_duplicates[file_hash] = [full_hash_dict[file_hash]]
            confirmed_duplicates[file_hash].append(file_path)
        else:
            full_hash_dict[file_hash] = file_path

        # Update progress
        processed_files += 1
        progress_update_func(processed_files, total_files, filename)

    return confirmed_duplicates
    
def get_file_info(file_path):
    try:
        # Get file size
        size = os.path.getsize(file_path)
        size_str = f"{size} bytes"

        # Get last modified date
        last_modified = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")

        # Get creation date
        creation_date = datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S")

        # Get file type
        type, _ = mimetypes.guess_type(file_path)
        if type is None:
            type = "Unknown"

        return {
            'size': size_str,
            'last_modified': last_modified,
            'type': type,
            'created': creation_date
        }
    except Exception as e:
        print(f"Error getting file info: {e}")
        return {
            'size': 'N/A',
            'last_modified': 'N/A',
            'type': 'N/A',
            'created': 'N/A'
        }

def is_image_file(file_path):
    # List of common image file extensions
    image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']
    # Get the file extension and check if it's in the list
    _, ext = os.path.splitext(file_path)
    return ext.lower() in image_extensions

def update_image_preview(file_path):
    if is_image_file(file_path):
        try:
            img = Image.open(file_path)
            img.thumbnail((350, 350))  # Resize the image to fit the preview area
            img = ImageTk.PhotoImage(img)
            image_canvas.create_image(0, 0, image=img, anchor='nw')  # Center the image
            image_canvas.image = img  # Keep a reference to avoid garbage collection
        except Exception as e:
            print(f"Error loading image: {e}")
            image_canvas.delete("all")  # Clear the canvas in case of an error
    else:
        # Clear the canvas if it's not an image
        image_canvas.delete("all")

def on_listbox_select(event):
    widget = event.widget
    index = int(widget.curselection()[0])
    value = widget.get(index).strip()
    if not (value.startswith("Group") or value.startswith("-" * 40)):
        update_image_preview(value)
        update_file_info(value)


def calculate_md5(file_path):
    """Calculate MD5 hash for a given file."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()

def find_duplicates(folder_path):
    # Get total number of files for progress calculation
    files_list = list(os.walk(folder_path))
    total_files = sum(len(files) for _, _, files in files_list)
    progress_var.set(0)
    progress_bar['maximum'] = 100  # Considering two stages

    # Stage 1: Find potential duplicates
    potential_duplicates = find_potential_duplicates(folder_path, update_progress_stage1)

    # Stage 2: Confirm actual duplicates
    confirmed_duplicates = confirm_duplicates(potential_duplicates, update_progress_stage2)

    # Formatting the confirmed duplicates for display
    duplicates_grouped = []
    for file_hash, files in confirmed_duplicates.items():
        # files[0] is the original file and files[1:] are the duplicates
        group = [files[0]] + files[1:]
        duplicates_grouped.append(group)

    # Update GUI after completion
    current_file_label.config(text="Done processing!")
    progress_bar['value'] = progress_bar['maximum']
    progress_label.config(text="100%")

    return duplicates_grouped

def update_progress_stage1(processed_count, total_files, filename):
    progress = (processed_count / (total_files * 2)) * 100  # Scale to 100 for the first half
    progress_var.set(progress)
    progress_label.config(text=f"{progress:.2f}%")
    current_file_label.config(text=f"Processing: {filename}")  # Show the current file being processed
    app_window.update_idletasks()

def update_progress_stage2(processed_count, total_files, filename):
    progress = 50 + (processed_count / (total_files * 2)) * 100  # Scale to 100 for the second half
    progress_var.set(progress)
    progress_label.config(text=f"{progress:.2f}%")
    current_file_label.config(text=f"Processing: {filename}")  # Update the label with the filename
    app_window.update_idletasks()

def delete_selected():
    selected_items = result_listbox.curselection()
    if not selected_items:
        messagebox.showinfo("No Selection", "No files selected for deletion.")
        return

    if messagebox.askyesno("Confirm Deletion", "Are you sure you want to move these files to the recycle bin?"):
        for index in selected_items[::-1]:  # Reverse the list to avoid index shifting after deletion
            file_path = result_listbox.get(index).strip()
            if file_path.startswith("Group") or file_path.startswith("-" * 40):
                continue  # Skip group headers and separators
            
            normalized_path = os.path.normpath(file_path)  # Normalize the path

            try:
                send2trash(normalized_path)
                result_listbox.delete(index)
            except Exception as e:
                messagebox.showerror("Error", f"Could not move file to recycle bin: {normalized_path}\n{e}")


def move_selected():
    selected_items = result_listbox.curselection()
    destination_folder = filedialog.askdirectory(title="Select Destination Folder")
    if destination_folder:
        for index in selected_items[::-1]:  # Reverse the list to avoid index shifting after moving
            file_path = result_listbox.get(index).strip()
            if file_path.startswith("Group") or file_path.startswith("-" * 40):
                continue  # Skip group headers and separators
            try:
                shutil.move(file_path, destination_folder)
                result_listbox.delete(index)
            except Exception as e:
                messagebox.showerror("Error", f"Could not move file: {file_path}\n{e}")

def browse_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        result_listbox.delete(0, tk.END)  # Clear existing entries in the listbox
        result_label.config(text="Searching for duplicates...")
        app_window.update_idletasks()  # Refresh the GUI to update the label text

        # Start the duplicate finding process
        duplicates_grouped = find_duplicates(folder_path)
        
        # Check if duplicates were found
        if duplicates_grouped:
            result_label.config(text="Duplicate files found:")
            for index, group in enumerate(duplicates_grouped):
                # Insert group header
                result_listbox.insert(tk.END, f"Group {index + 1}:")
                for file_path in group:
                    result_listbox.insert(tk.END, f"    {file_path}")  # Insert file path with indentation
                # Add a separator line between groups
                result_listbox.insert(tk.END, "-" * 40)
        else:
            result_label.config(text="No duplicates found.")
        delete_button.config(state=tk.NORMAL)
        move_button.config(state=tk.NORMAL)
        open_file_button.place(x=630, y=560, width=120, height=30)
        open_folder_button.place(x=760, y=560, width=120, height=30)
        app_window.update_idletasks()  # Refresh the GUI

def open_file():
    selected = result_listbox.curselection()
    if selected:
        file_path = result_listbox.get(selected[0]).strip()
        if os.path.isfile(file_path):
            # Open the file using the default application
            os.startfile(file_path)

def open_folder():
    selected = result_listbox.curselection()
    if selected:
        file_path = result_listbox.get(selected[0]).strip()
        if os.path.isfile(file_path):
            folder_path = os.path.dirname(file_path)
            # Open the folder containing the file
            os.startfile(folder_path)

def update_file_info(file_path):
    info = get_file_info(file_path)  # Retrieve file info
    # Format and display the information
    file_info_label.config(text=f"Size: {info['size']}\nLast Modified: {info['last_modified']}\nType: {info['type']}\nCreated: {info['created']}")

# Create the main window
# Rename 'root' to 'app_window' to avoid conflict with the 'root' directory variable in 'os.walk'
app_window = tk.Tk()
app_window.title("Duplicate File Finder")
app_window.geometry("1024x768")  # Initial size of the window
app_window.resizable(True, True)  # Allow window to be resizable
app_window.minsize(600,200)

# Create and configure widgets
frame = tk.Frame(app_window)
frame.pack(pady=10, padx=10, expand=True, fill="both")

browse_button = tk.Button(frame, text="Browse Folder", command=browse_folder)
result_label = tk.Label(frame, text="", anchor='w', justify='left')
result_listbox = tk.Listbox(frame, height=15, width=50, selectmode=tk.EXTENDED)

result_scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
horizontal_scrollbar = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
result_listbox.config(yscrollcommand=result_scrollbar.set, xscrollcommand=horizontal_scrollbar.set)
result_scrollbar.config(command=result_listbox.yview)
delete_button = tk.Button(frame, text="Delete Selected", command=delete_selected)
delete_button.config(state=tk.DISABLED)
move_button = tk.Button(frame, text="Move Selected", command=move_selected)
move_button.config(state=tk.DISABLED)
open_file_button = tk.Button(frame, text="Open File", command=open_file)
open_folder_button = tk.Button(frame, text="Open Folder", command=open_folder)
horizontal_scrollbar.config(command=result_listbox.xview)

# Add a Canvas for image preview
image_canvas = tk.Canvas(frame, width=350, height=350)

# Bind listbox select event
result_listbox.bind('<<ListboxSelect>>', on_listbox_select)

# Global variables to store the state of checkboxes
image_var = tk.BooleanVar()
video_var = tk.BooleanVar()
audio_var = tk.BooleanVar()

# Creating checkboxes
image_check = tk.Checkbutton(frame, text="Images", variable=image_var)
video_check = tk.Checkbutton(frame, text="Videos", variable=video_var)
audio_check = tk.Checkbutton(frame, text="Audio", variable=audio_var)

# Positioning checkboxes in the frame
image_check.place(x=400, y=0)
video_check.place(x=400, y=20)
audio_check.place(x=400, y=40)

# Progress bar and current file label
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(frame, variable=progress_var, length=300, mode='determinate')
current_file_label = tk.Label(frame, text="", anchor='w')
progress_label = tk.Label(frame, text="0%", anchor='e')  # Label to show percentage

# Layout using place

browse_button.place(x=10, y=10, width=120, height=30)
move_button.place(x=140, y=10, width=120, height=30)
delete_button.place(x=270, y=10, width=120, height=30)
result_label.place(x=10, y=45, width=400, height=15)
result_listbox.place(x=10, y=70, width=600, height=600)
result_scrollbar.place(x=610, y=70, width=20, height=600)
horizontal_scrollbar.place(x=10, y=670, width=600, height=20)
image_canvas.place(x=630, y=70, width=350, height=350)
progress_bar.place(x=10, y=700, width=580, height=20)
current_file_label.place(x=10, y=725, width=580, height=20)
progress_label.place(x=595, y=700, width=40, height=20)
file_info_label = tk.Label(frame, text="", anchor='w', justify='left')
file_info_label.place(x=630, y=430, width=350, height=100)

app_window.mainloop()
