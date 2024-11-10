import ctypes
import os
import string
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from tkinter import simpledialog
from tkinter.simpledialog import askstring
import webbrowser
import winreg
import psutil
import platform

version = "2"
drive_vars = []
divider = "__________________________________________________________________________________________________________________________________________________________________________________________________"
#global setting_status
#setting_status = "Idle"

# Global declarations for widgets
root = None
notebook = None
user_list = None
entry_username = None
entry_password = None
network_tree = None
socket = None
entry_ping_ip = None
startup_listbox = None

def is_admin():
    """
    Check for admin privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """
    Request the script to ask for administrator privileges.
    """
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, os.path.abspath(__file__), None, 1
        )
        sys.exit(0)  # Exit the original process if re-launch is successful
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Failed to elevate privileges: {e}")

def create_tooltip(widget, text):
    """
    Create a tooltip for a given widget.
    """
    tooltip = tk.Toplevel(widget)
    tooltip.withdraw()
    tooltip.wm_overrideredirect(True)
    tooltip.wm_geometry("+0+0")
    tooltip_label = tk.Label(
        tooltip,
        text=text,
        justify='left',
        background='yellow',
        relief='solid',
        borderwidth=1,
        wraplength=360
    )
    tooltip_label.pack()

    def enter(event):
        x = widget.winfo_rootx() + 20
        y = widget.winfo_rooty() + 20
        tooltip.wm_geometry(f"+{x}+{y}")
        tooltip.deiconify()

    def leave(event):
        tooltip.withdraw()

    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)
    
def get_processor_name():
    # Try to get the processor name using 'wmic'
    try:
        processor_name = subprocess.check_output("wmic cpu get name").decode().split('\n')[1].strip()
        return processor_name
    except Exception as e:
        return f"Error retrieving processor info: {e}"

def get_ram_amount():
    # Get the total physical RAM
    ram = psutil.virtual_memory().total / (1024 ** 3)  # Convert bytes to GB
    return f"{ram:.2f} GB"

def get_gpu_name():
    # Try to get the GPU name using 'wmic' or other methods
    try:
        gpu_info = subprocess.check_output("wmic path win32_videocontroller get caption").decode().split('\n')[1].strip()
        return gpu_info
    except Exception as e:
        return f"Error retrieving GPU info: {e}"

def get_storage_info():
    # Get information about all drives
    partitions = psutil.disk_partitions()
    storage_info = []
    for partition in partitions:
        usage = psutil.disk_usage(partition.mountpoint)
        storage_info.append(f"{partition.device}: {usage.total / (1024 ** 3):.2f} GB")
    return "\n    ".join(storage_info)

def get_battery_health():
    # Get battery health percentage if on laptop
    battery = psutil.sensors_battery()
    if battery:
        return f"{battery.percent}%"
    else:
        return "Not a laptop or battery not detected"

def get_windows_version():
    # Get the version of Windows installed
    print(f"WINDOWS VERSION: {platform.version()}")
    return platform.version()

def get_activation_status():
    # Query the Windows registry for activation status (e.g. license key presence)
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        value = winreg.QueryValueEx(registry_key, "ProductId")[0]
        if value:
            return "Activated"
        else:
            return "Not Activated"
    except Exception as e:
        return "Error retrieving activation status"

# Collect system information
processor = get_processor_name()
ram = get_ram_amount()
gpu = get_gpu_name()
storage = get_storage_info()
battery_health = get_battery_health()
windows_version = get_windows_version()
activation_status = get_activation_status()



def set_regkey(hkey: winreg.HKEYType, subkey: string, newvalue: string, datatype: string, inverse: bool, silent: bool):
    global checkbox_variable
    try:
        key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE)
        if inverse:
            value = 0 if checkbox_variable.get() else 1
        else:
            value = 1 if checkbox_variable.get() else 0
        winreg.SetValueEx(key, newvalue, 0, datatype, value)
        winreg.CloseKey(key)
        if not silent:
            messagebox.showinfo("Porkspatch", "Registry value set successfully.")
    except Exception as e:
        if not silent:
            messagebox.showerror("Porkspatch", f"Error setting registry value: {e}")

def get_regkey(hkey: winreg.HKEYType, subkey: string):
    try:
        key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "PorkspatchBootAsSystem")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading LongPathsEnabled: {e}")
        return False
    
def create_regkey_checkbox(master, hkey: winreg.HKEYType, subkey: string, newvalue: string, datatype: string, inverse: bool, silent: bool, checkbox_title: string, tooltip: string):
    global regkey_var
    regkey_var = tk.IntVar(value=int(get_regkey(hkey, subkey)))
    regkey_checkbox = ttk.Checkbutton(master, text=checkbox_title, variable=regkey_var, command=set_regkey(hkey, subkey, newvalue, datatype, inverse, silent))
    regkey_checkbox.pack(padx=10, pady=1, anchor='w')
    create_tooltip(regkey_checkbox, tooltip)

def set_system_boot():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup", 0, winreg.KEY_SET_VALUE)
        value = 0 if boot_as_system_value.get() else 1
        winreg.SetValueEx(key, "CmdLine", 0, winreg.REG_SZ, "cmd.exe")
        winreg.SetValueEx(key, "SetupPhase", 0, winreg.REG_DWORD, value)
        winreg.SetValueEx(key, "SetupType", 0, winreg.REG_DWORD, value)
        winreg.SetValueEx(key, "SystemSetupInProgress", 0, winreg.REG_DWORD, value)
        winreg.SetValueEx(key, "PorkspatchBootAsSystem", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", "Registry values set successfully.")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting registry values: {e}")

def get_system_boot():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "PorkspatchBootAsSystem")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading LongPathsEnabled: {e}")
        return False

def set_long_paths_enabled():
    # Set or unset LongPathsEnabled registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem", 0, winreg.KEY_SET_VALUE)
        value = 1 if long_paths_var.get() else 0
        winreg.SetValueEx(key, "LongPathsEnabled", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Unlimited Max Paths set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Unlimited Max Paths: {e}")

def get_long_paths_enabled():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading LongPathsEnabled: {e}")
        return False

def set_verbose_login():
    # Set or unset VerboseLogon registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        value = 1 if verbose_login.get() else 0
        winreg.SetValueEx(key, "VerboseStatus", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Verbose Logon set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Verbose Logon: {e}")

def get_verbose_login():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "VerboseStatus")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading VerboseStatus: {e}")
        return False

def set_low_disk_space_notifications():
    # Set or Unset NoLowDiskSpaceChecks registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        value = 1 if low_disk_notif.get() else 0
        winreg.SetValueEx(key, "NoLowDiskSpaceChecks", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Low Disk Space Notifications set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Low Disk Space Notifications: {e}")

def get_low_disk_space_notifications():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "NoLowDiskSpaceChecks")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading NoLowDiskSpaceChecks: {e}")
        return False

def set_disable_defender():
    # Set or Unset DisableAntiSpyware registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_defender.get() else 0
        winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable Windows Defender set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable Windows Defender: {e}")

def get_disable_defender():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "DisableAntiSpyware")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading DisableAntiSpyware: {e}")
        return False

def set_disable_cmd():
    # Set or Unset DisableCMD registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_cmd_value.get() else 0
        winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable Command Prompt set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable Command Prompt: {e}")

def get_disable_cmd():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "DisableCMD")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading DisableCMD: {e}")
        return False

def set_disable_ipv6():
    # Set or Unset DisabledComponents registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_ipv6_value.get() else 0
        winreg.SetValueEx(key, "DisabledComponents", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable IPv6 set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable IPv6: {e}")

def get_disable_ipv6():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "DisabledComponents")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading DisabledComponents: {e}")
        return False
    
def set_enable_lgco():
    # Set or Unset DisabledComponents registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot\Options", 0, winreg.KEY_SET_VALUE)
        value = 1 if enable_last_good_configuration_option_value.get() else 0
        winreg.SetValueEx(key, "UseLastKnownGood", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Enable Last Good Configuration set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Enable Last Good Configuration: {e}")

def get_enable_lgco():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot\Options", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "UseLastKnownGood")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading UseLastKnownGood: {e}")
        return False
    
def set_disable_windows_store():
    # Set or Unset RemoveWindowsStore registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\WindowsStore", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_windows_store_value.get() else 0
        winreg.SetValueEx(key, "RemoveWindowsStore", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Remove Windows Store set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Remove Windows Store: {e}")

def get_disable_windows_store():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\WindowsStore", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "RemoveWindowsStore")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading RemoveWindowsStore: {e}")
        return False
    
def set_disable_auto_updates():
    # Set or Unset NoAutoUpdate registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", 0, winreg.KEY_SET_VALUE)
        value = 1 if disable_no_auto_update_value.get() else 0
        winreg.SetValueEx(key, "NoAutoUpdate", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable Windows Auto Update set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable Windows Auto Update: {e}")

def get_disable_auto_updates():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "NoAutoUpdate")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading NoAutoUpdate: {e}")
        return False

def set_disable_activate_windows_watermark():
    # Set or Unset DisableActivateWindowsWatermark registry key based on the checkbox variable.
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, winreg.KEY_SET_VALUE)
        value = 0 if disable_activate_windows_watermark_value.get() else 1
        winreg.SetValueEx(key, "DisableActivateWindowsWatermark", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        messagebox.showinfo("Porkspatch", f"Disable Activate Windows Watermark set to {value}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting Disable Windows Auto Update: {e}")

def get_disable_activate_windows_watermark():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "PaintDesktopVersion")
        winreg.CloseKey(key)
        return bool(value)
    except FileNotFoundError:
        return False
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return False
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading DisableActivateWindowsWatermark: {e}")
        return False

def open_twitter():
    webbrowser.open_new("https://twitter.com/PorkyLIVE_")

def get_hidden_drives():
    """
    Get the current NoDrives value from the registry and return a bitmask of hidden drives.
    """
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    try:
        # Open registry key for reading
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        no_drives_value, _ = winreg.QueryValueEx(key, "NoDrives")
        winreg.CloseKey(key)
        return no_drives_value
    except FileNotFoundError:
        # If the key or value does not exist, assume no drives are hidden
        return 0
    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
        return 0
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error reading NoDrives: {e}")
        return 0

def set_hidden_drives():
    """
    Create the registry key if it doesn't exist and set the NoDrives value.
    """
    try:
        # Path to the registry key
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        
        # Open or create the registry key
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        # Calculate the NoDrives value
        no_drives_value = 0
        for i, drive_var in enumerate(drive_vars):
            if drive_var.get() == 1:
                no_drives_value |= (1 << i)

        # Set the NoDrives value
        winreg.SetValueEx(key, "NoDrives", 0, winreg.REG_DWORD, no_drives_value)
        
        winreg.CloseKey(key)
        
        # Inform the user
        #messagebox.showinfo("Porkspatch", f"NoDrives set to {no_drives_value}. Please restart Explorer.")
        restartexplorernow = messagebox.askyesno("Porkspatch", f"NoDrives set to {no_drives_value}. Do you want to restart the Explorer now?")
        if restartexplorernow == True:
            restart_explorer()

    except PermissionError:
        messagebox.showerror("Porkspatch", "Permission denied. Please run as administrator.")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error setting NoDrives: {e}")

def load_path_variable():
    """
    Load the PATH environment variable and display it in the Listbox.
    """
    global path_listbox
    path_listbox.delete(0, tk.END)  # Clear the listbox
    path = os.environ.get("PATH", "")
    if path:
        paths = path.split(os.pathsep)
        for p in paths:
            path_listbox.insert(tk.END, p)

def save_path_variable():
    """
    Save the updated PATH environment variable.
    """
    global path_listbox
    new_path_list = path_listbox.get(0, tk.END)
    new_path = os.pathsep.join(new_path_list).strip()
    try:
        # Save to environment variable
        os.environ["PATH"] = new_path

        # Optionally save to registry
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Session Manager\Environment", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)

        messagebox.showinfo("Porkspatch", "PATH variable updated successfully.")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error updating PATH variable: {e}")

def browse_path():
    global path_entry
    directory = filedialog.askdirectory()
    if directory:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, directory)


def add_path():
    """
    Add a new path to the PATH environment variable.
    """
    global path_entry, path_listbox
    new_path = path_entry.get().strip()
    if new_path:
        if new_path not in path_listbox.get(0, tk.END):
            path_listbox.insert(tk.END, new_path)
            path_entry.delete(0, tk.END)  # Clear the entry box
        else:
            messagebox.showinfo("Porkspatch", "Path already exists.")
    else:
        messagebox.showinfo("Porkspatch", "Please enter a valid path.")

def remove_path():
    """
    Remove the selected path from the PATH environment variable.
    """
    global path_listbox
    try:
        selected_index = path_listbox.curselection()
        if selected_index:
            path_listbox.delete(selected_index)
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error removing path: {e}")

def open_selected_path():
    """
    Open the selected path in the PATH environment variable using Windows File Explorer.
    """
    global path_listbox
    try:
        selected_index = path_listbox.curselection()
        if selected_index:
            selected_path = path_listbox.get(selected_index)
            if os.path.exists(selected_path):
                subprocess.Popen(f'explorer "{selected_path}"')
            else:
                messagebox.showerror("Porkspatch", f"The path does not exist:\n{selected_path}")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error opening path: {e}")

def restart_explorer():
    """
    Restart Windows Explorer.
    """
    try:
        os.system("taskkill /f /im explorer.exe")
        os.system("start explorer.exe")
    except Exception as e:
        messagebox.showerror("Porkspatch", f"Error restarting Explorer: {e}")

def system_cmd():
    try:
        subprocess.run(f'runas /user:{os.environ.get("computername")}\\SYSTEM {os.environ.get("windir")}\system32\cmd.exe', shell=True)
    except Exception as e:
        messagebox.showerror("Porkspatch", e)

def initialize_checkboxes(no_drives_value):
    """
    Initialize the checkboxes based on the NoDrives value.
    """
    for i in range(26):
        if no_drives_value & (1 << i):
            drive_vars[i].set(1)

def add_context_menu():
    name = entry_name.get()
    command = entry_command.get()
    description = entry_desc.get()
    if not name or not command or not description:
        messagebox.showwarning("Input Error", "Name and Command are required.")
        return

    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}")
        winreg.SetValueEx(key, '', 0, winreg.REG_SZ, description)
        cmdkey = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}\\command")
        winreg.SetValueEx(cmdkey, '', 0, winreg.REG_SZ, command)
        messagebox.showinfo("Success", f"Added context menu item '{name}'.")
        update_context_menu_list()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add context menu item: {e}")

def remove_context_menu():
    name = entry_name.get()
    if not name:
        messagebox.showwarning("Input Error", "Name is required.")
        return

    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}\\command")
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}")
        messagebox.showinfo("Success", f"Removed context menu item '{name}'.")
        update_context_menu_list()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to remove context menu item: {e}")

def update_context_menu_list():
    listbox_context_menu.delete(0, tk.END)
    try:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "*\shell")
        i = 0
        while True:
            name = winreg.EnumKey(key, i)
            try:
                cmdtest = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{name}\\command")
                if cmdtest:
                    listbox_context_menu.insert(tk.END, name)
            except Exception:
                pass
            i += 1
    except OSError:
        pass
    except Exception as e:
        messagebox.showerror("Porkspatch", e)

def load_context_menu_details(event):
    selected_item = listbox_context_menu.get(listbox_context_menu.curselection())
    try:
        desckey = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{selected_item}")
        description, _ = winreg.QueryValueEx(desckey, '')
        cmdkey = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"*\shell\\{selected_item}\\command")
        command, _ = winreg.QueryValueEx(cmdkey, '')
        entry_name.delete(0, tk.END)
        entry_name.insert(0, selected_item)
        entry_desc.delete(0, tk.END)
        entry_desc.insert(0, description)
        entry_command.delete(0, tk.END)
        entry_command.insert(0, command)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load context menu details: {e}")

def browse_new_cmd():
    global browse_result_cmd
    command = filedialog.askopenfilename()
    if command:
        entry_command.delete(0, tk.END)
        entry_command.insert(0, command)

# Function to retrieve Windows user accounts
def load_user_accounts():
    try:
        # Use PowerShell to get a more immediate update
        result = subprocess.run(["powershell", "-Command", "Get-WmiObject -Class Win32_UserAccount | Select-Object Name"], capture_output=True, text=True, shell=True)
        users = result.stdout.splitlines()
        
        # Clear the list in the Treeview before loading new data
        for item in user_list.get_children():
            user_list.delete(item)
        
        # Populate the Treeview with usernames
        for user in users:
            username = user.strip()
            if username:  # Filter out empty lines
                user_list.insert("", "end", values=(username,))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load user accounts: {e}")

# Function to handle selection in the user list
def on_user_select(event):
    selected_item = user_list.selection()
    if not selected_item:
        return
    
    # Get the selected username
    username = user_list.item(selected_item, "values")[0]
    
    # Update the username field and clear the password field
    entry_username.delete(0, tk.END)
    entry_username.insert(0, username)
    entry_password.delete(0, tk.END)  # Clear password field

# Function to add a new Windows user account
def add_user_account():
    username = entry_username.get().strip()
    password = entry_password.get().strip()
    
    if not username or not password:
        messagebox.showwarning("Input Error", "Username and password are required.")
        return
    
    try:
        subprocess.run(["net", "user", username, password, "/add"], check=True, shell=True)
        messagebox.showinfo("Success", f"User '{username}' added successfully.")
        load_user_accounts()  # Refresh the user list
        entry_username.delete(0, tk.END)
        entry_password.delete(0, tk.END)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to add user '{username}': {e}")

# Function to delete a selected Windows user account
def delete_user_account():
    selected_item = user_list.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "Please select a user to delete.")
        return

    username = user_list.item(selected_item, "values")[0]
    confirm = messagebox.askyesno("Delete User", f"Are you sure you want to delete the user '{username}'?")
    
    if confirm:
        try:
            subprocess.run(["net", "user", username, "/delete"], check=True, shell=True)
            messagebox.showinfo("Success", f"User '{username}' deleted successfully.")
            load_user_accounts()  # Reload the user accounts list
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to delete user '{username}': {e}")

# Function to update the password of the selected user
def update_user_password():
    selected_item = user_list.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "Please select a user to update.")
        return
    
    username = user_list.item(selected_item, "values")[0]
    new_password = entry_password.get().strip()
    
    if not new_password:
        messagebox.showwarning("Input Error", "Password is required to update.")
        return

    try:
        subprocess.run(["net", "user", username, new_password], check=True, shell=True)
        messagebox.showinfo("Success", f"Password for '{username}' updated successfully.")
        entry_password.delete(0, tk.END)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to update password for '{username}': {e}")

# Function to retrieve network interfaces and display their details
# Function to retrieve network interfaces and display their details
def load_network_interfaces():
    try:
        # Clear the treeview before reloading data
        for item in network_tree.get_children():
            network_tree.delete(item)
        
        # Use 'wmic' to get network adapter details
        result = subprocess.run(["wmic", "nic", "get", "NetConnectionID,Name,MACAddress,Speed"], 
                                capture_output=True, text=True, shell=True)
        lines = result.stdout.splitlines()[1:]  # Ignore header

        for line in lines:
            details = line.split()
            if len(details) < 4:
                continue  # Skip lines that don't contain enough info
            
            # Extract relevant information
            display_name = " ".join(details[:-3])
            internal_name = details[-3]
            mac_address = details[-2]
            speed = details[-1]

            # If the first 18 characters of the display name have at least 5 colons, treat it as the MAC address
            if display_name[:18].count(":") >= 5:
                mac_address = display_name[:17]  # Extract the MAC address
                display_name = display_name[18:]  # Update display name without the MAC address part

            # Convert speed to bits through yottabits (b, Kb, Mb, Gb, Tb, Pb, Eb, Zb, Yb)
            if speed.isdigit():
                speed = int(speed)  # Speed is in bits
                units = ["b", "Kb", "Mb", "Gb", "Tb", "Pb", "Eb", "Zb", "Yb"]
                index = 0
                while speed >= 1000 and index < len(units) - 1:
                    speed /= 1000.0
                    index += 1
                speed = f"{speed:.2f} {units[index]}"
            else:
                speed = "N/A"

            # Insert network adapter details into the treeview
            network_tree.insert("", "end", values=(display_name, internal_name, mac_address, speed))

    except Exception as e:
        messagebox.showerror("Error", f"Failed to load network interfaces: {e}")

# Function to enable a selected network adapter
def enable_network_interface():
    selected_item = network_tree.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "Please select a network interface to enable.")
        return

    internal_name = network_tree.item(selected_item, "values")[1]
    try:
        subprocess.run(["wmic", "path", "win32_networkadapter", "where", f"NetConnectionID='{internal_name}'", "call", "enable"], check=True, shell=True)
        messagebox.showinfo("Success", f"Network interface '{internal_name}' enabled successfully.")
        load_network_interfaces()
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to enable network interface '{internal_name}': {e}")

# Function to disable a selected network adapter
def disable_network_interface():
    selected_item = network_tree.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "Please select a network interface to disable.")
        return

    internal_name = network_tree.item(selected_item, "values")[1]
    try:
        subprocess.run(["wmic", "path", "win32_networkadapter", "where", f"NetConnectionID='{internal_name}'", "call", "disable"], check=True, shell=True)
        messagebox.showinfo("Success", f"Network interface '{internal_name}' disabled successfully.")
        load_network_interfaces()
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to disable network interface '{internal_name}': {e}")

# Function to ping a specified IP address
def ping_ip():
    ip_address = entry_ping_ip.get()
    if not ip_address:
        messagebox.showwarning("Input Error", "Please enter an IP address to ping.")
        return

    try:
        result = subprocess.run(["ping", "-n", "1", ip_address], capture_output=True, text=True)
        if "Reply from" in result.stdout:
            messagebox.showinfo("Ping Result", f"Successfully reached {ip_address}.")
        else:
            messagebox.showinfo("Ping Result", f"Failed to reach {ip_address}.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to ping IP address '{ip_address}': {e}")

# Function to open Command Prompt as Administrator (if the program already has elevated privileges)
def open_admin_cmd():
    try:
        if platform == "win32":
            # Command to open the Command Prompt with elevated privileges (admin rights)
            subprocess.Popen("cmd.exe", shell=True)
    except Exception as e:
        print(f"Error: {e}")

# Function to handle Shift + F10 key press
def on_shift_f10(event):
    open_admin_cmd()
    
def list_startup_programs():
    startup_programs = []
    
    try:
        # Attempt to access both registry keys depending on system architecture
        reg_key_paths = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",  # For 32-bit programs
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",  # For 32-bit programs on 64-bit OS
        ]
        
        # Check if the current user has access to HKLM (run as admin)
        for path in reg_key_paths:
            try:
                # Try accessing the registry key
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
                num_values = winreg.QueryInfoKey(reg_key)[1]  # Get the number of values under the key
                print(f"Found {num_values} entries in the registry key: {path}")
                
                # Loop through and fetch all values
                for i in range(num_values):
                    program_name, program_path, _ = winreg.EnumValue(reg_key, i)
                    print(f"Name: {program_name}, Path: {program_path}")
                    startup_programs.append((program_name, program_path))
                
                winreg.CloseKey(reg_key)
            except Exception as e:
                print(f"Failed to open registry key at {path}: {e}")
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to retrieve startup programs: {e}")
    
    return startup_programs

def add_program_to_startup():
    # Open file dialog to select an executable
    program_path = filedialog.askopenfilename(
        title="Select Program Executable",
        filetypes=[("Executable Files", "*.exe")]
    )
    
    if program_path:
        # Normalize the path to ensure all slashes are backslashes
        program_path = program_path.replace('/', '\\')
        
        # Ask for the program name (can be the filename or custom name)
        program_name = simpledialog.askstring("Program Name", "Enter the name of the program:")
        
        if program_name:
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
                winreg.SetValueEx(reg_key, program_name, 0, winreg.REG_SZ, program_path)
                winreg.CloseKey(reg_key)
                messagebox.showinfo("Success", "Program added to startup.")
                refresh_startup_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add program: {e}")

def remove_program_from_startup():
    selected_program = startup_listbox.curselection()
    if selected_program:
        program_name = startup_listbox.get(selected_program)
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
            winreg.DeleteValue(reg_key, program_name)
            winreg.CloseKey(reg_key)
            messagebox.showinfo("Success", f"{program_name} has been removed from startup.")
            refresh_startup_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove program: {e}")
    else:
        messagebox.showwarning("No Selection", "Please select a program to remove.")

def enable_program():
    selected_program = startup_listbox.curselection()
    if selected_program:
        program_name = startup_listbox.get(selected_program)
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
            _, program_path, _ = winreg.EnumValue(reg_key, selected_program[0])
            winreg.SetValueEx(reg_key, program_name, 0, winreg.REG_SZ, program_path)
            winreg.CloseKey(reg_key)
            messagebox.showinfo("Success", f"{program_name} has been enabled.")
            refresh_startup_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to enable program: {e}")
    else:
        messagebox.showwarning("No Selection", "Please select a program to enable.")

def disable_program():
    selected_program = startup_listbox.curselection()
    if selected_program:
        program_name = startup_listbox.get(selected_program)
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
            winreg.DeleteValue(reg_key, program_name)  # Removing will effectively disable it.
            winreg.CloseKey(reg_key)
            messagebox.showinfo("Success", f"{program_name} has been disabled.")
            refresh_startup_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to disable program: {e}")
    else:
        messagebox.showwarning("No Selection", "Please select a program to disable.")

def refresh_startup_list():
    startup_listbox.delete(0, tk.END)
    
    # Fetching the programs and printing them for debugging
    programs = list_startup_programs()
    print("Inserting the following programs into the Listbox:")
    
    for program in programs:
        print(f"Inserting program: {program[0]}")
        startup_listbox.insert(tk.END, program[0])










def main():
    try:
        ### INITIAL STARTUP ###
        init_setup_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(init_setup_key, "SystemSetupInProgress", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(init_setup_key)
        
        ### WINDOW CONFIGURATION ###
        window = tk.Tk()
        window.title("Porkspatch")
        window.geometry("1024x640")
        # window.geometry("1920x1080")
        window.configure(bg="pink")
        window.resizable(False, False)

        # Set window icon (if it exists)
        try:
            window.iconbitmap("porkspatch.ico")
        except Exception as e_icon:
            print(f"[ERR] {e_icon}")

        ### CONTEXT ###
        title_label = tk.Label(
            window,
            text="Welcome to Porkspatch!",
            font=("Comic Sans", 24),
            pady=20,
            background="pink"
        )
        title_label.pack(anchor="n")

        notebook = ttk.Notebook(window)
        notebook.pack(expand=True, fill="both")

        welcome_tab = ttk.Frame(notebook)
        global_tab = ttk.Frame(notebook)
        boot_tab = ttk.Frame(notebook)
        path_tab = ttk.Frame(notebook)
        drives_tab = ttk.Frame(notebook)
        context_menu_tab = ttk.Frame(notebook)
        about_tab = ttk.Frame(notebook)

        ## WELCOME TAB ##
        notebook.add(welcome_tab, text="Welcome")
        story_text = """
        Once upon a time in the land of Porkspatch, there lived a brave knight named Sir Bacon. 
        Sir Bacon was known far and wide for his courage and love for crispy adventures.

        One sunny morning, Sir Bacon received a message from the king, summoning him to the castle. 
        The king spoke of a mysterious dragon that had been terrorizing the kingdom, 
        and only Sir Bacon could save the day.

        With his trusty sword and shield in hand, Sir Bacon set off on his quest to find the dragon's lair...

        — ChatGPT
        """
        story_text_widget = tk.Label(welcome_tab, text=story_text, font=("Arial", 12, "italic"), pady=20, wraplength=600)
        story_text_widget.pack(expand=False, fill='x')

        if is_admin():
            admin_checker_text = "You have administrator privileges! :)"
        else:
            admin_checker_text = "No administrator privileges... :("

        admin_checker = tk.Label(welcome_tab, text=admin_checker_text, font=("Arial", 16))
        admin_checker.pack(expand=False, fill='y', anchor='s')

        version_label = tk.Label(welcome_tab, text=f"Version: {version}", font=("Arial", 8), foreground='gray')
        version_label.pack(expand=False,anchor='s')
        create_tooltip(version_label, f"""Username: {os.environ.get("username")}
User Directory: {os.environ.get("userprofile")}
AppData: {os.environ.get("appdata")}
LocalAppData: {os.environ.get("localappdata")}
Temp: {os.environ.get("temp")}
OneDrive: {os.environ.get("onedrive")}

Computer: {os.environ.get("computername")}
Operating System: {windows_version}
Windows Directory: {os.environ.get("windir")}
System Drive: {os.environ.get("systemdrive")}
System Root: {os.environ.get("systemroot")}

Processor: {processor}
RAM: {ram}
GPU: {gpu}
Storage:\n    {storage}
Battery Health: {battery_health}
Activation Status: {activation_status}

PATH Extensions: {os.environ.get("pathext")}
""")

        ## GLOBAL SETTINGS TAB ##
        notebook.add(global_tab, text="Global Settings")

        file_system_frame = ttk.LabelFrame(global_tab, text="File System")
        file_system_frame.grid(row=1, column=1, sticky='n')

        security_frame = ttk.LabelFrame(global_tab, text="Security")
        security_frame.grid(row=1, column=2, sticky='n')

        login_frame = ttk.LabelFrame(global_tab, text="Login & Booting")
        login_frame.grid(row=1, column=3, sticky='n')

        networking_frame = ttk.LabelFrame(global_tab, text="Networking")
        networking_frame.grid(row=2, column=1, sticky='n')

        windows_frame = ttk.LabelFrame(global_tab, text="Windows")
        windows_frame.grid(row=2, column=2, sticky='n')

        visual_frame = ttk.LabelFrame(global_tab, text="Visual")
        visual_frame.grid(row=3, column=2, sticky='n')

        global long_paths_var
        long_paths_var = tk.IntVar(value=int(get_long_paths_enabled()))
        long_paths_checkbox = ttk.Checkbutton(file_system_frame, text="Unlimited Max Paths", variable=long_paths_var, command=set_long_paths_enabled)
        long_paths_checkbox.pack(padx=10, pady=1, anchor='w')
        create_tooltip(long_paths_checkbox, "This will remove the 260 character limit for file paths.")

        global verbose_login
        verbose_login = tk.IntVar(value=int(get_verbose_login()))
        verbose_login_checkbox = ttk.Checkbutton(login_frame, text="Verbose Login", variable=verbose_login, command=set_verbose_login)
        verbose_login_checkbox.pack(padx=10, pady=1, anchor='w')
        create_tooltip(verbose_login_checkbox, "This will show additional information during logging in and out, starting up Windows, and shutting down, instead of the standard messages like 'Welcome!' and 'Shutting down...'.")

        global low_disk_notif
        low_disk_notif = tk.IntVar(value=int(get_low_disk_space_notifications()))
        low_disk_checkbox = ttk.Checkbutton(file_system_frame, text="Disable Low Disk Space Notifications", variable=low_disk_notif, command=set_low_disk_space_notifications)
        low_disk_checkbox.pack(padx=10, pady=1, anchor='w')
        create_tooltip(low_disk_checkbox, "This will disable the notifications regarding low storage space.")

        global disable_defender
        disable_defender_value = tk.IntVar(value=int(get_disable_defender()))
        disable_defender = ttk.Checkbutton(security_frame, text="Disable Windows Defender", variable=disable_defender_value, command=set_disable_defender)
        disable_defender.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_defender, """This will disable Windows Defender. 
        > WARNING: This will put your computer at risk if no other AntiVirus is running!""")

        global disable_cmd_value
        disable_cmd_value = tk.IntVar(value=int(get_disable_cmd()))
        disable_cmd = ttk.Checkbutton(security_frame, text="Disable Command Prompt", variable=disable_cmd_value, command=set_disable_cmd)
        disable_cmd.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_cmd, """This will disable the Command Prompt. You can still open the Command Prompt, but will no longer allow user input.
        > NOTE: You might need to restart your computer for this setting to take effect.""")

        global disable_ipv6_value
        disable_ipv6_value = tk.IntVar(value=int(get_disable_ipv6()))
        disable_ipv6 = ttk.Checkbutton(networking_frame, text="Disable IPv6 Protocol", variable=disable_ipv6_value, command=set_disable_ipv6)
        disable_ipv6.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_ipv6, """This will disable the IPv6 Network Protocol.
        > NOTE: You might need to restart your computer for this setting to take effect.""")

        global enable_last_good_configuration_option_value
        enable_last_good_configuration_option_value = tk.IntVar(value=int(get_enable_lgco()))
        enable_last_good_configuration_option = ttk.Checkbutton(login_frame, text="Enable Last Good Configuration Option", variable=enable_last_good_configuration_option_value, command=set_enable_lgco)
        enable_last_good_configuration_option.pack(padx=10, pady=1, anchor='w')
        create_tooltip(enable_last_good_configuration_option, """This will enable the 'Last Known Good Configuration' option in the boot menu.""")

        global disable_windows_store_value
        disable_windows_store_value = tk.IntVar(value=int(get_disable_windows_store()))
        disable_windows_store = ttk.Checkbutton(windows_frame, text="Disable Windows Store", variable=disable_windows_store_value, command=set_disable_windows_store)
        disable_windows_store.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_windows_store, """This will disable the Windows Store.""")

        global disable_no_auto_update_value
        disable_no_auto_update_value = tk.IntVar(value=int(get_disable_auto_updates()))
        disable_no_auto_update = ttk.Checkbutton(windows_frame, text="Disable Automatic Updates", variable=disable_no_auto_update_value, command=set_disable_auto_updates)
        disable_no_auto_update.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_no_auto_update, """This will disable the automatic downloading and installing of Windows Updates.
        > WARNING: This obviously creates a security risk if Windows Updates are ignored altogether.""")

        global disable_activate_windows_watermark_value
        disable_activate_windows_watermark_value = tk.IntVar(value=int(get_disable_activate_windows_watermark()))
        disable_activate_windows_watermark = ttk.Checkbutton(visual_frame, text="Disable Activate Windows Watermark", variable=disable_activate_windows_watermark_value, command=set_disable_activate_windows_watermark)
        disable_activate_windows_watermark.pack(padx=10, pady=1, anchor='w')
        create_tooltip(disable_activate_windows_watermark, """This will remove the 'Activate Windows' watermark if disabled, and will display it when enabled.""")

#        setting_status_bar_value = tk.StringVar(value=setting_status)
#        setting_status_bar = tk.Label(global_tab, textvariable=setting_status_bar_value)
#        setting_status_bar.grid(row=10,column=1,columnspan=3,sticky='nsew')
        
        ## BOOT SETTINGS TAB ##
        #notebook.add(boot_tab, text="Boot")
        
        global boot_as_system_value
        boot_as_system_value = tk.IntVar(value=int(get_system_boot()))
        boot_as_system_button = ttk.Checkbutton(boot_tab, text="Boot as SYSTEM", command=set_system_boot)
        boot_as_system_button.pack(pady=10)
        create_tooltip(boot_as_system_button, """This will configure Windows to start a command prompt with SYSTEM privileges on next boot.
        > WARNING: Porkspatch currently has no way to disable this setting once this setting is actively in use. Only use if you know how the Windows Registry Editor works, and how to disable the effects of this setting.
        > BUG: Porkspatch no longer opens when this setting is used.""")

        ## PATH EDITOR TAB ##
        notebook.add(path_tab, text="PATH Inspector")
        path_frame = ttk.Frame(path_tab)
        path_frame.pack(fill="both", expand=True, padx=20, pady=10)

        global path_listbox, path_entry
        path_listbox = tk.Listbox(path_frame, selectmode=tk.SINGLE, height=10)
        path_listbox.pack(fill="both", expand=True, pady=5)

        path_buttons_frame = ttk.Frame(path_frame)
        path_buttons_frame.pack(fill=tk.X, pady=5)

        path_save_button = ttk.Button(path_buttons_frame, text="Save PATH", command=save_path_variable)
        path_save_button.pack(side=tk.LEFT, padx=5)

        path_load_button = ttk.Button(path_buttons_frame, text="Load PATH", command=load_path_variable)
        path_load_button.pack(side=tk.LEFT, padx=5)

        path_remove_button = ttk.Button(path_buttons_frame, text="Remove Selected", command=remove_path)
        path_remove_button.pack(side=tk.LEFT, padx=5)

        path_open_button = ttk.Button(path_buttons_frame, text="Open Selected Path", command=open_selected_path)
        path_open_button.pack(side=tk.LEFT, padx=5)

        path_entry_frame = ttk.Frame(path_frame)
        path_entry_frame.pack(fill=tk.X, pady=5)

        path_entry = tk.Entry(path_entry_frame)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        path_browse = ttk.Button(path_entry_frame, text="Browse...", command=browse_path)
        path_browse.pack(side=tk.LEFT, padx=5)

        path_add_button = ttk.Button(path_entry_frame, text="Add Path", command=add_path)
        path_add_button.pack(side=tk.LEFT, padx=5)

        load_path_variable()

        ## CONTEXT MENU TAB ##
        notebook.add(context_menu_tab, text="Context Menu")

        # Name and Command labels and entries
        global reg
        
        global entry_name
        lbl_name = ttk.Label(context_menu_tab, text="Name:")
        lbl_name.grid(row=0, column=0, padx=10, pady=5, sticky='w')
        entry_name = ttk.Entry(context_menu_tab)
        entry_name.grid(row=0, column=1, padx=10, pady=5, sticky='ew')
        create_tooltip(entry_name, "The internalized name for this Context Menu item. This name will only show up in the list below.")

        global entry_desc
        lbl_desc = ttk.Label(context_menu_tab, text="Description:")
        lbl_desc.grid(row=1, column=0, padx=10, pady=5, sticky='w')
        entry_desc = ttk.Entry(context_menu_tab)
        entry_desc.grid(row=1, column=1, padx=10, pady=5, sticky='ew')
        create_tooltip(entry_desc, "The title of the Context Menu item that will show up inside the Context Menu.")

        global entry_command
        lbl_command = ttk.Label(context_menu_tab, text="Command:")
        lbl_command.grid(row=2, column=0, padx=10, pady=5, sticky='w')
        entry_command = ttk.Entry(context_menu_tab)
        entry_command.grid(row=2, column=1, padx=10, pady=5, sticky='ew')
        create_tooltip(entry_command, "The program or command to run. Enter the full path to the program, or use the 'Browse...' button.")

        global browse_command
        browse_command = ttk.Button(context_menu_tab, text="Browse...", command=browse_new_cmd)
        browse_command.grid(row=2, column=2, padx=10, pady=5, sticky='e')

        # Buttons for add and remove
        btn_add = ttk.Button(context_menu_tab, text="Add", command=add_context_menu)
        btn_add.grid(row=3, column=0, padx=10, pady=5, sticky='n')

        btn_remove = ttk.Button(context_menu_tab, text="Remove", command=remove_context_menu)
        btn_remove.grid(row=3, column=1, padx=10, pady=5, sticky='nw')

        # Listbox to show current context menu items
        global listbox_context_menu
        listbox_context_menu = tk.Listbox(context_menu_tab)
        listbox_context_menu.grid(row=4, column=0, columnspan=2, padx=10, pady=0, sticky='nsew')
        listbox_context_menu.bind('<<ListboxSelect>>', load_context_menu_details)

        # Make the listbox expand with window resize
        context_menu_tab.rowconfigure(4, weight=1)
        context_menu_tab.columnconfigure(1, weight=1)

        update_context_menu_list()

        ## DRIVES TAB ##
        notebook.add(drives_tab, text="Hide Drives")

        # Drive Checkboxes
        current_no_drives = get_hidden_drives()
        
        for index, drive in enumerate(string.ascii_uppercase):
            var = tk.IntVar()
            row, col = divmod(index, 12)
            chk = ttk.Checkbutton(drives_tab, text=f"{drive}:", variable=var)
            chk.grid(row=row, column=col, padx=5, pady=5)
            drive_vars.append(var)
            create_tooltip(chk, f"Hide drive {drive}: from the Windows Explorer. It will still show up in other programs.")

        initialize_checkboxes(current_no_drives)

        hide_drives_button = ttk.Button(drives_tab, text="Hide Selected Drives", command=set_hidden_drives)
        hide_drives_button.grid(row=3, column=3, columnspan=26, sticky='W')
        create_tooltip(hide_drives_button, "Apply drive hide settings. You will need to restart the Explorer to see the effects.")

        restart_explorer_button = ttk.Button(drives_tab, text="Restart Windows Explorer", command=restart_explorer)
        restart_explorer_button.grid(row=3, column=7, columnspan=454, sticky='W',)

        drive_divider = tk.Label(drives_tab, text=divider, foreground='light gray')
        drive_divider.grid(row=4, columnspan=26)

        # --- User Accounts Tab ---
        global user_list, entry_username, entry_password
        user_accounts_tab = ttk.Frame(notebook)
        notebook.add(user_accounts_tab, text="User Accounts")

        # Display List of Users
        user_list_frame = ttk.LabelFrame(user_accounts_tab, text="Windows User Accounts")
        user_list_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Create Treeview to display user accounts
        user_list = ttk.Treeview(user_list_frame, columns=("username",), show="headings")
        user_list.heading("username", text="Username")
        user_list.pack(fill='both', expand=True)
    
        # Bind the Treeview selection event to on_user_select
        user_list.bind("<<TreeviewSelect>>", on_user_select)

        # Refresh Button to reload users
        refresh_button = ttk.Button(user_accounts_tab, text="Refresh List", command=load_user_accounts)
        refresh_button.pack(pady=5)

        # Add User Frame
        add_user_frame = ttk.LabelFrame(user_accounts_tab, text="Add/Edit User")
        add_user_frame.pack(fill='x', padx=10, pady=10)

        # Username Entry
        ttk.Label(add_user_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        entry_username = ttk.Entry(add_user_frame)
        entry_username.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Password Entry
        ttk.Label(add_user_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        entry_password = ttk.Entry(add_user_frame, show="*")
        entry_password.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Buttons for account actions
        ttk.Button(add_user_frame, text="Add User", command=add_user_account).grid(row=2, column=0, padx=5, pady=10, sticky="e")
        ttk.Button(add_user_frame, text="Update Password", command=update_user_password).grid(row=2, column=1, padx=5, pady=10, sticky="w")
        ttk.Button(user_accounts_tab, text="Delete User", command=delete_user_account).pack(pady=5)

        # Initial load of user accounts
        load_user_accounts()

        ## NETWORK INTERFACE TAB ##
        global network_tree, entry_ping_ip

        network_tab = ttk.Frame(notebook)
        notebook.add(network_tab, text="Network Interfaces")

        # Network Treeview for showing network details
        network_tree_frame = ttk.LabelFrame(network_tab, text="Network Interfaces")
        network_tree_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Define columns for the treeview
        columns = ("display_name", "internal_name", "mac_address", "speed")
        network_tree = ttk.Treeview(network_tree_frame, columns=columns, show="headings")
        network_tree.heading("display_name", text="Display Name")
        network_tree.heading("internal_name", text="Internal Name")
        network_tree.heading("mac_address", text="MAC Address")
        network_tree.heading("speed", text="Speed")
        network_tree.pack(fill='both', expand=True)

        # Buttons to enable/disable selected interface
        button_frame = ttk.Frame(network_tab)
        button_frame.pack(pady=10)

        enable_button = ttk.Button(button_frame, text="Enable Interface", command=enable_network_interface)
        enable_button.grid(row=0, column=0, padx=5)

        disable_button = ttk.Button(button_frame, text="Disable Interface", command=disable_network_interface)
        disable_button.grid(row=0, column=1, padx=5)

        # Ping section
        ping_frame = ttk.LabelFrame(network_tab, text="Ping IP")
        ping_frame.pack(fill='x', padx=10, pady=10)

        tk.Label(ping_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        entry_ping_ip = tk.Entry(ping_frame)
        entry_ping_ip.grid(row=0, column=1, padx=5, pady=5)
        ping_button = ttk.Button(ping_frame, text="Ping", command=ping_ip)
        ping_button.grid(row=0, column=2, padx=5, pady=5)

        # Initial load of network interfaces
        load_network_interfaces()

        ## STARTUP TAB ##
        global startup_listbox

        startup_tab = ttk.Frame(notebook)
        notebook.add(startup_tab, text="Startup")
        # Create Listbox to display startup programs
        startup_listbox = tk.Listbox(startup_tab, height=15)
        startup_listbox.pack(fill='x', pady=20)

        # Create buttons for adding, enabling, disabling, and removing programs
        add_button = ttk.Button(startup_tab, text="Add Program", command=add_program_to_startup)
        add_button.pack(side=tk.LEFT, padx=10)

        enable_button = ttk.Button(startup_tab, text="Enable Program", command=enable_program)
        enable_button.pack(side=tk.LEFT, padx=10)

        disable_button = ttk.Button(startup_tab, text="Disable Program", command=disable_program)
        disable_button.pack(side=tk.LEFT, padx=10)

        remove_button = ttk.Button(startup_tab, text="Remove Program", command=remove_program_from_startup)
        remove_button.pack(side=tk.LEFT, padx=10)

        # Initial load of startup programs
        refresh_startup_list()

        ## ABOUT TAB ##
        notebook.add(about_tab, text="About")

        prog_credits = """
        Special thanks to:
            - PorkyLIVE
            - ChatGPT
        """
        prog_credits_widget = tk.Label(about_tab, text=prog_credits, font=("Arial", 12, "italic"), padx=20, pady=20)
        prog_credits_widget.pack(expand=True, fill='x')

        twitter_button = ttk.Button(about_tab, text="Twitter", command=open_twitter)
        twitter_button.pack(side=tk.BOTTOM, padx=20, pady=20)

        # Bind Shift + F10 key press to open command prompt
        window.bind("<Shift-F10>", on_shift_f10)
        
        # Bind Shift key press and release to change window title
        window.bind("<ShiftPress>", window.title("Porkspatch (Press Shift+F10 to open Command Prompt)"))
        window.bind("<ShiftRelease>", window.title("Porkspatch"))

        # Start the main event loop
        window.mainloop()

    except Exception as e:
        print(f"[ERR] {e}")

# Run the application
if __name__ == "__main__":
    if not is_admin():
        run_as_admin()
    else:
        main()
