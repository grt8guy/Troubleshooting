# vm_crash_dumps.py
# This script finds and analyzes Windows crash dump files (.dmp) using WinDbg (cdb.exe).
# It requires the Windows Debugging Tools to be installed.
# Ensure you have the necessary permissions to access the dump files and run WinDbg.

import os
import glob
import subprocess
import psutil
import ctypes
import sys
import _wmi
import winreg
# wmi is imported only when needed in list_loaded_drivers()

def find_crash_dumps(dump_dir="C:\\Windows\\Minidump"):
    """Find all .dmp files in the given directory."""
    pattern = os.path.join(dump_dir, "*.dmp")
    return glob.glob(pattern)

def analyze_dump(dump_file, windbg_path="C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe"):
    """
    Analyze a crash dump using WinDbg (cdb.exe).
    Returns the output as a string.
    """
    if not os.path.exists(windbg_path):
        raise FileNotFoundError("WinDbg (cdb.exe) not found at specified path.")
    cmd = [windbg_path, '-z', dump_file, '-c', '!analyze -v; q']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout
    except Exception as e:
        return f"Error analyzing dump: {e}"

if __name__ == "__main__":
    dumps = find_crash_dumps()
    if not dumps:
        print("No crash dumps found.")
    else:
        for dump in dumps:
            print(f"Analyzing: {dump}")
            output = analyze_dump(dump)
            print(output[:2000])  # Print first 2000 chars for brevity
            out_file = os.path.join("c:\\temp", os.path.basename(dump) + ".txt")
            os.makedirs(os.path.dirname(out_file), exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Output written to: {out_file}")
        print("Analysis complete.")

# This section is for gathering Running Processes and threads, loaded drivers and DLLs
def collect_processes_and_threads(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "processes_and_threads.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                f.write(f"Process: {proc.info['name']} (PID: {proc.info['pid']})\n")
                threads = proc.threads()
                f.write(f"  Threads ({len(threads)}):\n")
                for thread in threads:
                    f.write(f"    Thread ID: {thread.id}, User Time: {thread.user_time}, System Time: {thread.system_time}\n")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            f.write("\n")
    print(f"Processes and threads info written to: {out_file}")

collect_processes_and_threads()

# This section is for gathering loaded drivers and DLLs
def list_loaded_modules(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "loaded_modules.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                f.write(f"Process: {proc.info['name']} (PID: {proc.info['pid']})\n")
                modules = []
                if sys.platform == "win32":
                    try:
                        PROCESS_QUERY_INFORMATION = 0x0400
                        PROCESS_VM_READ = 0x0010
                        k32 = ctypes.windll.kernel32
                        OpenProcess = k32.OpenProcess
                        EnumProcessModules = ctypes.windll.psapi.EnumProcessModules
                        GetModuleFileNameEx = ctypes.windll.psapi.GetModuleFileNameExW
                        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.info['pid'])
                        if hProcess:
                            arr = (ctypes.c_void_p * 1024)()
                            cb = ctypes.sizeof(arr)
                            cb_needed = ctypes.c_ulong()
                            if EnumProcessModules(hProcess, ctypes.byref(arr), cb, ctypes.byref(cb_needed)):
                                count = int(cb_needed.value / ctypes.sizeof(ctypes.c_void_p))
                                for i in range(count):
                                    mod = arr[i]
                                    buf = ctypes.create_unicode_buffer(260)
                                    if GetModuleFileNameEx(hProcess, mod, buf, 260):
                                        modules.append(buf.value)
                            k32.CloseHandle(hProcess)
                    except Exception:
                        pass
                for m in modules:
                    f.write(f"  DLL: {m}\n")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            f.write("\n")
    print(f"Loaded modules info written to: {out_file}")

def list_loaded_drivers(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "loaded_drivers.txt")
    try:
        import wmi
        c = wmi.WMI()
        with open(out_file, "w", encoding="utf-8") as f:
            for driver in c.Win32_SystemDriver():
                f.write(f"Driver: {driver.Name}\n")
                f.write(f"  Path: {driver.PathName}\n")
                f.write(f"  State: {driver.State}\n")
                f.write(f"  Start Mode: {driver.StartMode}\n\n")
        print(f"Loaded drivers info written to: {out_file}")
    except ImportError:
        print("wmi module not installed. Run 'pip install wmi' to enable driver listing.")

list_loaded_modules()
list_loaded_drivers()

# This section is for kernel and user memory dumps
def dump_memory_info(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    kernel_out = os.path.join(output_dir, "kernel_memory_info.txt")
    user_out = os.path.join(output_dir, "user_memory_info.txt")

    # Kernel memory info (using psutil.virtual_memory and swap_memory)
    with open(kernel_out, "w", encoding="utf-8") as f:
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()
        f.write("=== Kernel Memory (System) ===\n")
        f.write(f"Total: {vm.total}\n")
        f.write(f"Available: {vm.available}\n")
        f.write(f"Used: {vm.used}\n")
        f.write(f"Free: {vm.free}\n")
        f.write(f"Percent Used: {vm.percent}\n")
        f.write("\n=== Swap Memory ===\n")
        f.write(f"Total: {sm.total}\n")
        f.write(f"Used: {sm.used}\n")
        f.write(f"Free: {sm.free}\n")
        f.write(f"Percent Used: {sm.percent}\n")
    print(f"Kernel memory info written to: {kernel_out}")

    # User memory info (per-process memory usage)
    with open(user_out, "w", encoding="utf-8") as f:
        f.write("=== User Memory (Per Process) ===\n")
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                mem = proc.info['memory_info']
                f.write(f"Process: {proc.info['name']} (PID: {proc.info['pid']})\n")
                f.write(f"  RSS: {mem.rss}\n")
                f.write(f"  VMS: {mem.vms}\n")
                f.write(f"  Shared: {getattr(mem, 'shared', 'N/A')}\n")
                f.write(f"  Text: {getattr(mem, 'text', 'N/A')}\n")
                f.write(f"  Lib: {getattr(mem, 'lib', 'N/A')}\n")
                f.write(f"  Data: {getattr(mem, 'data', 'N/A')}\n")
                f.write(f"  Dirty: {getattr(mem, 'dirty', 'N/A')}\n\n")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    print(f"User memory info written to: {user_out}")

dump_memory_info()

# network connections and sockets
def list_network_connections(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "network_connections.txt")
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            for conn in psutil.net_connections(kind='inet'):
                f.write(f"Local Address: {conn.laddr}\n")
                f.write(f"Remote Address: {conn.raddr}\n")
                f.write(f"Status: {conn.status}\n")
                f.write(f"PID: {conn.pid}\n\n")
        print(f"Network connections info written to: {out_file}")
    except Exception as e:
        print(f"Error listing network connections: {e}")

list_network_connections()

# This section is for registry keys and values
def export_registry_keys(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "registry_keys.txt")
    registry_roots = [
        (winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
        (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
        (winreg.HKEY_USERS, "HKEY_USERS"),
        (winreg.HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"),
        (winreg.HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG"),
    ]

    def enum_keys(root, path, depth=0, max_depth=2):
        keys = []
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(key, i)
                        keys.append((path, subkey))
                        if depth < max_depth:
                            keys.extend(enum_keys(root, os.path.join(path, subkey), depth + 1, max_depth))
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        return keys

    def enum_values(root, path):
        values = []
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(key, i)
                        values.append((name, value, vtype))
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        return values

    with open(out_file, "w", encoding="utf-8") as f:
        for root, root_name in registry_roots:
            f.write(f"=== {root_name} ===\n")
            keys = enum_keys(root, "", max_depth=1)
            for path, subkey in keys:
                full_path = os.path.join(path, subkey).replace("\\", "\\\\")
                f.write(f"[{root_name}\\{full_path}]\n")
                vals = enum_values(root, os.path.join(path, subkey))
                for name, value, vtype in vals:
                    f.write(f"  {name}: {value} (type {vtype})\n")
                f.write("\n")
    print(f"Registry keys and values exported to: {out_file}")

export_registry_keys()

# This section is for gather handles
def gather_handles(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "handles.txt")
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                try:
                    f.write(f"=== {proc.info['name']} (PID: {proc.info['pid']}) ===\n")
                    handles = proc.num_handles()
                    f.write(f"Number of handles: {handles}\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    except Exception as e:
        print(f"Error gathering handles: {e}")

gather_handles()

# This section is for Stacks and Callbacks
def gather_stacks_and_callbacks(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "stacks_and_callbacks.txt")
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                try:
                    f.write(f"=== {proc.info['name']} (PID: {proc.info['pid']}) ===\n")
                    threads = proc.threads()
                    for thread in threads:
                        f.write(f"Thread ID: {thread.id}\n")
                        f.write(f"User Time: {thread.user_time}\n")
                        f.write(f"System Time: {thread.system_time}\n")
                        # Note: Actual stack trace gathering requires more complex handling
                        f.write("Stack trace gathering is not implemented in this script.\n\n")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    except Exception as e:
        print(f"Error gathering stacks and callbacks: {e}") 

# this section is for gathering exception codes
def export_exception_codes(output_dir="c:\\temp"):
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "exception_codes.txt")
    exception_codes = []

    # Scan minidump files for exception codes using WinDbg
    dumps = find_crash_dumps()
    windbg_path = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe"
    for dump in dumps:
        if not os.path.exists(windbg_path):
            continue
        cmd = [windbg_path, '-z', dump, '-c', '!analyze -v; q']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout
            # Look for lines like: "ExceptionCode: c0000005 (Access violation)"
            for line in output.splitlines():
                if "ExceptionCode:" in line:
                    exception_codes.append(f"{os.path.basename(dump)}: {line.strip()}")
        except Exception:
            continue

    if exception_codes:
        with open(out_file, "w", encoding="utf-8") as f:
            for code in exception_codes:
                f.write(code + "\n")
        print(f"Exception codes exported to: {out_file}")
    else:
        print("No exception codes found in crash dumps.")

export_exception_codes()

     