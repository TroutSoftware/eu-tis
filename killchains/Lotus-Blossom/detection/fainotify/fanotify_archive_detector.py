#!/usr/bin/env python3

import os
import struct
import ctypes
import datetime
import pwd
from ctypes.util import find_library
from ctypes import CDLL

# 📂 Watched archive extensions
ARCHIVE_EXTENSIONS = ('.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz')
SUSPICIOUS_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB+

# 🎯 Target directories
WATCH_DIRS = ['/home', '/tmp', '/etc']

# fanotify constants
FAN_CLASS_NOTIF = 0x00000000
FAN_NONBLOCK = 0x00000002
FAN_CLOEXEC = 0x00000001

FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010

FAN_ACCESS = 0x00000001
FAN_OPEN = 0x00000020
FAN_EVENT_OK = 0

# Load libc
libc = CDLL(find_library("c"))

fanotify_init = libc.fanotify_init
fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
fanotify_init.restype = ctypes.c_int

fanotify_mark = libc.fanotify_mark
fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
fanotify_mark.restype = ctypes.c_int

# Fanotify metadata structure
class FanotifyEventMetadata(ctypes.Structure):
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]

def get_filepath(fd):
    try:
        return os.readlink(f'/proc/self/fd/{fd}')
    except Exception:
        return '[unknown]'

def get_uid_from_pid(pid):
    try:
        with open(f'/proc/{pid}/status') as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return -1

def log_event(pid, uid, path, access_type):
    timestamp = datetime.datetime.now().isoformat()
    username = pwd.getpwuid(uid).pw_name if uid >= 0 else "unknown"
    try:
        size = os.path.getsize(path)
    except Exception:
        size = -1

    print(f"\n🚨 [{timestamp}] {access_type} DETECTED")
    print(f"  → PID  : {pid}")
    print(f"  → UID  : {uid} ({username})")
    print(f"  → Path : {path}")
    print(f"  → Size : {size / 1024:.2f} KB" if size >= 0 else "  → Size : N/A")

    if size >= SUSPICIOUS_SIZE_BYTES:
        print("  ⚠️ Suspiciously large archive file detected!")

def main():
    print("👀 Initializing fanotify... (requires sudo)")
    fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_CLOEXEC, os.O_RDONLY)
    if fan_fd < 0:
        raise RuntimeError("Error in fanotify_init")

    for path in WATCH_DIRS:
        b_path = path.encode()
        res = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_ACCESS | FAN_OPEN, -1, b_path)
        if res < 0:
            raise RuntimeError(f"fanotify_mark failed on {path}")

    print("✅ Fanotify is active. Monitoring access to:")
    for d in WATCH_DIRS:
        print(f"  - {d}")
    print("🔔 Waiting for events...\n")

    buffer_size = ctypes.sizeof(FanotifyEventMetadata)
    while True:
        try:
            try:
                buffer = os.read(fan_fd, buffer_size)
            except BlockingIOError:
                continue  # No data available, continue loop

            if not buffer:
                continue

            event = FanotifyEventMetadata.from_buffer_copy(buffer)
            if event.fd < 0:
                continue

            path = get_filepath(event.fd)
            os.close(event.fd)

            if path.endswith(ARCHIVE_EXTENSIONS):
                pid = event.pid
                uid = get_uid_from_pid(pid)
                access_type = "Archive read/write"
                log_event(pid, uid, path, access_type)

            elif path.startswith('/home/'):
                pid = event.pid
                uid = get_uid_from_pid(pid)
                log_event(pid, uid, path, "Potential source file read")

        except KeyboardInterrupt:
            print("\n❌ Interrupted by user.")
            break
        except Exception as e:
            print(f"⚠️ Error: {e}")

if __name__ == "__main__":
    main()
