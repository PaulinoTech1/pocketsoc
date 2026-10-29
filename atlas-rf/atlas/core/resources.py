"""Linux procfs resource snapshots; no psutil, worker pool or retained samples."""
import os
from pathlib import Path
import resource
import shutil
import time
from .errors import ResourceLimitError

MIB = 1024 * 1024


def values(path):
    try:
        text = Path(path).read_text()
    except OSError:
        return {}
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].isdigit():
            result[fields[0].rstrip(':')] = int(fields[1])
    return result


class ResourceMonitor:
    def __init__(self):
        self.wall = time.monotonic()
        self.cpu = time.process_time()

    def sample(self, data_path):
        current, cpu = time.monotonic(), time.process_time()
        cpu_percent = max(0.0, (cpu - self.cpu) / max(current - self.wall, 0.000001) * 100)
        self.wall, self.cpu = current, cpu
        process, memory = values('/proc/self/status'), values('/proc/meminfo')
        directory = Path(data_path).expanduser().absolute().parent
        while not directory.exists() and directory != directory.parent:
            directory = directory.parent
        try:
            disk_free = shutil.disk_usage(directory).free
        except OSError:
            disk_free = None
        return dict(pid=os.getpid(), rss_bytes=process.get('VmRSS', 0) * 1024 if 'VmRSS' in process else None,
                    peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                    available_memory_bytes=memory.get('MemAvailable', 0) * 1024 if 'MemAvailable' in memory else None,
                    total_memory_bytes=memory.get('MemTotal', 0) * 1024 if 'MemTotal' in memory else None,
                    cpu_percent=round(cpu_percent, 2), disk_free_bytes=disk_free,
                    cpu_note='Process CPU since previous sample; 100% equals one fully used CPU. First sample covers startup only.')


def enforce(snapshot, config):
    reasons = []
    if snapshot['rss_bytes'] is not None and snapshot['rss_bytes'] > config.max_rss_mb * MIB:
        reasons.append('process RSS exceeds configured budget')
    if snapshot['available_memory_bytes'] is not None and snapshot['available_memory_bytes'] < config.min_available_mb * MIB:
        reasons.append('available VM memory below configured reserve')
    if snapshot['disk_free_bytes'] is not None and snapshot['disk_free_bytes'] < config.min_free_disk_mb * MIB:
        reasons.append('free data-volume space below configured reserve')
    if reasons:
        raise ResourceLimitError('; '.join(reasons))
