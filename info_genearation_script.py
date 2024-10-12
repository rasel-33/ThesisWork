import os
import time
import csv
import psutil
from datetime import datetime


# Function to get system and process metrics
def get_system_info():
    processes_info = []
    for proc in psutil.process_iter(
            ['pid', 'ppid', 'name', 'status', 'create_time', 'num_threads', 'cpu_times', 'memory_info', 'io_counters',
             'nice']):
        try:
            # Process creation and status
            pid = proc.info['pid']
            ppid = proc.info['ppid']
            status = proc.info['status']
            process_creation_time = datetime.fromtimestamp(proc.info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
            num_threads = proc.info['num_threads']
            nice = proc.info['nice']

            # CPU times
            cpu_times = proc.info['cpu_times']
            cpu_user_time = cpu_times.user
            cpu_kernel_time = cpu_times.system

            # Memory info
            memory_info = proc.info['memory_info']
            vmem = memory_info.vms
            rss = memory_info.rss
            pss = getattr(memory_info, 'pss', 0)
            uss = getattr(memory_info, 'uss', 0)
            swap = memory_info.swap if hasattr(memory_info, 'swap') else 0

            # I/O info
            io_info = proc.info['io_counters']
            if io_info:
                io_info = io_info[:4]  # Ensure only 4 values are unpacked
            else:
                io_info = (0, 0, 0, 0)  # Default values if io_counters is None or empty

            io_read_count, io_write_count, io_read_bytes, io_write_bytes = io_info

            # Network activity (Assuming using netstat or similar)
            kb_received = io_read_bytes / 1024
            kb_sent = io_write_bytes / 1024

            # Context switches
            ctx_switches_voluntary = proc.num_ctx_switches().voluntary
            ctx_switches_involuntary = proc.num_ctx_switches().involuntary

            # I/O priority (ionice)
            try:
                ionice_info = proc.ionice()
                ionice_ioclass = ionice_info.ioclass if hasattr(ionice_info, 'ioclass') else 0
                ionice_value = ionice_info.value if hasattr(ionice_info, 'value') else 0
            except AttributeError:
                ionice_ioclass = 0
                ionice_value = 0

            # Store process information in list
            processes_info.append([
                pid, ppid, process_creation_time, status, num_threads,
                kb_received, kb_sent, vmem, rss, pss, uss, swap,
                cpu_user_time, cpu_kernel_time,
                io_write_count, io_read_bytes, io_read_count,
                ctx_switches_involuntary, ctx_switches_voluntary,
                nice, ionice_ioclass, ionice_value
            ])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes_info


# Create CSV file with the required columns
output_file = "benign_system_info.csv"
header = [
    "sample_no", "exp_no", "vm_id", "pid", "ppid", "sample_time",
    "process_creation_time", "status", "num_threads", "kb_received",
    "kb_sent", "vmem", "rss", "pss", "uss", "swap",
    "cpu_user_time", "cpu_kernel_time",
    "io_write_count", "io_read_bytes", "io_read_count",
    "ctx_switches_involuntary", "ctx_switches_voluntary",
    "nice", "exe_path", "cmd_line", "ionice_ioclass", "ionice_value", "label"
]

with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(header)

    start_time = time.time()
    elapsed_time = 0
    sample_no = 0
    exp_no = 1  # Assign an experiment number
    vm_id = 778  # Example VM ID (You can adjust this as needed)
    label = 0  # Assuming 0 means benign in this case

    # Collect data for 10 minutes
    while elapsed_time < 600:  # 10 minutes = 600 seconds
        processes_info = get_system_info()
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        for process_info in processes_info:
            sample_no += 1
            writer.writerow([sample_no, exp_no, vm_id, *process_info, label])

        time.sleep(10)  # 10 seconds interval
        elapsed_time = time.time() - start_time

print(f"System information collection completed. Data saved to {output_file}.")

# import psutil
# import csv
# import time
# from datetime import datetime
#
# # Columns for 44 metrics
# columns = [
#     "timestamp", "pid", "name", "status", "cpu_percent", "cpu_times_user", "cpu_times_system",
#     "cpu_children_user", "cpu_children_system", "ctx_switches_voluntary", "ctx_switches_involuntary",
#     "io_read_count", "io_write_count", "io_read_bytes", "io_write_bytes", "io_read_chars", "io_write_chars",
#     "memory_swap_out", "memory_pss", "memory_rss", "memory_uss", "memory_vms", "dirty_pages",
#     "memory_physical", "memory_text", "memory_shared_libs", "net_recv_bytes", "net_sent_bytes",
#     "num_threads", "num_fds"
# ]
#
# # Path to save the CSV file
# csv_file = "expanded_benign_process_metrics.csv"
#
#
# # Function to collect system metrics
# def collect_metrics(duration=300, interval=10):
#     with open(csv_file, mode='w', newline='') as file:
#         writer = csv.DictWriter(file, fieldnames=columns)
#         writer.writeheader()
#
#         end_time = time.time() + duration
#         while time.time() < end_time:
#             for proc in psutil.process_iter(attrs=['pid', 'name', 'status']):
#                 try:
#                     p_info = proc.info
#                     p_info['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#                     p_info['cpu_percent'] = proc.cpu_percent(interval=None)
#                     cpu_times = proc.cpu_times()
#                     p_info['cpu_times_user'] = cpu_times.user
#                     p_info['cpu_times_system'] = cpu_times.system
#                     p_info['cpu_children_user'] = proc.cpu_times().children_user if hasattr(proc, 'cpu_times') else None
#                     p_info['cpu_children_system'] = proc.cpu_times().children_system if hasattr(proc,
#                                                                                                 'cpu_times') else None
#
#                     # Context switches
#                     ctx_switches = proc.num_ctx_switches() if proc.num_ctx_switches() else None
#                     if ctx_switches:
#                         p_info['ctx_switches_voluntary'] = ctx_switches.voluntary
#                         p_info['ctx_switches_involuntary'] = ctx_switches.involuntary
#                     else:
#                         p_info['ctx_switches_voluntary'] = None
#                         p_info['ctx_switches_involuntary'] = None
#
#                     # IO Counters
#                     io_counters = proc.io_counters() if proc.io_counters() else None
#                     if io_counters:
#                         p_info['io_read_count'] = io_counters.read_count
#                         p_info['io_write_count'] = io_counters.write_count
#                         p_info['io_read_bytes'] = io_counters.read_bytes
#                         p_info['io_write_bytes'] = io_counters.write_bytes
#                         p_info['io_read_chars'] = io_counters.read_chars if hasattr(io_counters, 'read_chars') else None
#                         p_info['io_write_chars'] = io_counters.write_chars if hasattr(io_counters,
#                                                                                       'write_chars') else None
#                     else:
#                         p_info['io_read_count'] = None
#                         p_info['io_write_count'] = None
#                         p_info['io_read_bytes'] = None
#                         p_info['io_write_bytes'] = None
#                         p_info['io_read_chars'] = None
#                         p_info['io_write_chars'] = None
#
#                     # Memory info
#                     mem_info = proc.memory_info()
#                     p_info['memory_pss'] = proc.memory_full_info().pss if hasattr(proc, 'memory_full_info') else None
#                     p_info['memory_rss'] = mem_info.rss
#                     p_info['memory_uss'] = proc.memory_full_info().uss if hasattr(proc, 'memory_full_info') else None
#                     p_info['memory_vms'] = mem_info.vms
#                     p_info['dirty_pages'] = proc.memory_full_info().dirty if hasattr(proc, 'memory_full_info') else None
#                     p_info['memory_physical'] = psutil.virtual_memory().used
#                     p_info['memory_text'] = proc.memory_info().text if hasattr(proc, 'memory_info') else None
#                     p_info['memory_shared_libs'] = proc.memory_info().shared if hasattr(proc, 'memory_info') else None
#
#                     # Network info (mock, as psutil does not provide per-process network info)
#                     p_info['net_recv_bytes'] = None  # Placeholder for network stats
#                     p_info['net_sent_bytes'] = None  # Placeholder for network stats
#
#                     p_info['num_threads'] = proc.num_threads()
#                     p_info['num_fds'] = proc.num_fds() if hasattr(proc, 'num_fds') else None
#
#                     # Write data to CSV
#                     writer.writerow(p_info)
#
#                 except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#                     # Handle processes that are no longer available
#                     continue
#
#             # Sleep for the specified interval before collecting again
#             time.sleep(interval)
#
#
# if __name__ == "__main__":
#     collect_metrics(duration=300, interval=10)  # Collect for 5 minutes, every 10 seconds
