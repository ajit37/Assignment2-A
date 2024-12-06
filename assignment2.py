#!/usr/bin/env python3

'''
OPS445 Assignment 2
Program: assignment2.py 
Author: Ajit Virk
Semester: Fall

The python code in this file is original work written by
Ajit Virk. No code in this file is copied from any other source 
except those provided by the course instructor, including any person, 
textbook, or on-line resource. I have not shared this python script 
with anyone or anything except for submission for grading.  
I understand that the Academic Honesty Policy will be enforced and 
violators will be reported and appropriate action will be taken.

Description: <Enter your documentation here>

'''

import argparse
import os, sys

def parse_command_args() -> object:
# create argparse function
    parser = argparse.ArgumentParser(description="Memory Visualiser -- See Memory Usage Report with bar charts", epilog="Copyright 2023")

    # -H option for human-readable memory output (e.g., MiB, GiB, etc.)
    parser.add_argument("-H", "--human-readable", action="store_true", help="Prints sizes in human-readable format")

    # -l option for specifying the length of the bar graph
    parser.add_argument("-l", "--length", type=int, default=20, help="Specify the length of the graph. Default is 20.")

    # -r option to list only running processes
    parser.add_argument("-r", "--running", action="store_true", help="List only running processes (optional)")

    # Positional argument for the program name (to specify a program for memory use tracking)
    parser.add_argument("program", type=str, nargs='?', help="If a program is specified, show memory use of all associated processes. Show only total use if not.")

    # Parse and return the arguments object
    args = parser.parse_args()
    return args
    
    # -H human readable
# -r running only

def percent_to_graph(percent: float, length: int=20) -> str:
    "turns a percent 0.0 - 1.0 into a bar graph"
    # Ensure percent is between 0 and 1
    percent = max(0, min(1, percent))
    # Calculate how many hash symbols 
    num_hashes = int(percent * length)
    # Construct the bar
    return "#" * num_hashes + " " * (length - num_hashes)

# percent to graph function

def get_sys_mem() -> int:
    "return total system memory (used or available) in kB"
    with open("/proc/meminfo", "r") as f:
        for line in f:
            if line.startswith("MemTotal"):
                # Extract the value in kB from the line and return it
                return int(line.split()[1])

def get_avail_mem() -> int:
    "return total memory that is available"
    with open("/proc/meminfo", "r") as f:
        mem_free = 0
        swap_free = 0
        mem_available = 0
        
        for line in f:
            if line.startswith("MemFree"):
                mem_free = int(line.split()[1])
            elif line.startswith("SwapFree"):
                swap_free = int(line.split()[1])
            elif line.startswith("MemAvailable"):
                mem_available = int(line.split()[1])
        
        # If MemAvailable is available, return it, otherwise fall back on MemFree + SwapFree
        if mem_available > 0:
            return mem_available
        else:
            return mem_free + swap_free

def pids_of_prog(app_name: str) -> list:
    "given an app name, return all pids associated with app"
    try:
        # Use the pidof command to get process IDs for the program name
        pid_list = os.popen(f"pidof {app_name}").read().strip()
        # Return a list of process IDs, split by spaces
        return pid_list.split() if pid_list else []
    except Exception as e:
        print(f"Error getting PIDs for {app_name}: {e}")
        return []

def rss_mem_of_pid(proc_id: str) -> int:
    "given a process id, return the resident memory used, zero if not found"
    try:
        rss = 0
        # Open the smaps file for the given process ID
        with open(f"/proc/{proc_id}/smaps", "r") as f:
            for line in f:
                if line.startswith("Rss"):
                    # Sum up the RSS memory values
                    rss += int(line.split()[1])
        return rss
    except FileNotFoundError:
        print(f"Process {proc_id} not found.")
        return 0
    except Exception as e:
        print(f"Error reading RSS memory for PID {proc_id}: {e}")
        return 0

def bytes_to_human_r(kibibytes: int, decimal_places: int=2) -> str:
    "turn 1,024 into 1 MiB, for example"
    suffixes = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB']  # iB indicates 1024
    suf_count = 0
    result = kibibytes 
    while result > 1024 and suf_count < len(suffixes):
        result /= 1024
        suf_count += 1
    str_result = f'{result:.{decimal_places}f} '
    str_result += suffixes[suf_count]
    return str_result

if __name__ == "__main__":
    args = parse_command_args()
    if not args.program:
        # If no program is specified, show the overall system memory usage
        total_mem = get_sys_mem()
        avail_mem = get_avail_mem()
        used_mem = total_mem - avail_mem
        percent_used = used_mem / total_mem

        # Display the memory usage in a user-friendly way
        if args.human_readable:
            print(f"Memory {bytes_to_human_r(used_mem)} [{percent_to_graph(percent_used, args.length)} | {percent_used * 100:.1f}%] {bytes_to_human_r(used_mem)}/{bytes_to_human_r(total_mem)}")
        else:
            print(f"Memory {percent_to_graph(percent_used, args.length)} | {percent_used * 100:.1f}% {used_mem}/{total_mem} kB")

    else:
        # If a program is specified, get its associated PIDs and show memory usage for each process
        pids = pids_of_prog(args.program)
        if not pids:
            print(f"No running processes found for program: {args.program}")
        else:
            print(f"{'PID':<10}{'Memory (kB)':<15}{'Graph':<30}")
            for pid in pids:
                rss = rss_mem_of_pid(pid)
                percent = rss / total_mem
                if args.human_readable:
                    print(f"{pid:<10}{bytes_to_human_r(rss, 2):<15}{percent_to_graph(percent, args.length)}")
                else:
                    print(f"{pid:<10}{rss:<15}{percent_to_graph(percent, args.length)}")
    # process args
    # if no parameter passed, 
    # open meminfo.
    # get used memory
    # get total memory
    # call percent to graph
    # print

    # if a parameter passed:
    # get pids from pidof
    # lookup each process id in /proc
    # read memory used
    # add to total used
    # percent to graph
    # take total our of total system memory? or total used memory? total used memory.
    # percent to graph.
