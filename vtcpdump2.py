import os
import sys
import subprocess
import atexit
import signal
import json

cleaned = False

def vtcpdump_log(msg):
    print(f"> {msg}")

def cleanup_old_contexts(tmp_dir, current_pid):
    for fname in os.listdir(tmp_dir):
        if not fname.endswith('.context'):
            continue

        vtcpdump_log(f"cleaning up old contexts: {fname}")
        pid_str = fname[:-8]
        try:
            old_pid = int(pid_str)
            if old_pid == current_pid:
                continue
            # Check if process is alive
            os.kill(old_pid, 0)
        except (ValueError, OSError):
            # Process doesn't exist or invalid, clean up
            path = os.path.join(tmp_dir, fname)
            try:
                with open(path, 'r') as f:
                    ctx = json.load(f)
                # Disable span
                vtcpdump_log(f"disabling span: {ctx['vpp_interface']} -> {ctx['tap_if']}")
                subprocess.call(['vppctl', 'set', 'interface', 'span', ctx['vpp_interface'], 'destination', ctx['tap_if'], 'disable'])
                
                # Set state down
                vtcpdump_log(f"setting state down: {ctx['tap_if']}")
                subprocess.call(['vppctl', 'set', 'interface', 'state', ctx['tap_if'], 'down'])
                
                # Delete tap
                vtcpdump_log(f"deleting tap: {ctx['tap_if']}")
                subprocess.call(['vppctl', 'delete', 'tap', ctx['tap_if']])

                vtcpdump_log(f"deleting linux tap: {ctx['linux_tap']}")
                subprocess.call(['ip', 'tuntap', 'del', 'dev', ctx['linux_tap'], 'mode', 'tap'])
                
                # Delete context
                vtcpdump_log(f"deleting context: {path}")
                os.remove(path)
            except Exception:
                pass

def main():
    if os.geteuid() != 0:
        vtcpdump_log("This script requires sudo privileges for some commands.")
        sys.exit(1)

    tmp_dir = '/tmp/vtcpdump'
    os.makedirs(tmp_dir, exist_ok=True)

    pid = os.getpid()

    # Clean up old contexts
    cleanup_old_contexts(tmp_dir, pid)

    # Parse arguments
    argv = sys.argv[1:]
    try:
        i_idx = argv.index('-i')
        vpp_interface = argv[i_idx + 1]
        del argv[i_idx : i_idx + 2]
    except ValueError:
        vtcpdump_log("Must provide -i <vpp_interface>")
        sys.exit(1)

    # Set up tap
    linux_tap = f"vtap_{pid}"
    create_cmd = ['vppctl', 'create', 'tap', 'host-if-name', linux_tap]
    try:
        out = subprocess.check_output(create_cmd, stderr=subprocess.STDOUT).decode().strip()
        tap_if = out  # Assuming output is the VPP interface name, e.g., 'tap0'
    except subprocess.CalledProcessError as e:
        vtcpdump_log(f"Failed to create tap: {e.output.decode()}")
        sys.exit(1)

    # Save context
    context = {
        'tap_if': tap_if,
        'linux_tap': linux_tap,
        'vpp_interface': vpp_interface
    }
    context_file = os.path.join(tmp_dir, f"{pid}.context")
    with open(context_file, 'w') as f:
        json.dump(context, f)

    def cleanup():
        global cleaned
        if cleaned:
            return
        cleaned = True
        vtcpdump_log(f"disabling span: {vpp_interface} -> {tap_if}")
        subprocess.call(['vppctl', 'set', 'interface', 'span', vpp_interface, 'destination', tap_if, 'disable'])

        vtcpdump_log(f"setting state down: {tap_if}")
        subprocess.call(['vppctl', 'set', 'interface', 'state', tap_if, 'down'])
        
        vtcpdump_log(f"deleting tap: {tap_if}")
        subprocess.call(['vppctl', 'delete', 'tap', tap_if])
        
        vtcpdump_log(f"deleting linux tap: {linux_tap}")
        subprocess.call(['vppctl', 'delete', 'host-interface', 'name', linux_tap])
        
        vtcpdump_log(f"deleting context: {context_file}")
        if os.path.exists(context_file):
            os.remove(context_file)

    atexit.register(cleanup)

    def signal_handler(signum, frame):
        cleanup()
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Enable tap
    vtcpdump_log(f"Enabling tap: {tap_if}")
    subprocess.check_call(['vppctl', 'set', 'interface', 'state', tap_if, 'up'])
    subprocess.check_call(['ip', 'link', 'set', linux_tap, 'up'])

    # Set span
    vtcpdump_log(f"Setting span: {vpp_interface} -> {tap_if}")
    subprocess.check_call(['vppctl', 'set', 'interface', 'span', vpp_interface, 'destination', tap_if, 'both'])

    # Promisc mode
    vtcpdump_log(f"Promisc mode: {linux_tap}")
    subprocess.check_call(['ip', 'link', 'set', linux_tap, 'promisc', 'on'])

    # Run tcpdump
    vtcpdump_log(f"Running tcpdump: {linux_tap}")
    tcpdump_cmd = ['tcpdump', '-i', linux_tap] + argv
    p = subprocess.Popen(tcpdump_cmd)
    p.wait()

    # Cleanup will be called via atexit

if __name__ == "__main__":
    main()
