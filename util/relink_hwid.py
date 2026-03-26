#!/usr/bin/env python3
import socketio
import wmi
import subprocess

SERVER_URL = "http://127.0.0.1:3000"

def get_cpu_serial():
    try:
        c = wmi.WMI()
        for processor in c.Win32_Processor():
            return processor.ProcessorId.strip()
    except:
        pass
    try:
        result = subprocess.run(['wmic', 'cpu', 'get', 'ProcessorId'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        if len(lines) > 1:
            return lines[1].strip()
    except:
        pass
    return "CPU000000000000"

def get_disk_serial():
    try:
        c = wmi.WMI()
        for disk in c.Win32_DiskDrive():
            if disk.SerialNumber:
                return disk.SerialNumber.strip()
    except:
        pass
    try:
        result = subprocess.run(['wmic', 'diskdrive', 'get', 'SerialNumber'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        if len(lines) > 1:
            return lines[1].strip()
    except:
        pass
    return "DISK0000000000"

def get_mac_address():
    try:
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.MACAddress:
                return nic.MACAddress.replace(':', '').replace('-', '')
    except:
        pass
    return "001122334455"

def get_ram_serial():
    serials = []
    try:
        c = wmi.WMI()
        for ram in c.Win32_PhysicalMemory():
            if ram.SerialNumber and ram.SerialNumber.strip():
                serials.append(ram.SerialNumber.strip())
    except:
        pass
    if not serials:
        try:
            result = subprocess.run(['wmic', 'memorychip', 'get', 'SerialNumber'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:
                line = line.strip()
                if line:
                    serials.append(line)
        except:
            pass
    if not serials:
        serials = ["RAM000000000"]
    return ','.join(serials)

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python hwid_relink.py <license_id>")
        sys.exit(1)
    
    license_id = sys.argv[1]
    
    print("Gathering machine info...")
    machine_info = {
        "cpu_serial": get_cpu_serial(),
        "disk_serial": get_disk_serial(),
        "mac_address": get_mac_address(),
        "ram_serial": get_ram_serial()
    }
    
    print(f"CPU: {machine_info['cpu_serial']}")
    print(f"Disk: {machine_info['disk_serial']}")
    print(f"MAC: {machine_info['mac_address']}")
    print(f"RAM: {machine_info['ram_serial']}")
    
    sio = socketio.Client()
    
    @sio.on('connect')
    def on_connect():
        print("connected, sending machine info...")
        sio.emit('license:relink', {
            'licenseId': license_id,
            'machineInfo': machine_info
        })
    
    @sio.on('license:relink')
    def on_relink(data):
        if data.get('success'):
            print("license relinked successfully!")
        else:
            print(f"error: {data.get('error')}")
        sio.disconnect()
    
    try:
        sio.connect(SERVER_URL, transports=['polling'])
        sio.wait()
    except Exception as e:
        print(f"connection failed: {e}")

if __name__ == "__main__":
    main()
