import tkinter as tk
from tkinter import ttk, messagebox
import threading
import network_scanner
import os
import json

class NetworkScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("CyberSeer - Network Vulnerability Scanner")
        master.geometry("1000x600")
        master.configure(bg='#0a0e14')

        self.security_score = "N/A"
        self.generated_files = []
        self.create_widgets()

    def create_widgets(self):
        # Main frame
        main_frame = tk.Frame(self.master, bg='#0a0e14')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Network Security Score label
        self.score_label = tk.Label(main_frame, text=f"Network Security Score: {self.security_score}", 
                                    font=("Courier", 18, "bold"), fg='#00ffff', bg='#0a0e14')
        self.score_label.pack(pady=(0, 20))

        # Button style
        style = ttk.Style()
        style.configure('TButton', 
                        foreground='#00ffff', 
                        background='#1a1f29', 
                        font=('Courier', 10, 'bold'),
                        borderwidth=1,
                        focuscolor='none')
        style.map('TButton', background=[('active', '#2a3544')])

        # Button frame
        button_frame = tk.Frame(main_frame, bg='#0a0e14')
        button_frame.pack(pady=(0, 20))

        # Start Scan button
        self.start_button = ttk.Button(button_frame, text="Start Network Scan", command=self.start_scan, style='TButton')
        self.start_button.pack(side='left', padx=(0, 10))

        # Progress bar
        style.configure("TProgressbar", thickness=20, troughcolor='#1a1f29', background='#00ffff')
        self.progress_bar = ttk.Progressbar(main_frame, length=400, mode='determinate', style="TProgressbar")
        self.progress_bar.pack(pady=(0, 20))

        # Notebook for logs and results
        style.configure('TNotebook', background='#0a0e14')
        style.configure('TNotebook.Tab', background='#1a1f29', foreground='#00ffff', font=('Courier', 10, 'bold'), padding=[10, 2])
        style.map("TNotebook.Tab", background=[("selected", "#0a0e14")])

        notebook = ttk.Notebook(main_frame, style='TNotebook')
        notebook.pack(expand=True, fill='both')

        # Log frame
        log_frame = tk.Frame(notebook, bg='#0a0e14')
        notebook.add(log_frame, text="Log")

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, bg='#0a0e14', fg='#00ffff', font=("Courier", 10))
        self.log_text.pack(expand=True, fill='both', side='left')
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scrollbar.pack(side='right', fill='y')
        self.log_text.configure(yscrollcommand=log_scrollbar.set)

        # Results frame
        results_frame = tk.Frame(notebook, bg='#0a0e14')
        notebook.add(results_frame, text="Results")

        style.configure("Treeview", 
                        background="#0a0e14",
                        foreground="#00ffff",
                        fieldbackground="#0a0e14")
        style.configure("Treeview.Heading", 
                        background="#1a1f29", 
                        foreground="#00ffff", 
                        font=("Courier", 10, "bold"))

        self.results_tree = ttk.Treeview(results_frame, columns=('IP', 'Port', 'Protocol', 'Service', 'Product', 'Version', 'Criticality'), 
                                         show='headings', style="Treeview")
        for col in ('IP', 'Port', 'Protocol', 'Service', 'Product', 'Version', 'Criticality'):
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100)
        self.results_tree.pack(expand=True, fill='both', side='left')
        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        results_scrollbar.pack(side='right', fill='y')
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)

        self.results_tree.bind("<Double-1>", self.show_port_info)

    def start_scan(self):
        threading.Thread(target=self.run_scan).start()

    def run_scan(self):
        self.log("Starting network scan...")
        self.progress_bar['value'] = 0
        target = network_scanner.get_local_ip_range()
        additional_targets = ['127.0.0.1']

        all_targets = [target] + additional_targets

        # Phase 1: Host-Specific Scan
        self.log("Phase 1: Scanning the host machine...")
        host_vulnerabilities = network_scanner.run_host_scan()
        self.display_results(host_vulnerabilities)

        # Update progress bar for host scan
        self.progress_bar['value'] += 50
        self.update_progress()

        # Phase 2: Subnet Scan
        self.log("Phase 2: Scanning the network subnet...")
        subnet_vulnerabilities = []

        # Run a single nmap scan for the entire subnet
        results = network_scanner.run_subnet_scan(target)
        self.display_results(results)

        # Update log and progress for each host in the subnet
        total_hosts = len(list(network_scanner.ip_network(target).hosts()))
        for i, host in enumerate(network_scanner.ip_network(target).hosts()):
            ip_str = str(host)
            self.log(f"Scanned IP: {ip_str}")
            self.progress_bar['value'] = 50 + ((i + 1) / total_hosts) * 50
            self.update_progress()

        self.progress_bar['value'] = 100
        self.update_progress()

        self.log("Scan completed.")

        # Calculate and update security score
        score = network_scanner.calculate_network_security_score(host_vulnerabilities + results, '127.0.0.1')
        self.update_score(score)
        self.save_score(score)

    def update_progress(self):
        self.master.update_idletasks()

    def display_results(self, vulnerabilities):
        for vuln in vulnerabilities:
            self.results_tree.insert('', tk.END, values=(vuln['ip'], vuln['port'], vuln['protocol'], 
                                                         vuln['service'], vuln['product'], vuln['version'],
                                                         vuln['criticality']))

    def show_port_info(self, event):
        item = self.results_tree.selection()[0]
        port = int(self.results_tree.item(item, "values")[1])
        info = "No specific information available for this port."

        for port_range, port_info in network_scanner.PORT_INFO.items():
            if isinstance(port_range, tuple) and port in port_range:
                info = port_info
                break
            elif port == port_range:
                info = port_info
                break

        messagebox.showinfo("Port Information", f"Port {port}:\n\n{info}")

    def update_score(self, score):
        self.security_score = score
        self.score_label.config(text=f"Network Security Score: {self.security_score}")

    def save_score(self, score):
        try:
            with open("network_score.txt", "w") as f:
                f.write(f"{score}")
            self.log("Network security score saved.")

            # Save detailed results
            results = []
            for item in self.results_tree.get_children():
                results.append(self.results_tree.item(item)['values'])
            
            with open("network_scan_results.json", "w") as f:
                json.dump(results, f)

        except Exception as e:
            self.log(f"Error saving network security score and results: {str(e)}")

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def cleanup(self):
        files_to_remove = [
            "network_score.txt",
            "subnet_scan_results.xml",
            "host_scan_results.xml",
            "live_hosts.xml"
        ]
        for file in files_to_remove:
            if os.path.exists(file):
                os.remove(file)
        self.log("Temporary files cleaned up.")

if __name__ == "__main__":
    root = tk.Tk()
    gui = NetworkScannerGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: [gui.cleanup(), root.destroy()])
    root.mainloop()
