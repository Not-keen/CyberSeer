import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import subprocess
import threading
import queue
import match_cve
import os

class CyberSeerGUI:
    def __init__(self, master, update_main_score_callback):
        self.master = master
        self.update_main_score_callback = update_main_score_callback
        master.title("CyberSeer - CVE Scanner")
        master.geometry("1200x700")
        master.configure(bg='#0a0e14')

        self.security_score = "N/A"
        self.log_queue = queue.Queue()
        self.after_id = None
        self.total_software = 0
        self.processed_software = 0
        self.excluded_results = set()

        self.create_widgets()
        self.update_log()

    def create_widgets(self):
        main_frame = tk.Frame(self.master, bg='#0a0e14')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        style = ttk.Style()
        style.configure('TButton', 
                        foreground='#00ffff', 
                        background='#1a1f29', 
                        font=('Courier', 10, 'bold'),
                        borderwidth=1,
                        relief='flat',
                        padding=(10, 5))
        style.map('TButton', background=[('active', '#2a3544')])

        self.score_label = tk.Label(main_frame, text=f"Software Security Score: {self.security_score}", 
                                    font=("Courier", 18, "bold"), fg='#00ffff', bg='#0a0e14')
        self.score_label.pack(pady=(0, 20))

        button_frame = tk.Frame(main_frame, bg='#0a0e14')
        button_frame.pack(pady=(0, 20))

        self.import_button = ttk.Button(button_frame, text="Import API Key", command=self.import_api_key)
        self.import_button.pack(side='left', padx=5)

        self.list_software_button = ttk.Button(button_frame, text="List Software", command=self.list_installed_software)
        self.list_software_button.pack(side='left', padx=5)

        self.start_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side='left', padx=5)

        style.configure("TProgressbar", thickness=20, troughcolor='#1a1f29', background='#00ffff')
        self.progress_bar = ttk.Progressbar(main_frame, length=400, mode='determinate', style="TProgressbar")
        self.progress_bar.pack(pady=(0, 20))

        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill='both')

        log_frame = tk.Frame(notebook, bg='#0a0e14')
        notebook.add(log_frame, text="Log")

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, bg='#0a0e14', fg='#00ffff', font=("Courier", 10))
        self.log_text.pack(expand=True, fill='both', side='left')
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scrollbar.pack(side='right', fill='y')
        self.log_text.configure(yscrollcommand=log_scrollbar.set)

        results_frame = tk.Frame(notebook, bg='#0a0e14')
        notebook.add(results_frame, text="Results")

        style.configure("Treeview",
                        background="#0a0e14",
                        foreground="#00ffff",
                        fieldbackground="#0a0e14",
                        rowheight=60)
        style.configure("Treeview.Heading", 
                        background="#1a1f29", 
                        foreground="#00ffff", 
                        font=("Courier", 10, "bold"))
        style.map('Treeview', background=[('selected', '#1a1f29')])

        self.results_tree = ttk.Treeview(results_frame, columns=('Software', 'Version', 'CVE', 'Severity'), 
                                         show='headings', style='Treeview')
        self.results_tree.pack(expand=True, fill='both', side='left')
        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        results_scrollbar.pack(side='right', fill='y')
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)

        for col in ('Software', 'Version', 'CVE', 'Severity'):
            self.results_tree.heading(col, text=col)
        
        self.results_tree.column('Software', width=150, anchor='w')
        self.results_tree.column('Version', width=100, anchor='w')
        self.results_tree.column('CVE', width=700, anchor='w')
        self.results_tree.column('Severity', width=100, anchor='w')

    def log(self, message):
        self.log_queue.put(message)

    def update_log(self):
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
        self.after_id = self.master.after(100, self.update_log)

    def import_api_key(self):
        api_key = simpledialog.askstring("API Key", "Enter your NIST API Key:", parent=self.master)
        if api_key:
            match_cve.set_api_key(api_key)
            self.log("API key imported and saved successfully.")
        else:
            self.log("API key import cancelled.")

    def list_installed_software(self):
        def run_script():
            try:
                result = subprocess.run(["bash", "list_installed_software.sh"], capture_output=True, text=True)
                if result.returncode == 0:
                    self.log("Installed software list generated successfully.")
                    self.log("Contents of installed_software.csv:")
                    with open("installed_software.csv", "r") as f:
                        self.log(f.read())
                else:
                    self.log(f"Error running list_installed_software.sh: {result.stderr}")
            except Exception as e:
                self.log(f"Error running list_installed_software.sh: {str(e)}")

        threading.Thread(target=run_script).start()

    def start_scan(self):
        def run_scan():
            self.start_button.config(state=tk.DISABLED)
            self.progress_bar['value'] = 0
            self.log("Starting scan...")
            self.log("Note: This scan may take a while due to API rate limits. Please be patient.")
            try:
                if not match_cve.load_api_key():
                    raise ValueError("API key not found. Please import an API key first.")

                self.results_tree.delete(*self.results_tree.get_children())
                self.excluded_results.clear()

                match_cve.main(self.log, self.add_result, self.update_progress)
                self.log("Scan completed.")
            except ValueError as ve:
                self.log(f"Error: {str(ve)}")
                messagebox.showerror("API Key Error", str(ve), parent=self.master)
            except Exception as e:
                self.log(f"An unexpected error occurred: {str(e)}")
                import traceback
                self.log(traceback.format_exc())
            finally:
                self.start_button.config(state=tk.NORMAL)
                self.progress_bar['value'] = 100

        threading.Thread(target=run_scan).start()

    def update_progress(self, progress):
        self.progress_bar['value'] = progress
        self.master.update_idletasks()

    def add_result(self, result):
        software, version, cve_list, severity = result
        if software == "OVERALL_SCORE":
            self.update_score(severity)
        else:
            if isinstance(cve_list, list):
                if len(cve_list) > 1:
                    cve_display = f"{cve_list[0]} + {len(cve_list) - 1} more"
                elif len(cve_list) == 1:
                    cve_display = cve_list[0]
                else:
                    cve_display = "No CVEs"
            else:
                cve_display = cve_list  # In case it's already formatted as a string
            self.results_tree.insert('', 'end', values=(software, version, cve_display, severity))


    def save_score(self):
        try:
            with open("security_score.txt", "w") as f:
                f.write(f"{self.security_score}")
            self.update_main_score_callback()
        except Exception as e:
            self.log(f"Error saving security score: {str(e)}")
            
    def update_score(self, score):
        self.security_score = score
        self.score_label.config(text=f"Software Security Score: {self.security_score}")

    def cleanup(self):
        match_cve.cleanup_temp_files()

if __name__ == "__main__":
    root = tk.Tk()
    gui = CyberSeerGUI(root, lambda: None)
    root.protocol("WM_DELETE_WINDOW", lambda: [gui.cleanup(), root.destroy()])
    root.mainloop()
