import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from PIL import Image, ImageTk
from frontend import CyberSeerGUI
from gui_network_scanner import NetworkScannerGUI
from vulnerability_assessment import VulnerabilityAssessment
import os
import shutil
import json
import requests
import time

class MainPage:
    def __init__(self, master):
        self.master = master
        master.title("CyberSeer")
        master.geometry("800x600")
        master.configure(bg='#0a0e14')
        master.resizable(True, True)

        self.setup_theme()
        self.create_widgets()

        master.bind("<Configure>", self.update_background_size)
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_theme(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TButton', 
                        foreground='#00ffff', 
                        background='#1a1f29', 
                        font=('Courier', 12, 'bold'), 
                        borderwidth=0,
                        focuscolor='none',
                        highlightthickness=0)
        style.map('TButton', background=[('active', '#2a3544')])
        
        style.configure('TNotebook', background='#0a0e14')
        style.configure('TNotebook.Tab', background='#1a1f29', foreground='#00ffff', padding=(10, 5))
        style.map('TNotebook.Tab', background=[('selected', '#0a0e14')])
        
        style.configure("Treeview",
                        background="#0a0e14",
                        foreground="#00ffff",
                        fieldbackground="#0a0e14")
        style.map('Treeview', background=[('selected', '#1a1f29')])

    def create_widgets(self):
        # Load and display the background image
        self.bg_image = Image.open("cyber_seer_logo.png")
        self.bg_image = self.bg_image.resize((800, 600), Image.LANCZOS)
        self.bg_photo = ImageTk.PhotoImage(self.bg_image)
        self.bg_label = tk.Label(self.master, image=self.bg_photo)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Create a frame for buttons
        button_frame = tk.Frame(self.master, bg='#0a0e14')
        button_frame.place(relx=0.5, rely=0.5, anchor='center')

        # Add a canvas behind the buttons for a cohesive look
        canvas_width = 300
        canvas_height = 300
        canvas = tk.Canvas(button_frame, width=canvas_width, height=canvas_height, bg='#0a0e14', highlightthickness=0)
        canvas.pack()

        # Draw a rounded rectangle on the canvas
        canvas.create_rectangle(2, 2, canvas_width-2, canvas_height-2, fill='#1a1f29', outline='#00ffff', width=2)

        # Create buttons
        button_width = 20
        system_scan_button = ttk.Button(button_frame, text="System Scan", command=self.open_system_scan, width=button_width)
        system_scan_button.place(relx=0.5, rely=0.2, anchor='center')

        cve_button = ttk.Button(button_frame, text="CVE Scan", command=self.open_cve_scanner, width=button_width)
        cve_button.place(relx=0.5, rely=0.4, anchor='center')

        network_button = ttk.Button(button_frame, text="Network Scan", command=self.open_network_scanner, width=button_width)
        network_button.place(relx=0.5, rely=0.6, anchor='center')

        results_button = ttk.Button(button_frame, text="Scan Results", command=self.open_scan_results, width=button_width)
        results_button.place(relx=0.5, rely=0.8, anchor='center')

    def open_system_scan(self):
        assessment_window = tk.Toplevel(self.master)
        basic_assessment = VulnerabilityAssessment(assessment_window)

    def open_cve_scanner(self):
        cve_window = tk.Toplevel(self.master)
        cve_scanner_gui = CyberSeerGUI(cve_window, self.dummy_update_score)

    def dummy_update_score(self):
        # This method doesn't update any score, it's just a placeholder
        pass

    def open_network_scanner(self):
        network_window = tk.Toplevel(self.master)
        network_scanner_gui = NetworkScannerGUI(network_window)

    def open_scan_results(self):
        results_window = tk.Toplevel(self.master)
        results_window.title("CyberSeer - Scan Results")
        results_window.geometry("1000x600")
        results_window.configure(bg='#0a0e14')

        results = self.aggregate_results()
        ScanResultsGUI(results_window, results)

    def aggregate_results(self):
        results = {}
        score_files = {
            "system": "system_security_score.txt",
            "cve": "security_score.txt",
            "network": "network_score.txt"
        }

        for scan_type, file in score_files.items():
            if os.path.exists(file):
                with open(file, "r") as f:
                    score = f.read().strip()
                    results[scan_type] = {"score": float(score)}

        # Load detailed results
        if os.path.exists("system_scan_results.json"):
            with open("system_scan_results.json", "r") as f:
                results["system"]["details"] = json.load(f)

        if os.path.exists("temp_cve_results.json"):
            with open("temp_cve_results.json", "r") as f:
                results["cve"]["details"] = json.load(f)

        if os.path.exists("network_scan_results.json"):
            with open("network_scan_results.json", "r") as f:
                results["network"]["details"] = json.load(f)

        # Calculate overall score
        scores = [results[scan_type]["score"] for scan_type in results if "score" in results[scan_type]]
        if scores:
            results["overall"] = sum(scores) / len(scores)
        else:
            results["overall"] = "N/A"

        return results

    def update_background_size(self, event):
        # Resize the background image to fit the window size
        self.bg_image_resized = self.bg_image.resize((event.width, event.height), Image.LANCZOS)
        self.bg_photo = ImageTk.PhotoImage(self.bg_image_resized)
        self.bg_label.config(image=self.bg_photo)
        self.bg_label.image = self.bg_photo  # Prevent garbage collection of image

    def on_closing(self):
        self.cleanup()
        self.master.destroy()

    def cleanup(self):
        files_to_remove = [
            "network_score.txt",
            "security_score.txt",
            "subnet_scan_results.xml",
            "host_scan_results.xml",
            "system_security_score.txt",
            "live_hosts.xml",
            "temp_cve_results.json",
            "network_scan_results.json",
            "system_scan_results.json"
        ]
        for file in files_to_remove:
            if os.path.exists(file):
                os.remove(file)

        if os.path.exists("__pycache__"):
            shutil.rmtree("__pycache__")

class ScanResultsGUI:
    def __init__(self, master, results):
        self.master = master
        self.results = results
        self.chatgpt_api_key = self.load_chatgpt_api_key()
        self.assistant_id = "asst_MYrnWcPVLsSosSjFsnhvg4Ui"  # Your assistant ID
        self.create_widgets()

    def create_widgets(self):
        main_frame = tk.Frame(self.master, bg='#0a0e14')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Overall score
        overall_score = self.results.get("overall", "N/A")
        overall_label = tk.Label(main_frame, text=f"Overall Security Score: {overall_score:.2f}" if isinstance(overall_score, float) else f"Overall Security Score: {overall_score}", 
                                 font=("Courier", 18, "bold"), fg='#00ffff', bg='#0a0e14')
        overall_label.pack(pady=(0, 20))

        # Button frame
        button_frame = tk.Frame(main_frame, bg='#0a0e14')
        button_frame.pack(pady=(0, 20))

        # Insights button
        insights_button = ttk.Button(button_frame, text="Get Insights", command=self.get_insights)
        insights_button.pack(side='left', padx=(0, 10))

        # Export button
        export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        export_button.pack(side='left', padx=(0, 10))

        # Import ChatGPT API Key button
        import_key_button = ttk.Button(button_frame, text="Import ChatGPT API Key", command=self.import_chatgpt_api_key)
        import_key_button.pack(side='left')

        # Combined results table
        self.create_combined_table(main_frame)

    def create_combined_table(self, parent):
        tree = ttk.Treeview(parent, show='headings', style="Treeview")
        tree.pack(fill='both', expand=True)

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        scrollbar.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scrollbar.set)

        tree["columns"] = ("Scan Type", "Category", "Result", "Status")
        for col in tree["columns"]:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor='w')

        for scan_type, data in self.results.items():
            if scan_type != "overall" and "details" in data:
                score = data.get("score", "N/A")
                tree.insert('', 'end', values=(f"{scan_type.capitalize()} Scan", f"Score: {score}", "", ""), tags=('score',))
                for item in data["details"]:
                    if scan_type == "system":
                        tree.insert('', 'end', values=(scan_type.capitalize(), item[0], item[1], item[2]))
                    elif scan_type == "cve":
                        tree.insert('', 'end', values=(scan_type.upper(), f"{item[0]} {item[1]}", f"CVE: {item[2]}", f"Severity: {item[3]}"))
                    elif scan_type == "network":
                        tree.insert('', 'end', values=(scan_type.capitalize(), f"IP: {item[0]}, Port: {item[1]}", f"Service: {item[3]}", f"Criticality: {item[6]}"))

        tree.tag_configure('score', font=("Courier", 12, "bold"), foreground="#00ffff")

    def get_insights(self):
        if not self.chatgpt_api_key:
            messagebox.showerror("API Key Missing", "Please import a ChatGPT API key first.")
            return
        insights = self.call_chatgpt_api(self.results)
        self.show_insights(insights)

    def call_chatgpt_api(self, results):
        url = "https://api.openai.com/v1/threads/runs"
        headers = {
            "Authorization": f"Bearer {self.chatgpt_api_key}",
            "Content-Type": "application/json",
            "OpenAI-Beta": "assistants=v1"
        }
        
        # Create a new thread
        thread_response = requests.post(
            "https://api.openai.com/v1/threads",
            headers=headers
        )
        thread_id = thread_response.json()['id']
        
        # Add a message to the thread
        message_data = {
            "role": "user",
            "content": f"Analyze these scan results and provide insights and recommendations: {json.dumps(results)}"
        }
        requests.post(
            f"https://api.openai.com/v1/threads/{thread_id}/messages",
            headers=headers,
            json=message_data
        )
        
        # Run the assistant
        run_data = {
            "assistant_id": self.assistant_id,
            "instructions": "You are a cybersecurity expert analyzing scan results."
        }
        run_response = requests.post(
            f"https://api.openai.com/v1/threads/{thread_id}/runs",
            headers=headers,
            json=run_data
        )
        run_id = run_response.json()['id']
        
        # Wait for the run to complete
        while True:
            run_status_response = requests.get(
                f"https://api.openai.com/v1/threads/{thread_id}/runs/{run_id}",
                headers=headers
            )
            run_status = run_status_response.json()['status']
            if run_status == 'completed':
                break
            time.sleep(1)
        
        # Retrieve the messages
        messages_response = requests.get(
            f"https://api.openai.com/v1/threads/{thread_id}/messages",
            headers=headers
        )
        messages = messages_response.json()['data']
        
        # Return the last assistant message
        for message in messages:
            if message['role'] == 'assistant':
                return message['content'][0]['text']['value']
        
        return "No response from the assistant."

    def show_insights(self, insights):
        insights_window = tk.Toplevel(self.master)
        insights_window.title("CyberSeer - Scan Insights")
        insights_window.geometry("600x400")
        insights_window.configure(bg='#0a0e14')

        insights_text = tk.Text(insights_window, wrap=tk.WORD, bg='#0a0e14', fg='#00ffff', font=("Courier", 10))
        insights_text.pack(expand=True, fill='both', padx=20, pady=20)
        insights_text.insert(tk.END, insights)
        insights_text.config(state=tk.DISABLED)

    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.results, f, indent=4)
            messagebox.showinfo("Export Successful", f"Results exported to {file_path}")

    def import_chatgpt_api_key(self):
        if self.chatgpt_api_key:
            use_existing = messagebox.askyesno("API Key Found", "A ChatGPT API key was found. Do you want to use the existing key?")
            if use_existing:
                messagebox.showinfo("API Key", "Using existing ChatGPT API key.")
                return

        api_key = simpledialog.askstring("API Key", "Enter your ChatGPT API Key:", parent=self.master)
        if api_key:
            self.save_chatgpt_api_key(api_key)
            self.chatgpt_api_key = api_key
            messagebox.showinfo("API Key", "ChatGPT API key imported and saved successfully.")
        else:
            messagebox.showinfo("API Key", "ChatGPT API key import cancelled.")

    def save_chatgpt_api_key(self, key):
        with open("chatgpt_api_key.txt", "w") as f:
            f.write(key)

    def load_chatgpt_api_key(self):
        try:
            with open("chatgpt_api_key.txt", "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            return None

if __name__ == "__main__":
    root = tk.Tk()
    main_page = MainPage(root)
    root.mainloop()
