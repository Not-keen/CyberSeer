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
import threading
import logging
import traceback
import textwrap
import time
import match_cve

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
        scan_results_gui = ScanResultsGUI(results_window, results)

    def aggregate_results(self):
        results = {}
        score_files = {
            "system": "system_security_score.txt",
            "cve": "security_score.txt",
            "network": "network_score.txt"
        }

        for scan_type, file in score_files.items():
            if os.path.exists(file):
                try:
                    with open(file, "r") as f:
                        score = f.read().strip()
                        results[scan_type] = {"score": float(score)}
                except ValueError as e:
                    print(f"Error reading score from {file}: {e}")
                    results[scan_type] = {"score": "N/A"}

        # Load detailed results
        detailed_results_files = {
            "system": "system_scan_results.json",
            "cve": "temp_cve_results.json",
            "network": "network_scan_results.json"
        }

        for scan_type, file in detailed_results_files.items():
            if os.path.exists(file):
                try:
                    with open(file, "r") as f:
                        data = json.load(f)
                        if scan_type in results:
                            results[scan_type]["details"] = data
                        else:
                            results[scan_type] = {"details": data, "score": "N/A"}
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON from {file}: {e}")
                    results[scan_type] = results.get(scan_type, {})
                    results[scan_type]["details"] = []

        # Calculate overall score
        valid_scores = [results[scan_type]["score"] for scan_type in results 
                        if "score" in results[scan_type] and isinstance(results[scan_type]["score"], (int, float))]
        if valid_scores:
            results["overall"] = sum(valid_scores) / len(valid_scores)
        else:
            results["overall"] = "N/A"

        return results

    def update_background_size(self, event):
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
            "system_scan_results.json",
            "temp_chatgpt_results.json",
            "chatgpt_response.json"
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
        self.assistant_id = self.load_assistant_id()
        self.chatgpt_response = None
        self.create_widgets()

    def create_widgets(self):
        main_frame = tk.Frame(self.master, bg='#0a0e14')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        overall_score = self.calculate_overall_score()
        self.score_label = tk.Label(main_frame, 
                                    text=f"Overall Security Score: {overall_score:.2f}" if isinstance(overall_score, float) else f"Overall Security Score: {overall_score}", 
                                    font=("Courier", 18, "bold"), fg='#00ffff', bg='#0a0e14')
        self.score_label.pack(pady=(0, 20))

        button_frame = tk.Frame(main_frame, bg='#0a0e14')
        button_frame.pack(pady=(0, 20))

        import_key_button = ttk.Button(button_frame, text="Import API Key", command=self.import_chatgpt_api_key)
        import_key_button.pack(side='left', padx=(0, 10))

        import_assistant_id_button = ttk.Button(button_frame, text="Import Assist. ID", command=self.import_assistant_id)
        import_assistant_id_button.pack(side='left', padx=(0, 10))

        insights_button = ttk.Button(button_frame, text="Get Recommendations", command=self.get_insights)
        insights_button.pack(side='left', padx=(0, 10))

        export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        export_button.pack(side='left', padx=(0, 10))

        import_results_button = ttk.Button(button_frame, text="Import Results", command=self.import_results)
        import_results_button.pack(side='left')

        self.create_combined_table(main_frame)
        self.refresh_results_table()

    def create_combined_table(self, parent):
        style = ttk.Style()
        style.configure("Treeview", rowheight=80)
        style.configure("Title.Treeview.Row", font=("Courier", 12, "bold"), background="#1a1f29", foreground="#00ffff")

        tree = ttk.Treeview(parent, columns=("Software/Category", "Result/Version", "Status/Severity", "Recommendation"), 
                            show='headings', style="Treeview")
        tree.pack(fill='both', expand=True)

        scrollbar_y = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        scrollbar_y.pack(side='right', fill='y')
        scrollbar_x = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        scrollbar_x.pack(side='bottom', fill='x')
        tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        column_widths = [200, 200, 150, 350]
        for col, width in zip(tree["columns"], column_widths):
            tree.heading(col, text=col)
            tree.column(col, width=width, anchor='w')

        self.results_tree = tree

    def refresh_results_table(self):
        self.results_tree.delete(*self.results_tree.get_children())

        for scan_type, data in self.results.items():
            if scan_type != "overall" and isinstance(data, dict) and "details" in data:
                score = data.get("score", "N/A")
                title = f"{scan_type.capitalize()} Scan (Score: {score})" if scan_type.lower() != "cve" else f"CVE Scan (Score: {score})"
                self.results_tree.insert('', 'end', values=(title, "", "", ""), tags=('title',))
                for item in data["details"]:
                    values = self.format_item_for_treeview(scan_type, item)
                    self.results_tree.insert('', 'end', values=values)

        self.results_tree.tag_configure('title', font=("Courier", 12, "bold"), background="#1a1f29", foreground="#00ffff")

    def calculate_overall_score(self):
        valid_scores = [self.results[scan_type]["score"] for scan_type in self.results 
                        if isinstance(self.results[scan_type], dict) and 
                        "score" in self.results[scan_type] and 
                        isinstance(self.results[scan_type]["score"], (int, float))]
        if valid_scores:
            return sum(valid_scores) / len(valid_scores)
        return "N/A"

    def update_overall_score(self):
        overall_score = self.calculate_overall_score()
        self.score_label.config(text=f"Overall Security Score: {overall_score:.2f}" if isinstance(overall_score, float) else f"Overall Security Score: {overall_score}")

    def format_item_for_treeview(self, scan_type, item):
        if scan_type == "system":
            return (item[0], item[1], item[2], self.wrap_text(item[3] if len(item) > 3 else "", 60))
        elif scan_type == "cve":
            severity = item[3].replace("Severity: ", "") if isinstance(item[3], str) else item[3]
            recommendation = item[4] if len(item) > 4 else ""
            return (f"{item[0]} {item[1]}", item[2], severity, self.wrap_text(recommendation, 60))
        elif scan_type == "network":
            status = item[6] if len(item) > 6 else ""
            recommendation = item[7] if len(item) > 7 else ""
            return (f"IP: {item[0]}, Port: {item[1]}", f"Service: {item[2]}, Protocol: {item[3]}", 
                    status, self.wrap_text(recommendation, 60))
        else:
            return (scan_type.capitalize(), "", "", "")

    def wrap_text(self, text, width):
        return '\n'.join(textwrap.wrap(str(text), width=width))

    def load_chatgpt_api_key(self):
        try:
            with open("chatgpt_api_key.txt", "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            return None

    def load_assistant_id(self):
        try:
            with open("assistant_id.txt", "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            return None

    def import_chatgpt_api_key(self):
        api_key = simpledialog.askstring("API Key", "Enter your ChatGPT API Key:", parent=self.master)
        if api_key:
            self.chatgpt_api_key = api_key.strip()
            self.save_chatgpt_api_key(self.chatgpt_api_key)
            messagebox.showinfo("API Key", "ChatGPT API key imported and saved successfully.")
        else:
            messagebox.showinfo("API Key", "ChatGPT API key import cancelled.")

    def import_assistant_id(self):
        assistant_id = simpledialog.askstring("Assistant ID", "Enter your Assistant ID:", parent=self.master)
        if assistant_id:
            self.assistant_id = assistant_id.strip()
            self.save_assistant_id(self.assistant_id)
            messagebox.showinfo("Assistant ID", "Assistant ID imported and saved successfully.")
        else:
            messagebox.showinfo("Assistant ID", "Assistant ID import cancelled.")

    def save_chatgpt_api_key(self, key):
        with open("chatgpt_api_key.txt", "w") as f:
            f.write(key)

    def save_assistant_id(self, assistant_id):
        with open("assistant_id.txt", "w") as f:
            f.write(assistant_id)

    def log_data(self, filename, data):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

    def get_insights(self):
        if not self.chatgpt_api_key or not self.assistant_id:
            messagebox.showerror("Missing Credentials", "Please import both API Key and Assistant ID first.")
            return

        filtered_results = {k: v for k, v in self.results.items() if k != 'overall'}
        self.log_data('sent_data_to_assistant.json', filtered_results)

        def run_insights():
            try:
                insights = self.call_chatgpt_api(filtered_results)
                self.log_data('received_data_from_assistant.json', insights)

                if insights:
                    self.results = self.merge_insights(self.results, insights)
                    self.master.after(0, self.refresh_results_table)
            except Exception as e:
                error_message = f"An error occurred while getting insights: {str(e)}\n\nType: {type(e)}\n\nFull traceback:"
                error_message += "\n" + traceback.format_exc()
                messagebox.showerror("Error", error_message)
                print(error_message)

        threading.Thread(target=run_insights).start()

    def merge_insights(self, original_data, insights_data):
        for scan_type, data in insights_data.items():
            if scan_type == "overall":
                original_data["overall"] = data
                continue

            if scan_type in original_data and isinstance(data, dict) and "details" in data and "details" in original_data[scan_type]:
                for i, item in enumerate(data["details"]):
                    if i < len(original_data[scan_type]["details"]):
                        if isinstance(item, list) and isinstance(original_data[scan_type]["details"][i], list):
                            original_data[scan_type]["details"][i].append(item[-1])
        return original_data

    def call_chatgpt_api(self, results):
        base_url = "https://api.openai.com/v1"
        headers = {
            "Authorization": f"Bearer {self.chatgpt_api_key}",
            "Content-Type": "application/json",
            "OpenAI-Beta": "assistants=v2"
        }

        try:
            thread_response = requests.post(f"{base_url}/threads", headers=headers)
            thread_response.raise_for_status()
            thread_id = thread_response.json()['id']

            message_data = {
                "role": "user",
                "content": json.dumps(results)
            }
            message_response = requests.post(
                f"{base_url}/threads/{thread_id}/messages",
                headers=headers,
                json=message_data
            )
            message_response.raise_for_status()

            run_data = {
                "assistant_id": self.assistant_id
            }
            run_response = requests.post(
                f"{base_url}/threads/{thread_id}/runs",
                headers=headers,
                json=run_data
            )
            run_response.raise_for_status()
            run_id = run_response.json()['id']

            while True:
                run_status_response = requests.get(
                    f"{base_url}/threads/{thread_id}/runs/{run_id}",
                    headers=headers
                )
                run_status_response.raise_for_status()
                run_status = run_status_response.json()['status']

                if run_status == 'completed':
                    messages_response = requests.get(
                        f"{base_url}/threads/{thread_id}/messages",
                        headers=headers
                    )
                    messages_response.raise_for_status()
                    messages = messages_response.json()['data']

                    for message in reversed(messages):
                        if message['role'] == 'assistant':
                            content = message['content'][0]['text']['value']
                            return json.loads(content)

                    return {"response": "No response from the assistant."}

                elif run_status in ['failed', 'cancelled', 'expired']:
                    raise Exception(f"Run failed with status: {run_status}")

                time.sleep(5)

        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {str(e)}")

    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.results, f, indent=4)
            messagebox.showinfo("Export Successful", f"Results exported to {file_path}")

    def import_results(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    imported_results = json.load(f)
                self.results = imported_results
                self.refresh_results_table()
                self.update_overall_score()
                messagebox.showinfo("Import Successful", "Results imported successfully.")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import results: {str(e)}")

    def handle_error(self, error_message):
        messagebox.showerror("Error", error_message)
        print(f"Error: {error_message}")

    def validate_results(self, results):
        required_keys = ["system", "cve", "network"]
        for key in required_keys:
            if key not in results:
                raise ValueError(f"Missing '{key}' data in results")
            if not isinstance(results[key], dict) or "score" not in results[key] or "details" not in results[key]:
                raise ValueError(f"Invalid format for '{key}' data in results")
        return True

    def update_single_scan_score(self, scan_type, new_score):
        if scan_type in self.results and isinstance(self.results[scan_type], dict):
            self.results[scan_type]["score"] = new_score
            self.update_overall_score()
            self.refresh_results_table()
        else:
            self.handle_error(f"Invalid scan type: {scan_type}")

    def get_scan_score(self, scan_type):
        if scan_type in self.results and isinstance(self.results[scan_type], dict):
            return self.results[scan_type].get("score", "N/A")
        else:
            self.handle_error(f"Invalid scan type: {scan_type}")
            return "N/A"


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    root = tk.Tk()
    main_page = MainPage(root)
    root.mainloop()

