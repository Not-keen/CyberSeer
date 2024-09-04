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
import textwrap
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
        self.chatgpt_response = None  # Ensure it's None initially
        self.create_widgets()

    def load_chatgpt_response(self):
        try:
            with open("chatgpt_response.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

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

        # Import ChatGPT API Key button
        import_key_button = ttk.Button(button_frame, text="Import API Key", command=self.import_chatgpt_api_key)
        import_key_button.pack(side='left', padx=(0, 10))

        # Import Assistant ID button
        import_assistant_id_button = ttk.Button(button_frame, text="Import Assist. ID", command=self.import_assistant_id)
        import_assistant_id_button.pack(side='left', padx=(0, 10))

        # Get Recommendations button
        insights_button = ttk.Button(button_frame, text="Get Recommendations", command=self.get_insights)
        insights_button.pack(side='left', padx=(0, 10))

        # Export Results button
        export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        export_button.pack(side='left', padx=(0, 10))

        # Import Results button
        import_results_button = ttk.Button(button_frame, text="Import Results", command=self.import_results)
        import_results_button.pack(side='left')

        # Combined results table
        self.create_combined_table(main_frame)

    def create_combined_table(self, parent):
        style = ttk.Style()
        style.configure("Treeview", rowheight=60)  # Increase row height for wrapped text

        tree = ttk.Treeview(parent, show='headings', style="Treeview")
        tree.pack(fill='both', expand=True)

        scrollbar_y = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        scrollbar_y.pack(side='right', fill='y')
        scrollbar_x = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        scrollbar_x.pack(side='bottom', fill='x')
        tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        tree["columns"] = ("Scan Type", "Category", "Result", "Status", "Recommendation")
        column_widths = [100, 150, 200, 100, 400]
        for col, width in zip(tree["columns"], column_widths):
            tree.heading(col, text=col)
            tree.column(col, width=width, anchor='w')

        self.results_tree = tree  # Store the tree as an instance variable
        self.refresh_results_table()  # Populate the table

    def refresh_results_table(self):
        # Clear existing items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Repopulate with updated results
        for scan_type, data in self.results.items():
            if scan_type != "overall" and "details" in data:
                score = data.get("score", "N/A")
                self.results_tree.insert('', 'end', values=(f"{scan_type.capitalize()} Scan", f"Score: {score}", "", "", ""), tags=('score',))
                for item in data["details"]:
                    values = self.format_item_for_treeview(scan_type, item)

                    # Add ChatGPT recommendation if available
                    if self.chatgpt_response and scan_type in self.chatgpt_response:
                        recommendation = next((issue['recommendation'] for issue in self.chatgpt_response.get(scan_type, {}).get('issues', []) if issue['category'] == item[0]), "No specific recommendation")
                        values = values[:-1] + (recommendation,)
                    
                    self.results_tree.insert('', 'end', values=values)

        self.results_tree.tag_configure('score', font=("Courier", 12, "bold"), foreground="#00ffff")

    def format_item_for_treeview(self, scan_type, item):
        if scan_type == "system":
            return (scan_type.capitalize(), self.wrap_text(item[0], 20), self.wrap_text(item[1], 25), item[2], self.wrap_text(item[3] if len(item) > 3 else "", 50))
        elif scan_type == "cve":
            return (scan_type.upper(), self.wrap_text(f"{item[0]} {item[1]}", 20), self.wrap_text(f"CVE: {item[2]}", 25), f"Severity: {item[3]}", self.wrap_text(item[4] if len(item) > 4 else "", 50))
        elif scan_type == "network":
            category = self.wrap_text(f"IP: {item[0]}, Port: {item[1]}", 20)
            result = self.wrap_text(f"Service: {item[3]}, Protocol: {item[2]}", 25)
            return (scan_type.capitalize(), category, result, item[6], self.wrap_text(item[7] if len(item) > 7 else "", 50))

    def wrap_text(self, text, width):
        return '\n'.join(textwrap.wrap(str(text), width=width))

    def get_insights(self):
        if not self.chatgpt_api_key:
            messagebox.showerror("API Key Missing", "Please import a ChatGPT API key first.")
            return
        if not self.assistant_id:
            messagebox.showerror("Assistant ID Missing", "Please import an Assistant ID first.")
            return
        
        def run_insights():
            insights = self.call_chatgpt_api(self.results)
            self.master.after(0, lambda: self.update_results_with_insights(insights))
        
        threading.Thread(target=run_insights).start()

    def call_chatgpt_api(self, results):
        base_url = "https://api.openai.com/v1"
        headers = {
            "Authorization": f"Bearer {self.chatgpt_api_key.strip()}",
            "Content-Type": "application/json",
            "OpenAI-Beta": "assistants=v2"
        }

        try:
            # Step 1: Create a new thread
            thread_response = requests.post(
                f"{base_url}/threads",
                headers=headers
            )
            thread_response.raise_for_status()
            thread_id = thread_response.json()['id']
            print(f"Thread created with ID: {thread_id}")

            # Step 2: Add a message to the thread
            message_data = {
                "role": "user",
                "content": json.dumps(results)  # Only send the raw data without additional instructions
            }

            message_response = requests.post(
                f"{base_url}/threads/{thread_id}/messages",
                headers=headers,
                json=message_data
            )
            message_response.raise_for_status()
            print("Message added to thread")

            # Step 3: Run the assistant
            run_data = {
                "assistant_id": self.assistant_id,
                "response_format": {"type": "json_object"}
            }
            run_response = requests.post(
                f"{base_url}/threads/{thread_id}/runs",
                headers=headers,
                json=run_data
            )
            run_response.raise_for_status()
            run_id = run_response.json()['id']
            print(f"Run created with ID: {run_id}")

            # Step 4: Check the run status and retrieve the result
            while True:
                run_status_response = requests.get(
                    f"{base_url}/threads/{thread_id}/runs/{run_id}",
                    headers=headers
                )
                run_status_response.raise_for_status()
                run_status = run_status_response.json()['status']
                print(f"Run status: {run_status}")
                
                if run_status == 'completed':
                    messages_response = requests.get(
                        f"{base_url}/threads/{thread_id}/messages",
                        headers=headers
                    )
                    messages_response.raise_for_status()
                    messages = messages_response.json()['data']
                    
                    # Get the last assistant message
                    for message in reversed(messages):
                        if message['role'] == 'assistant':
                            response_content = json.loads(message['content'][0]['text']['value'])
                            
                            # Save the response to a file
                            with open("chatgpt_response.json", "w") as f:
                                json.dump(response_content, f, indent=4)
                            
                            print("Response saved to chatgpt_response.json")
                            return response_content
                    
                    return "No response from the assistant."
                elif run_status in ['failed', 'cancelled', 'expired']:
                    return f"Run failed with status: {run_status}"
                
                time.sleep(5)  # Wait for 5 seconds before checking again

        except requests.exceptions.RequestException as e:
            print(f"API request failed: {str(e)}")
            if hasattr(e.response, 'text'):
                print(f"Response content: {e.response.text}")
            return f"API request failed: {str(e)}"

    def update_results_with_insights(self, insights):
        if not isinstance(insights, dict):
            messagebox.showerror("Error", "Failed to get valid insights from ChatGPT.")
            return

        for scan_type in ['system', 'network']:
            if scan_type in insights and 'details' in insights[scan_type]:
                for i, item in enumerate(insights[scan_type]['details']):
                    if i < len(self.results[scan_type]['details']):
                        # Ensure that the recommendation is appended correctly
                        if isinstance(item, list) and len(item) > 3:
                            self.results[scan_type]['details'][i].append(item[3])  # Append recommendation
                        elif isinstance(item, dict) and 'recommendation' in item:
                            self.results[scan_type]['details'][i].append(item['recommendation'])
        
        self.refresh_results_table()
        self.show_insights("Insights added to the results table.")

    def show_insights(self, message):
        messagebox.showinfo("Insights", message)

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
                messagebox.showinfo("Import Successful", "Results imported successfully.")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import results: {str(e)}")

    def import_chatgpt_api_key(self):
        if self.chatgpt_api_key:
            use_existing = messagebox.askyesno("API Key Found", "A ChatGPT API key was found. Do you want to use the existing key?")
            if use_existing:
                messagebox.showinfo("API Key", "Using existing ChatGPT API key.")
                return

        api_key = simpledialog.askstring("API Key", "Enter your ChatGPT API Key:", parent=self.master)
        if api_key:
            api_key = api_key.strip()  # Remove any leading/trailing whitespace
            self.save_chatgpt_api_key(api_key)
            self.chatgpt_api_key = api_key
            messagebox.showinfo("API Key", "ChatGPT API key imported and saved successfully.")
        else:
            messagebox.showinfo("API Key", "ChatGPT API key import cancelled.")

    def import_assistant_id(self):
        if self.assistant_id:
            use_existing = messagebox.askyesno("Assistant ID Found", "An Assistant ID was found. Do you want to use the existing ID?")
            if use_existing:
                messagebox.showinfo("Assistant ID", "Using existing Assistant ID.")
                return

        assistant_id = simpledialog.askstring("Assistant ID", "Enter your Assistant ID:", parent=self.master)
        if assistant_id:
            assistant_id = assistant_id.strip()  # Remove any leading/trailing whitespace
            self.save_assistant_id(assistant_id)
            self.assistant_id = assistant_id
            messagebox.showinfo("Assistant ID", "Assistant ID imported and saved successfully.")
        else:
            messagebox.showinfo("Assistant ID", "Assistant ID import cancelled.")

    def save_chatgpt_api_key(self, key):
        with open("chatgpt_api_key.txt", "w") as f:
            f.write(key)

    def load_chatgpt_api_key(self):
        try:
            with open("chatgpt_api_key.txt", "r") as f:
                api_key = f.read().strip()
                print(f"Loaded ChatGPT API Key: {api_key[:5]}...{api_key[-5:]}")  # Debug print
                return api_key
        except FileNotFoundError:
            print("ChatGPT API Key file not found")  # Debug print
            return None

    def save_assistant_id(self, assistant_id):
        with open("assistant_id.txt", "w") as f:
            f.write(assistant_id)

    def load_assistant_id(self):
        try:
            with open("assistant_id.txt", "r") as f:
                assistant_id = f.read().strip()
                print(f"Loaded Assistant ID: {assistant_id}")  # Debug print
                return assistant_id
        except FileNotFoundError:
            print("Assistant ID file not found")  # Debug print
            return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    root = tk.Tk()
    main_page = MainPage(root)
    root.mainloop()

