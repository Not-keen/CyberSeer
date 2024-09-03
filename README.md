# CyberSeer
CyberSeer - Lightweight, automated Linux Security Scanner

SEE **IMPORTANT** NOTICE AT THE BOTTOM

Dependancies - 
1. Install Python 3

Some Linux Distro's come with Python 3 pre-installed. You can check if Python 3 is installed by running:

python3 --version

If it's not installed or you are on another flavour of Linux, you can install it using:

	sudo apt update
	sudo apt install python3


2. Install Pip for Python 3

Ensure that pip (Python package manager) is installed:

	sudo apt install python3-pip



3. Install Tkinter

tkinter is the standard Python interface to the Tk GUI toolkit. To install tkinter for Python 3:

	sudo apt install python3-tk



4. Install Python Imaging Library (Pillow) and ImageTk

Pillow is a fork of the Python Imaging Library (PIL) and is the most common library for opening, manipulating, and saving many different image file formats. ImageTk is part of the Pillow package, so installing Pillow also covers ImageTk.

To install Pillow:

	sudo apt install python3-pil

For ImageTk support, ensure Pillow is up to date:

	sudo pip3 install --upgrade Pillow



5. Install the packaging module

The packaging module provides core utilities for Python packages. If you're working in an environment that supports apt package installation:

	sudo apt install python3-packaging

Or, if you use a virtual environment:
Create a virtual environment:

	python3 -m venv myenv

Activate the virtual environment:

	source myenv/bin/activate

Install packaging inside the virtual environment:

    pip install packaging
    
    

6. Set Up a Virtual Environment (Optional but Recommended)

To avoid conflicts with system packages and maintain a clean environment:

python3 -m venv env_name
source env_name/bin/activate

Once inside the virtual environment, install your packages as needed:

	pip install Pillow packaging
	
	
	
You are now good to go. Navigate to the CyberSeer Folder and run the following command:

	python3 main_page.py



** IMPORTANT**
 You will need a valid NIST API key for the CVE scanner to work. you can get one from here https://nvd.nist.gov/developers/request-an-api-key
 
 ALSO
 
 For the result "Insights" to work you will need a ChatGPT API key. You can either message me for a key to my Assistant, or, better yet, make your own here https://platform.openai.com. 
 
This is the prompt I used for the ChatGPT Assistant -
 
"You are to receive a list of found vulnerabilities from a Linux system and you are to very concisely comment on what should be done about each vulnerability,   if anything. Some results may be benign or informational. Each comment should be returned in the same format as the data you receive."
