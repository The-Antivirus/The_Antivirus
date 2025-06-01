import google.generativeai as genai
import queue
import sys # Added for printing to stderr

print("ai.py: Starting module initialization...")

try:
    # IMPORTANT: Replace "AIzaSyBTCuHASbyDTM0cUYb8oa3DQGP6POXYOyM" with your actual Google Gemini API key.
    # If this key is invalid or has issues, the program might still fail later when using the model.
    genai.configure(api_key="AIzaSyBTCuHASbyDTM0cUYb8oa3DQGP6POXYOyM")
    print("ai.py: Google Generative AI configured successfully.")
except Exception as e:
    print(f"ai.py ERROR: Failed to configure Google Generative AI: {e}", file=sys.stderr)
    # This error here is critical for AI functionality.
    # If AI is essential, you might want to exit or disable AI features.
    # For now, it will print and attempt to continue.

scan_results_queue = queue.Queue()

def add_to_queue(item):
    """Adds an item to the global scan results queue."""
    scan_results_queue.put(item)

def get_queue_contents():
    """Retrieves all items currently in the scan results queue."""
    contents = []
    while not scan_results_queue.empty():
        contents.append(scan_results_queue.get())
    return contents

def generate_prompt(prompt): # <-- THIS IS THE FUNCTION main.py IS LOOKING FOR
    """Generates an AI response or detects security suspicions from a user prompt."""
    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
    except Exception as e:
        print(f"ai.py ERROR: Failed to create GenerativeModel (check API key/network): {e}", file=sys.stderr)
        return "AI Error: Could not initialize AI model."

    suspicious_keywords = {
        "downloads": ["download folder", "suspicion of downloading", "downloaded file", "downloaded application", "download", "downloads", "install", "installed"],
        "running_file": ["running file", "suspicion of running process", "process running", "executable running", "active program", "running", "active"]
    }

    prompt_suspicions = queue.Queue()

    # Check for suspicious keywords in the user's prompt
    for suspicion, keywords in suspicious_keywords.items():
        if any(keyword in prompt.lower() for keyword in keywords):
            prompt_suspicions.put(suspicion)
            print(prompt_suspicions)

    # If suspicions are detected, signal them to the main program
    if not prompt_suspicions.empty():
        suspicion_list = ", ".join(list(prompt_suspicions.queue))
        return f"SUSPICION_DETECTED:{suspicion_list}"

    # Otherwise, generate a general AI response
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"ai.py ERROR: Error generating content from AI: {e}", file=sys.stderr)
        return f"AI Error: Could not generate content - {e}"

print("ai.py: Module initialization complete.")
