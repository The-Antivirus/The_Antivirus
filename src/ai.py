import google.generativeai as genai
import queue
import sys # Added for printing to stderr

print("ai.py: Starting module initialization...")

try:
    # IMPORTANT: Replace with your actual Google Gemini API key.
    genai.configure(api_key="AIzaSyD6NtJM4EiXdGUPxCH7KY5f6_4k3Yglfxs")
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

def generate_prompt(prompt):
    """
    Uses Gemini AI to decide if a folder or running processes should be scanned based on the user prompt.
    If so, returns 'SCAN_FOLDER:<absolute_path>' or 'SCAN_PROCESSES'.
    Otherwise, returns the AI's normal response.
    """
    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
    except Exception as e:
        print(f"ai.py ERROR: Failed to create GenerativeModel (check API key/network): {e}", file=sys.stderr)
        return "AI Error: Could not initialize AI model."

    # Update system instruction to include SCAN_PROCESSES response
    system_instruction = (
        "You are an antivirus assistant. If the user's prompt suggests scanning a specific folder, "
        "respond ONLY with: SCAN_FOLDER:<absolute_path> (e.g., SCAN_FOLDER:C:/Users/username/Downloads). "
        "If the user's prompt suggests scanning all running processes for malware, respond ONLY with: SCAN_PROCESSES. "
        "If no scan is needed, respond with a helpful message or answer as usual. Do not explain the scan commands."
    )
    try:
        response = model.generate_content(f"{system_instruction}\nUser prompt: {prompt}")
        return response.text.strip()
    except Exception as e:
        print(f"ai.py ERROR: Error generating content from AI: {e}", file=sys.stderr)
        return f"AI Error: Could not generate content - {e}"

print("ai.py: Module initialization complete.")
