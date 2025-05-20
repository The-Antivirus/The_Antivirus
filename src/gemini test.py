import requests

API_KEY = "your_gemini_api_key"
API_URL = "https://gemini.example.com/api"  # Replace with the actual endpoint

def send_to_gemini(user_input):
    data = {"input": user_input}
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    
    response = requests.post(API_URL, json=data, headers=headers)
    
    if response.status_code == 200:
        result = response.json().get("response", "").lower()
        if "scan my device" in result:
            return "scan"
        return result
    else:
        return f"Error: {response.status_code} - {response.text}"

# Example usage
user_input = "Can you scan my device?"
response = send_to_gemini(user_input)
print(response)