# Assignment_LangGraph

**JSON Threat Analyzer with VirusTotal API**

This project is a state-driven threat analyzer built using LangGraph.
It takes a JSON file as input, extracts IP addresses and hash values, and checks their reputation using the VirusTotal API.
The flow is modeled as a graph of states for better modularity and debugging.

📌 **Features**
  - ✅ Validates JSON file input.
  - ✅ Extracts ip and hash values automatically from nested JSON.
  - ✅ Queries VirusTotal API for IP and File Hash reputation.
  - ✅ Handles errors (invalid API key, rate limits, wrong input).
  - ✅ Graph visualization of processing pipeline.



🚀 **Usage**

Run the program with a JSON file as input:

python main.py sample.json

Example JSON
{
  "file": {
    "metadata": {
      "ip": "8.8.8.8",
      "hash": "44d88612fea8a8f36de82e1278abb02f"
    }
  }
}

**Output Example**
Running IP scoring...
IP_Score: {'malicious': 0, 'undetected': 72, 'harmless': 10}
Running Hash scoring...
Hash_Score: {'malicious': 5, 'undetected': 65, 'harmless': 12}


If file is invalid:
  Message: File doesn't exist.

**Graph Visualization**  
After running, the project saves a graph of the state machine:
  graph.png


Example Graph:
Process file → Read JSON → Extract Parameters → Score (IP/Hash) → End

🛡️ **Error Handling**
- Invalid API Key (401): returns "Invalid API Key"
- Rate Limiting (429): returns "Rate limit exceeded, try again later"
- Wrong/Corrupt JSON: returns "File contents are not in JSON"
