import json
import requests
import os
from langgraph.graph import START, END, StateGraph
from typing_extensions import TypedDict
import sys
from IPython.display import Image

API_KEY = "API KEY"   
 
def take_parameter_from_File(Content, Key_Value):
    if isinstance(Content, dict):
        for k, v in Content.items():
            if k == Key_Value:
                return v
            else:
                res= take_parameter_from_File(v, Key_Value)
                if res is not None:
                    return res
                
    elif isinstance(Content,list):
        for itm in Content:
            res= take_parameter_from_File(itm, Key_Value)
            if res is not None:
                return res

    else: 
        return None
    
def Error_Handle_API(url, header):
    try:
        response = requests.get(url, headers=header, timeout=10)
        if response.status_code ==200:
            return response.json()
        elif response.status_code ==401:
            return {"Error: " : "Invalid API Key"}
        elif response.status_code ==429:
            return {"Error: ", "Rate Limit Exceeded, Try again later."}
        else:
            return {"Error: ": f"Unexpected Status Code: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"Error: ": f"Error: {e}"}
    

class mystate(TypedDict):
    filename : str
    Msg: str
    Data : dict
    IP: str
    HASH: str
    ipscore: dict
    hashscore: dict


def ProcessFile(state: mystate):
    if len(sys.argv)< 2:
        return {"Msg" : "File is not given."}
    elif len(sys.argv)==2:
        filename = sys.argv[1]
        if filename.endswith(".json"):
            if os.path.exists(filename):
                return {"filename" : filename}
            else:
                return {"Msg" : "File doesn't exist."}
        else: 
            return {"Msg" : "File is not Json."}
    else: 
        return {"Msg": "Too many Files."}


def ReadJsonFile(state: mystate):
    Filename= state["filename"]
    try:
        with open (Filename, "r") as f:
            data=json.load(f)
            # print(data)
            return {"Data" : data}
    except json.JSONDecodeError:
        return {"Msg": "File Contents are not in Json."}
    
def Extract_parameters(state: mystate):
    data=state['Data']
    result={}
    ip_value=take_parameter_from_File(data, 'ip')
    hash_value=take_parameter_from_File(data, 'hash')
    if ip_value is not None:
        result["IP"]= ip_value
    if hash_value is not None:
        result["HASH"]= hash_value

    return result  

def IP_score(state: mystate):
    print("Running IP scoring...")
    ip_add=state.get("IP")
    print(ip_add)
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_add}'

    headers = {
    "accept": "application/json", 
    "x-apikey": API_KEY}
    data= Error_Handle_API(url, headers)
    # response = requests.get(url, headers=headers)
    if "Error" in data:
        return {"Msg" : data["Error"]}
    
    # data = json.loads(response.content)
    score = data["data"]["attributes"]["last_analysis_stats"]
    # print("VirusTotal Score:", score)
    return {"ipscore" : score}


def Hash_Score(state: mystate):
    print("Running Hash scoring...")
    hash_val=state.get("HASH")
    print(hash_val)

    url = f'https://www.virustotal.com/api/v3/files/{hash_val}'

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY}
    data= Error_Handle_API(url, headers)
    # response = requests.get(url, headers=headers)
    if "Error" in data:
        return {"Msg" : data["Error"]}
    
    score = data["data"]["attributes"]["last_analysis_stats"]
    # print("VirusTotal Score:", score)
    return {"hashscore" : score}

def Not_Found(state: mystate):
    # print("Neither IP nor Hash given.")
    return {"Msg": "IP and Hash Values not find in json file."}

def Source_Route(state: mystate):
    if state.get("IP") and state.get("HASH"):
        return "IP_score"
    elif state.get("IP"):
        return "IP_score"
    elif state.get("HASH"):
        return "Hash_Score"
    else:
        return "Not_Found"

def route_process_file(state: mystate):
    if "Msg" in state:
        return END       
    return "read_json"


def route_json_file(state: mystate):
    if "Msg" in state:
        return END       
    return "Extract_parameters"





graph = StateGraph(mystate)

# Add nodes
graph.add_node("process_file", ProcessFile)
graph.add_node("read_json", ReadJsonFile)
graph.add_node("Extract_parameters", Extract_parameters)
graph.add_node("IP_score", IP_score)
graph.add_node("Hash_Score", Hash_Score)
graph.add_node("Not_Found", Not_Found)

graph.add_edge(START, "process_file")
# Edges

graph.add_conditional_edges(
    "process_file", 
    route_process_file, 
    {"read_json": "read_json", END: END}
)

graph.add_conditional_edges(
    "read_json", 
    route_json_file, 
    {"Extract_parameters": "Extract_parameters", END: END}
)

graph.add_conditional_edges(
    "Extract_parameters",
    Source_Route,
    {
        "IP_score": "IP_score",
        "Hash_Score": "Hash_Score",
        "Not_Found": "Not_Found"
    }
)

graph.add_conditional_edges(
    "IP_score",
    lambda state: "Hash_Score" if state.get("HASH") else END,
    {
        "Hash_Score": "Hash_Score",
        END: END
    }
)
graph.add_edge("Hash_Score", END)
graph.add_edge("IP_score", END)
graph.add_edge("Not_Found", END)


# Compile the graph
app = graph.compile()

if __name__ == "__main__":
    result = app.invoke({})
    # print("Result: ", result)
    if result.get("Msg"):
        print("Message: ", result["Msg"])

    else: 
        if result.get("ipscore"):
            print("IP_Score: ", result["ipscore"])
        if result.get("hashscore"):
            print("Hash_Score: ", result["hashscore"])
    # print("Final State:", result.get("ipscore"), result.get("hashscore"))
    png_bytes = app.get_graph().draw_mermaid_png()
    with open("graph.png", "wb") as f:
        f.write(png_bytes)

    # print("Graph saved as graph.png")
    # display(Image(app.get_graph().draw_mermaid_png()))
