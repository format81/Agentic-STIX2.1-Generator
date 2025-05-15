# app.py
import streamlit as st
import autogen
from autogen import AssistantAgent, UserProxyAgent, Agent
import os
import json
import stix2
from stix2 import Identity, Indicator, Relationship, Bundle
from stix2.base import _STIXBase
from datetime import datetime
import time # Kept as it was in the original
import re # Ensure re is imported at the top
import uuid
from dotenv import load_dotenv
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import PyPDF2
import io # Kept as it was in the original
from urllib.parse import urlparse
import markitdown

# Load .env from the same directory as the script
env_path = Path(__file__).resolve().parent / "my.env"
load_dotenv(dotenv_path=env_path)


# Safe version of UserProxyAgent to avoid executing JSON, YAML, STIX
class SafeUserProxyAgent(UserProxyAgent):
    def run_code(self, code, **kwargs):
        """
        Override run_code to:
         1) Strip out markdown code fences labeled ```json``` (or generic ```…```).
         2) Treat any pure JSON or YAML content as non-executable.
         3) Otherwise, pass cleaned code to the parent implementation.
        """
        # 1. Rimuovi blocchi ```json ... ``` o anche generici ```
        cleaned = re.sub(r'```(?:json)?\s*(.*?)\s*```', r'\1', code, flags=re.DOTALL).strip()

        # 2. Se il testo pulito inizia con { o [, lo consideriamo JSON/YAML non eseguibile
        first_char = cleaned[:1]
        if first_char in ('{', '['):
            # Optionally, validate if it's actual JSON before returning
            try:
                json.loads(cleaned) # Check if it's valid JSON
                return 0, "Non-executable content (JSON/YAML detected and validated)", None
            except json.JSONDecodeError:
                 # If not valid JSON but starts with { or [, still treat as non-executable text
                return 0, "Non-executable content (potential JSON/YAML detected, but invalid format)", None


        # 3. Altrimenti, passa al super con il codice ripulito
        #    Rimuovi eventuali kwargs non supportati
        supported_kwargs = {k: v for k, v in kwargs.items() if k not in ['non_executable_languages']}
        # st.warning(f"SafeUserProxyAgent allowing execution of code: {cleaned[:100]}...") # For debugging
        return super().run_code(cleaned, **supported_kwargs)


# Set the page configuration
st.set_page_config(
    page_title="Agentic STIX 2.1 Generator",
    page_icon="🛡️",
    layout="wide"
)

# App title and description
st.title("🛡️ Agentic GenAI STIX 2.1 Generator")
st.markdown("""
This application uses AI agents to help you generate STIX 2.1 content.
You can describe a threat intelligence scenario, process a web threat report, or upload a PDF file.
""")

# Add mode selection to the sidebar
st.sidebar.title("Generation Mode")
mode = st.sidebar.radio(
    "Select generation mode:",
    ["Standard", "Advanced (Multi-Agent)"],
    help="Standard mode uses basic agents. Advanced mode uses specialized agents for different STIX object types."
)

if mode == "Advanced (Multi-Agent)":
    st.sidebar.info("""
    Advanced mode uses a pipeline of specialized agents:
    1. Orchestrator - Plans the generation process
    2. TI Analyst - Analyzes the scenario
    3. SDO Specialist - Creates domain objects
    4. SCO Specialist - Creates cyber observables
    5. Pattern Specialist - Creates indicator patterns
    6. SRO Specialist - Creates relationships
    7. Validator - Ensures STIX compliance
    """)

# Initialize session state variables if they don't exist
if 'stix_objects' not in st.session_state:
    st.session_state.stix_objects = []
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'bundle' not in st.session_state:
    st.session_state.bundle = None
if 'agents_initialized' not in st.session_state:
    st.session_state.agents_initialized = False
if 'advanced_agents_initialized' not in st.session_state:
    st.session_state.advanced_agents_initialized = False
if 'advanced_agents' not in st.session_state: # Ensure advanced_agents key exists
    st.session_state.advanced_agents = {}
if 'advanced_conversations' not in st.session_state:
    st.session_state.advanced_conversations = {}

# --- Helper function to clean agent responses for JSON parsing ---
def _clean_agent_json_response(response_text: str) -> str:
    """
    Cleans the agent's response by:
    1. Extracting content from markdown JSON code fences if present.
    2. Removing the TERMINATE signal from the extracted (or original) content.
    3. Stripping leading/trailing whitespace from the final content.
    """
    if not isinstance(response_text, str):
        return ""

    # Step 1: Extract content from markdown fences (if any)
    # This prioritizes content within fences if they exist.
    match = re.search(r'```(?:json)?\s*(.*?)\s*```', response_text, re.DOTALL)
    content_to_clean = match.group(1) if match else response_text
    
    # Step 2: Remove TERMINATE signal from this 'content_to_clean'
    # Try to remove it if it's on its own line at the end of this content.
    lines = content_to_clean.splitlines()
    if lines and lines[-1].strip().upper() == "TERMINATE":
        final_content_before_strip = "\n".join(lines[:-1])
    else:
        # Fallback: remove TERMINATE if it's at the very end of content_to_clean,
        # possibly with whitespace before it but nothing after.
        # Using re.DOTALL with $ ensures it matches the true end of the string.
        final_content_before_strip = re.sub(r'TERMINATE\s*$', '', content_to_clean, flags=re.IGNORECASE | re.DOTALL)
            
    # Step 3: Strip leading/trailing whitespace from the final content
    return final_content_before_strip.strip()
# --- End of helper function ---


# Function to create a UUID for STIX objects
def generate_stix_id(object_type):
    return f"{object_type}--{str(uuid.uuid4())}"

# Function to extract content from web page
def extract_web_content(url):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return None, "Invalid URL. Please provide a complete URL including http:// or https://"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        for tag in soup(['script', 'style', 'header', 'footer', 'nav', 'aside']):
            tag.decompose()
        
        title = soup.title.string if soup.title else "Web Content"
        
        content_tags = soup.find_all(['article', 'main', 'div.content', 'div.article'])
        if content_tags:
            text = " ".join([tag.get_text(separator=' ', strip=True) for tag in content_tags])
        else:
            text = soup.body.get_text(separator=' ', strip=True) if soup.body else ""
        
        processed_text = clean_text(text)
        return f"Title: {title}\n\n{processed_text}", None
    except requests.exceptions.RequestException as e:
        return None, f"Error fetching URL: {str(e)}"
    except Exception as e:
        return None, f"Error processing web content: {str(e)}"

def clean_text(text):
    text = re.sub(r'\n+', '\n', text)
    text = re.sub(r' +', ' ', text)
    return text.strip()

def extract_pdf_content(pdf_file):
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            page_content = page.extract_text()
            if page_content: # Ensure text was extracted
                 text += page_content + "\n"
        
        processed_text = markitdown.markitdown(text) if text else "" # Original logic
        return processed_text, None
    except Exception as e:
        return None, f"Error processing PDF file: {str(e)}"

def verify_azure_openai_settings():
    required_vars = [
        "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", 
        "AZURE_OPENAI_DEPLOYMENT_NAME", "AZURE_OPENAI_API_VERSION"
    ]
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    if missing_vars:
        st.error(f"Missing required Azure OpenAI environment variables: {', '.join(missing_vars)}")
        st.error("Please set these in your .env file or environment.")
        return False
    return True

def initialize_agents():
    if not verify_azure_openai_settings():
        st.stop()

    llm_config = {
        "model": os.environ["AZURE_OPENAI_DEPLOYMENT_NAME"], "api_type": "azure",
        "api_key": os.environ["AZURE_OPENAI_API_KEY"], "base_url": os.environ["AZURE_OPENAI_ENDPOINT"],
        "api_version": os.environ["AZURE_OPENAI_API_VERSION"],
        "timeout": 60 # Added a timeout for standard agents too
    }

    ti_expert = AssistantAgent(
        name="ThreatIntelligenceExpert", llm_config=llm_config,
        system_message="""You are a threat intelligence expert who specializes in creating STIX 2.1 content.
        Your job is to analyze threat scenarios and convert them into appropriate STIX objects.
        Focus on technical accuracy and adherence to the STIX 2.1 standard."""
    )
    stix_formatter = AssistantAgent(
        name="STIXFormatter", llm_config=llm_config,
        system_message="""You are a STIX 2.1 specialist who converts threat information into valid STIX JSON.
        You ensure that all STIX objects have required fields and follow the proper format.
        You only output valid STIX 2.1 JSON that can be parsed by the stix2 Python library."""
    )
    user_proxy = SafeUserProxyAgent(
        name="UserProxy", human_input_mode="NEVER", max_consecutive_auto_reply=30,
        is_termination_msg=lambda x: "TERMINATE" in x.get("content", "").upper(),
        code_execution_config={"use_docker": False} # Original config
    )
    # Force cleanup as in original
    if isinstance(user_proxy._code_execution_config, dict):
        user_proxy._code_execution_config["use_docker"] = False
    return ti_expert, stix_formatter, user_proxy

def create_advanced_agents():
    if not verify_azure_openai_settings():
        st.stop()
    llm_config = {
        "model": os.environ["AZURE_OPENAI_DEPLOYMENT_NAME"], "api_type": "azure",
        "api_key": os.environ["AZURE_OPENAI_API_KEY"], "base_url": os.environ["AZURE_OPENAI_ENDPOINT"],
        "api_version": os.environ["AZURE_OPENAI_API_VERSION"],
        "timeout": 120,  # Added timeout in seconds (e.g., 2 minutes)
        "temperature": 0.1 
    }
    # Using original system messages from the first prompt
    orchestrator = AssistantAgent(
        name="Orchestrator", llm_config=llm_config,
        system_message="""
        You are an orchestration agent responsible for coordinating the generation of a STIX 2.1 bundle.
        Your tasks:
        1. Analyze the threat scenario input and plan the sequence of steps to create each STIX object.
        2. After planning, instruct downstream agents to generate domain objects, observables, patterns, and relationships.
        3. Finally, once all objects are ready, assemble them into a complete STIX 2.1 bundle.
        At the end of your final response, include the word TERMINATE on its own line to signal completion.
        """
    )
    ti_analyst = AssistantAgent(
        name="ThreatAnalyst", llm_config=llm_config,
        system_message="""
        You are a Threat Intelligence Analyst.
        Your task is to analyze the provided threat scenario and return a structured JSON object with four keys: "sdos", "scos", "relationships", "patterns".
        - "sdos": list candidate STIX Domain Objects (type, name, confidence)
        - "scos": list technical observables (type, value, context)
        - "relationships": list {source, relationship, target}
        - When you list "patterns", also suggest in the "relationships" section how these patterns (which will become indicators) would typically relate to other SDOs using an "indicates" relationship. For example: {"source_pattern": "[ipv4-addr:value = '1.2.3.4']", "relationship": "indicates", "target_type": "infrastructure", "target_name_hint": "IP 1.2.3.4"}.
        IMPORTANT:
        - Output only the pure JSON object.
        - Do NOT wrap the JSON inside code blocks (no triple backticks).
        - Do NOT add any comments, explanations, or markdown formatting.
        - Your output must be a clean, directly parsable JSON.
        IMPORTANT: After providing the valid JSON output as requested, add the word 'TERMINATE' on a new line by itself at the very end of your response. Output absolutely nothing after 'TERMINATE'. Your output must be only the JSON followed by the TERMINATE signal.
        """
    )
    sdo_agent = AssistantAgent(
        name="SDOSpecialist", llm_config=llm_config,
        system_message="""You are a STIX 2.1 Domain Object (SDO) creation specialist...
    Your primary task is to create a valid JSON array of STIX 2.1 Domain Objects based on the 'sdos' section of the provided threat intelligence analysis.
    General Rules for SDO Creation:
    1.  All generated SDOs MUST be compliant with the STIX 2.1 specification.
    2.  The output MUST be a single JSON array `[...]` containing the STIX SDOs.
    3.  Each SDO in the array MUST be a valid JSON object.
    4.  The `type` property for each SDO must be a valid STIX Domain Object type (e.g., "threat-actor", "malware", "infrastructure", "identity", "tool", "attack-pattern", "campaign", "intrusion-set", "vulnerability", "course-of-action", "location", "note", "opinion", "report", "grouping").
    5.  Each SDO MUST have an `id` property. Use the format `"<sdo-type>--<UUID>"`. You should generate a new UUID for each object. Example: `"id": "malware--YOUR_GENERATED_UUID_HERE"`. Do NOT use placeholder IDs like "malware--" in the final output.
    6.  Each SDO MUST have `created` and `modified` timestamp properties in ISO 8601 format (e.g., `"YYYY-MM-DDTHH:MM:SS.sssZ"`). Use the current UTC time for these if not specified in the analysis.
    7.  Each SDO MUST have a `spec_version` property with the value `"2.1"`.
    8.  Do NOT include `created_by_ref` or `source_ref` properties unless explicitly provided and necessary.
    9.  Only include properties that are defined in the STIX 2.1 specification for the respective object type. Do not invent properties.
    10. Base the SDO content (name, description, specific properties) on the information provided in the 'sdos' section of the input analysis.
    Object-Specific REQUIRED Properties and Guidance:
    For **ThreatActor** objects: `name` REQUIRED, `labels` REQUIRED (JSON array).
    For **Malware** objects: `name` REQUIRED, `is_family` (boolean) REQUIRED, `labels` REQUIRED (JSON array).
    For **Infrastructure** objects: `name` REQUIRED, `labels` REQUIRED, `infrastructure_types` REQUIRED (JSON array).
    For **Identity** objects: `name` REQUIRED, `identity_class` REQUIRED, `labels` REQUIRED.
    (And so on for other SDOs as detailed in the original prompt)
    IMPORTANT FINAL INSTRUCTIONS:
    - Your output MUST be ONLY the valid JSON array `[...]`.
    - Do NOT wrap the JSON in markdown code blocks (no triple backticks).
    - Do NOT include any conversational text, comments, explanations, or markdown formatting outside the JSON array.
    - After providing the valid JSON array as requested, add the word 'TERMINATE' on a new line by itself at the very end of your response. Output absolutely nothing after 'TERMINATE'.
        """
    )
    sco_agent = AssistantAgent(
        name="SCOSpecialist", llm_config=llm_config,
        system_message="""You are tasked with creating STIX 2.1 Cyber-observable Objects (SCOs)...
        SCOs include: Artifact, Autonomous System, Directory, Domain Name, Email Address, Email Message, File, IPv4 Address, IPv6 Address, MAC Address, Mutex, Network Traffic, Process, Software, URL, User Account, Windows Registry Key, X.509 Certificate, HTTP Request, ICMP, Socket Ext, TCP Ext, Archive Ext, Raster Image Ext, NTFS Ext, PDF Ext, UNIX Account Ext, Windows PE Binary Ext, Windows Process Ext, Windows Service Ext, Windows Registry Ext, JPEG File Ext, Email MIME Component, Email MIME Multipart Type, Email MIME Message Type, Email MIME Text Type.
        Create relevant STIX 2.1 SCOs in JSON format based on the information provided in the text.
        Strictly follow the STIX 2.1 specification, ensuring no properties are used that are not defined in the specification
        Ensure the JSON output is valid, starting with [ and closing with ].
        STIX SCO objects require at least type, id and value properties
        Only provide output if one or more SCOs can be identified with reasonable certainty from the text.
        Ensure the structure and format are fully compliant with STIX 2.1.
        id STIX identifier must match <object-type>--<UUID>
        Return only the JSON array, without any additional text, commentary, or code block delimiters (e.g., json).
        IMPORTANT: After providing the valid JSON output as requested, add the word 'TERMINATE' on a new line by itself at the very end of your response. Output absolutely nothing after 'TERMINATE'. Your output must be only the JSON followed by the TERMINATE signal.
        """
    )
    sro_agent = AssistantAgent(
        name="SROSpecialist", llm_config=llm_config,
        system_message="""You are a STIX 2.1 Relationship Object (SRO) Specialist...
        Your task is to create a JSON array of STIX Relationship Objects based on the provided SDOs, SCOs, Indicators, specific 'Indicator Relationship Hints', and overall threat analysis.
        Instructions:
        1.  Analyze the 'Threat Analysis' provided, specifically its 'relationships' section, to create relationships connecting core SDOs (e.g., threat-actor uses malware).
        2.  Analyze the 'Indicator Relationship Hints' provided. Each hint contains a 'source_indicator_id', 'target_sdo_name', and 'target_sdo_type'.
            * For each hint, find the SDO in the provided 'SDOs' list whose 'name' and 'type' match the 'target_sdo_name' and 'target_sdo_type' from the hint.
            * If a matching SDO is found, create an 'indicates' relationship object where `source_ref` is the 'source_indicator_id' from the hint, and `target_ref` is the ID of the found SDO.
            * If an exact SDO match is not found for a hint, you may try to find the closest match or omit that specific relationship if no confident match can be made. Clearly state if you omit a relationship due to no match.
        3.  You may also identify other relevant relationships (e.g., `attributed-to` from an Indicator to a Threat Actor) if strongly supported by the overall analysis, in addition to those from hints.
        4.  Ensure all `source_ref` and `target_ref` IDs in your relationship objects correctly correspond to the IDs of the SDOs or Indicators from your input.
        5.  All relationship objects must be valid STIX 2.1 JSON. Timestamps (created, modified) must be in ISO 8601 format. Generate unique IDs for each relationship object.
        Output ONLY the JSON array of relationship objects.
        IMPORTANT: After providing the valid JSON output as requested, add the word 'TERMINATE' on a new line by itself at the very end of your response. Output absolutely nothing after 'TERMINATE'.
        """
    )
    pattern_agent = AssistantAgent(
        name="PatternSpecialist", llm_config=llm_config,
        system_message="""
        You are a STIX 2.1 Pattern Specialist.
        Your job is to generate STIX Indicator objects.
        Based on the provided Cyber Observables (SCOs) and the overall scenario analysis:
        1. For each relevant observable or pattern mentioned in the analysis:
           a. Build a valid STIX Pattern string (e.g., "[ipv4-addr:value = '1.2.3.4']").
           b. Create a complete STIX Indicator object using that pattern. Ensure all required fields are present: type, id, created, modified, pattern, pattern_type, name, description, confidence. Use "pattern_type": "stix". Timestamps must be in ISO 8601 format (e.g., "YYYY-MM-DDTHH:MM:SS.sssZ"). The `name` and `description` should be meaningful and derived from the context.
        2. Your output MUST be a **JSON array** of STIX Indicator objects.
        Example of an element in the output array (a single STIX Indicator object):
        {
          "type": "indicator",
          "spec_version": "2.1",
          "id": "indicator--YOUR_GENERATED_UUID",
          "created": "YYYY-MM-DDTHH:MM:SS.sssZ",
          "modified": "YYYY-MM-DDTHH:MM:SS.sssZ",
          "pattern": "[ipv4-addr:value = '1.2.3.4']",
          "pattern_type": "stix",
          "name": "Indicator for IP 1.2.3.4",
          "description": "This IP address 1.2.3.4 is associated with malicious activity.",
          "confidence": 80
        }
        IMPORTANT:
        - Output only the pure JSON array of STIX Indicator objects.
        - Do NOT wrap the JSON inside code blocks (no triple backticks).
        - Do NOT add any comments, explanations, or markdown formatting.
        - Ensure all STIX Indicator objects are STIX 2.1 compliant.
        - After providing the valid JSON output as requested, add the word 'TERMINATE' on a new line by itself at the very end of your response. Output absolutely nothing after 'TERMINATE'.
        """
    )
    validator = AssistantAgent(
        name="Validator", llm_config=llm_config,
        system_message="""
        You are a STIX 2.1 Bundling Specialist. Your primary task is to assemble provided STIX objects into a single, valid STIX 2.1 Bundle.

        Your tasks:
        1. Receive a list of STIX 2.1 objects (SDOs, SCOs, SROs, Indicators).
        2. **Assume these objects are mostly valid.** Your main goal is to bundle them.
        3. Perform a quick check for STIX 2.1 compliance:
            - Ensure `id` properties are correctly formatted (e.g., "threat-actor--<UUID>").
            - Ensure timestamps (`created`, `modified`) are in ISO 8601 format.
            - Ensure `spec_version: "2.1"` is present.
            - Check for presence of essential fields for common types (e.g., `labels` for `threat-actor`, `is_family` and `labels` for `malware`). If clearly missing and easily fixable with a default (like `labels: ["unknown"]`), you may add it. Do not attempt complex corrections.
        4. Assemble ALL provided objects into a single STIX 2.1 Bundle object.
        5. The bundle MUST have `type: "bundle"`, a unique `id: "bundle--<UUID_YOU_GENERATE>"`, and `spec_version: "2.1"`.
        6. The "objects" field of the bundle must be a list of all the STIX objects you received.

        Return ONLY the full STIX 2.1 Bundle as pure JSON.
        Do NOT include any extra text, explanations, comments, or markdown formatting. The output must be parsable by the stix2 Python library.
        IMPORTANT: After providing the valid JSON Bundle output, add the word 'TERMINATE' on a new line by itself at the very end of your response.
        """
    )
    user_proxy = SafeUserProxyAgent(
        name="UserProxy", # Name from original code
        human_input_mode="NEVER", max_consecutive_auto_reply=30,
        is_termination_msg=lambda x: "TERMINATE" in x.get("content", "").upper(),
        code_execution_config={"use_docker": False} # Original config
    )
    # Force cleanup as in original
    if isinstance(user_proxy._code_execution_config, dict):
        user_proxy._code_execution_config["use_docker"] = False

    return {
        "orchestrator": orchestrator, "ti_analyst": ti_analyst, "sdo_agent": sdo_agent,
        "sco_agent": sco_agent, "sro_agent": sro_agent, "pattern_agent": pattern_agent,
        "validator": validator, "user_proxy": user_proxy
    }

def generate_stix_content(scenario_description):
    if not st.session_state.agents_initialized:
        st.session_state.ti_expert, st.session_state.stix_formatter, st.session_state.user_proxy_std = initialize_agents() # Renamed proxy to avoid conflict
        st.session_state.agents_initialized = True
    
    ti_expert = st.session_state.ti_expert
    stix_formatter = st.session_state.stix_formatter
    user_proxy = st.session_state.user_proxy_std # Use the standard mode proxy

    user_proxy.reset() # Reset proxy for fresh conversation
    chat_messages = []
    
    user_proxy.initiate_chat(
        ti_expert,
        message=f"Please analyze this threat scenario and suggest appropriate STIX 2.1 objects:\n\n{scenario_description}\n\nFocus on identifying key entities, indicators, attack patterns, and relationships. Conclude with TERMINATE."
    )
    
    ti_expert_analysis_raw = ""
    if ti_expert in user_proxy.chat_messages and user_proxy.chat_messages[ti_expert]:
        for msg in user_proxy.chat_messages[ti_expert]:
            chat_messages.append({"role": msg["role"], "name": ti_expert.name, "content": msg["content"]})
        ti_expert_analysis_raw = user_proxy.chat_messages[ti_expert][-1]["content"]
    else:
        st.error("ThreatIntelligenceExpert did not respond.")
        st.session_state.chat_history = chat_messages
        return

    ti_expert_analysis_cleaned = _clean_agent_json_response(ti_expert_analysis_raw)

    if stix_formatter in user_proxy.chat_messages: # Clear previous messages for this agent
        del user_proxy.chat_messages[stix_formatter]

    user_proxy.initiate_chat(
        stix_formatter,
        message=f"Based on the threat analysis below, please create valid STIX 2.1 JSON objects, preferably as a STIX Bundle:\n\n{ti_expert_analysis_cleaned}\n\nReturn only the JSON. Conclude with TERMINATE."
    )
    
    stix_formatter_response_raw = ""
    if stix_formatter in user_proxy.chat_messages and user_proxy.chat_messages[stix_formatter]:
        for msg in user_proxy.chat_messages[stix_formatter]:
            chat_messages.append({"role": msg["role"], "name": stix_formatter.name, "content": msg["content"]})
        stix_formatter_response_raw = user_proxy.chat_messages[stix_formatter][-1]["content"]
    else:
        st.error("STIXFormatter did not respond.")
        st.session_state.chat_history = chat_messages
        return
        
    st.session_state.chat_history = chat_messages
    extract_stix_objects(stix_formatter_response_raw) # This will use the cleaned response

def advanced_stix_generation(scenario_description):
    if not st.session_state.advanced_agents_initialized:
        st.session_state.advanced_agents = create_advanced_agents()
        st.session_state.advanced_agents_initialized = True

    agents = st.session_state.advanced_agents
    user_proxy = agents["user_proxy"] 

    all_conversations = {}
    processed_outputs = {}

    def get_and_parse_last_response(agent_object_key, agent_name_for_log: str):
        if agent_object_key not in user_proxy.chat_messages or not user_proxy.chat_messages[agent_object_key]:
            st.error(f"No response received from {agent_name_for_log} in user_proxy.chat_messages.")
            st.write("Available keys in chat_messages:", [k.name if hasattr(k,'name') else str(k) for k in user_proxy.chat_messages.keys()])
            return None

        message_to_process = user_proxy.chat_messages[agent_object_key][-1]["content"]
        cleaned_json_str = _clean_agent_json_response(message_to_process)
        attempt_description = "last message"

        if not cleaned_json_str: 
            st.warning(f"Received empty content (after cleaning {attempt_description}) from {agent_name_for_log}. "
                       f"Original content: '''{message_to_process}'''. Trying previous message if available.")
            if len(user_proxy.chat_messages[agent_object_key]) > 1:
                message_to_process = user_proxy.chat_messages[agent_object_key][-2]["content"]
                cleaned_json_str = _clean_agent_json_response(message_to_process)
                attempt_description = "previous message"
                if not cleaned_json_str:
                    st.error(f"Content from {agent_name_for_log} ({attempt_description}) also empty after cleaning. "
                               f"Original content: '''{message_to_process}'''. Cannot parse.")
                    return None
            else: 
                st.error(f"Received empty content (after cleaning {attempt_description}) from {agent_name_for_log} "
                           f"and no previous message available. Original content: '''{message_to_process}'''.")
                return None
        
        try:
            if not cleaned_json_str: 
                 st.error(f"Unexpected empty cleaned_json_str for {agent_name_for_log} before parsing, from original: '''{message_to_process}'''")
                 return None
            parsed_data = json.loads(cleaned_json_str)
            return parsed_data
        except json.JSONDecodeError as e:
            st.error(f"Failed to parse JSON response from {agent_name_for_log} (attempted on {attempt_description}): {e}\n"
                     f"Original content that led to this error:\n'''{message_to_process}'''\n"
                     f"String passed to json.loads():\n'''{cleaned_json_str}'''")
            return None
        except Exception as e: 
            st.error(f"Unexpected error processing/parsing response from {agent_name_for_log} (attempted on {attempt_description}): {e}\n"
                     f"Original content:\n'''{message_to_process}'''\n"
                     f"Cleaned string (if available):\n'''{cleaned_json_str}'''")
            return None

    progress_bar = st.progress(0)
    progress_text = st.empty()
    user_proxy.reset() 

    progress_text.text("Step 1/7: Orchestrator creating a plan...")
    user_proxy.initiate_chat(
        agents["orchestrator"], 
        message=f"Create a STIX generation plan for this scenario: {scenario_description}",
        clear_history=True
    )
    all_conversations[agents["orchestrator"]] = user_proxy.chat_messages.get(agents["orchestrator"], []) 
    progress_bar.progress(10)

    progress_text.text("Step 2/7: Threat Intelligence Analyst analyzing scenario...")
    ti_analyst_input_message = f"Generate a structured analysis in JSON (sdos, scos, relationships, patterns) for: {scenario_description}"
    user_proxy.initiate_chat(agents["ti_analyst"], message=ti_analyst_input_message, clear_history=True)
    all_conversations[agents["ti_analyst"]] = user_proxy.chat_messages.get(agents["ti_analyst"], [])
    ti_analysis_data = get_and_parse_last_response(agents["ti_analyst"], "ThreatAnalyst")
    if ti_analysis_data is None: return None
    processed_outputs["ti_analysis"] = ti_analysis_data
    progress_bar.progress(20)

    progress_text.text("Step 3/7: Creating STIX Domain Objects (SDOs)...")
    sdo_input_message = f"Based on this analysis 'sdos' section: {json.dumps(processed_outputs['ti_analysis'].get('sdos',[]))}\nCreate SDOs."
    user_proxy.initiate_chat(agents["sdo_agent"], message=sdo_input_message, clear_history=True)
    all_conversations[agents["sdo_agent"]] = user_proxy.chat_messages.get(agents["sdo_agent"], [])
    sdo_data = get_and_parse_last_response(agents["sdo_agent"], "SDOSpecialist")
    if sdo_data is None: return None
    processed_outputs["sdos"] = sdo_data
    progress_bar.progress(35)

    progress_text.text("Step 4/7: Creating STIX Cyber Observable Objects (SCOs)...")
    sco_input_message = f"Based on this analysis 'scos' section: {json.dumps(processed_outputs['ti_analysis'].get('scos',[]))}\nCreate SCOs."
    user_proxy.initiate_chat(agents["sco_agent"], message=sco_input_message, clear_history=True)
    all_conversations[agents["sco_agent"]] = user_proxy.chat_messages.get(agents["sco_agent"], [])
    sco_data = get_and_parse_last_response(agents["sco_agent"], "SCOSpecialist")
    processed_outputs["scos"] = sco_data if sco_data is not None else []
    progress_bar.progress(50)

    progress_text.text("Step 5/7: Creating indicator patterns (Indicators)...")
    pattern_input_message = (f"Based on these cyber observables (if any): {json.dumps(processed_outputs.get('scos',[]))}\n"
                             f"And the 'patterns' from TI analysis: {json.dumps(processed_outputs.get('ti_analysis',{}).get('patterns',[]))}\n"
                             f"Generate STIX Indicator objects.")
    user_proxy.initiate_chat(agents["pattern_agent"], message=pattern_input_message, clear_history=True)
    all_conversations[agents["pattern_agent"]] = user_proxy.chat_messages.get(agents["pattern_agent"], [])
    indicator_data = get_and_parse_last_response(agents["pattern_agent"], "PatternSpecialist")
    actual_indicators = []
    if indicator_data and isinstance(indicator_data, list):
        for item in indicator_data:
            if isinstance(item, dict) and item.get("type") == "indicator" and "id" in item:
                actual_indicators.append(item)
            else: st.warning(f"PatternSpecialist produced a non-indicator item: {item}")
    elif indicator_data is not None:
        st.error(f"PatternSpecialist output was not a list: {indicator_data}")
    processed_outputs["indicators"] = actual_indicators 
    progress_bar.progress(65)
    
    progress_text.text("Step 6/7: Creating relationships between objects...")
    sro_input_message = f"""
    Based on SDOs: {json.dumps(processed_outputs.get("sdos", []))}
    SCOs: {json.dumps(processed_outputs.get("scos", []))}
    Indicators: {json.dumps(processed_outputs.get("indicators", []))}
    And overall Threat Analysis (especially 'relationships' hints): {json.dumps(processed_outputs.get("ti_analysis", {}))}
    Create STIX Relationship Objects.
    """
    user_proxy.initiate_chat(agents["sro_agent"], message=sro_input_message, clear_history=True)
    all_conversations[agents["sro_agent"]] = user_proxy.chat_messages.get(agents["sro_agent"], [])
    sro_data = get_and_parse_last_response(agents["sro_agent"], "SROSpecialist")
    processed_outputs["relationships"] = sro_data if sro_data is not None else []
    progress_bar.progress(80)

    progress_text.text("Step 7/7: Validating and formatting final STIX bundle...")
    all_objects_for_validator = (
        processed_outputs.get("sdos", []) +
        processed_outputs.get("scos", []) +
        processed_outputs.get("indicators", []) +
        processed_outputs.get("relationships", [])
    )
    all_objects_for_validator = [obj for obj in all_objects_for_validator if obj is not None] 

    # --- Debugging Validator Input ---
    st.sidebar.subheader("Validator Input Debug") # Display in sidebar to avoid clutter
    st.sidebar.write(f"Num objects for validator: {len(all_objects_for_validator)}")
    if all_objects_for_validator:
        try:
            st.sidebar.json([obj for obj in all_objects_for_validator[:2]]) # Show first 2 objects
            if len(all_objects_for_validator) > 2:
                st.sidebar.write(f"... and {len(all_objects_for_validator) - 2} more objects (full list not shown to save space).")
        except Exception as debug_e:
            st.sidebar.error(f"Error displaying validator input debug: {debug_e}")
    # --- End Debugging ---

    validator_input_message = f"Assemble and validate these STIX objects into a single STIX 2.1 bundle:\n{json.dumps(all_objects_for_validator)}"
    user_proxy.initiate_chat(agents["validator"], message=validator_input_message, clear_history=True)
    all_conversations[agents["validator"]] = user_proxy.chat_messages.get(agents["validator"], [])
    final_bundle_data = get_and_parse_last_response(agents["validator"], "Validator")
    if final_bundle_data is None: 
        st.error("Validator agent failed to produce data for the final bundle.")
        return None
    processed_outputs["final_bundle"] = final_bundle_data
    progress_bar.progress(100)
    progress_text.text("STIX generation complete!")

    if processed_outputs.get("final_bundle"):
        try:
            final_bundle_obj = stix2.parse(processed_outputs["final_bundle"], allow_custom=True)
            st.session_state.bundle = final_bundle_obj
            st.session_state.stix_objects = [stix2.parse(o) if isinstance(o, dict) else o for o in final_bundle_obj.objects] if hasattr(final_bundle_obj, 'objects') and final_bundle_obj.objects else []
            st.success("STIX Bundle generated and validated successfully!")
        except Exception as e:
            st.error(f"Error parsing or validating the final bundle from Validator: {e}")
            st.subheader("Raw JSON from Validator (Potential Error):")
            st.json(processed_outputs["final_bundle"])
            st.session_state.bundle = None; st.session_state.stix_objects = []
    else:
        st.error("Failed to generate the final STIX bundle.")
        st.session_state.bundle = None; st.session_state.stix_objects = []

    st.session_state.advanced_conversations = all_conversations
    return all_conversations

def extract_stix_objects(raw_text_from_llm: str):
    stix_objects_list = []
    bundle_obj_from_response = None
    
    cleaned_json_text = _clean_agent_json_response(raw_text_from_llm)

    if not cleaned_json_text:
        st.warning("No parsable JSON content found in the agent's response (Standard Mode).")
        st.session_state.stix_objects = []
        st.session_state.bundle = None
        return

    try:
        parsed_json_data = json.loads(cleaned_json_text)

        if isinstance(parsed_json_data, dict) and parsed_json_data.get("type") == "bundle":
            bundle_obj_from_response = stix2.parse(parsed_json_data, allow_custom=True)
            if hasattr(bundle_obj_from_response, 'objects') and bundle_obj_from_response.objects:
                stix_objects_list = [stix2.parse(o) if isinstance(o, dict) else o for o in bundle_obj_from_response.objects]
        elif isinstance(parsed_json_data, list):
            for obj_dict in parsed_json_data:
                if isinstance(obj_dict, dict) and "type" in obj_dict:
                    try:
                        stix_objects_list.append(stix2.parse(obj_dict, allow_custom=True))
                    except Exception as e:
                        st.warning(f"Could not parse STIX object from list: {obj_dict.get('type','N/A')}. Error: {e}")
            if stix_objects_list:
                 bundle_obj_from_response = stix2.Bundle(objects=stix_objects_list, allow_custom=True)
        elif isinstance(parsed_json_data, dict) and "type" in parsed_json_data: # Single STIX object
            single_obj = stix2.parse(parsed_json_data, allow_custom=True)
            stix_objects_list.append(single_obj)
            bundle_obj_from_response = stix2.Bundle(objects=stix_objects_list, allow_custom=True)
        else:
            st.warning("Agent's JSON response was not a STIX bundle or a list/single STIX object.")
            st.json(parsed_json_data)

    except json.JSONDecodeError as e:
        st.error(f"Failed to decode JSON from agent's response (Standard Mode): {e}")
        st.text_area("Content that failed JSON decoding:", cleaned_json_text, height=150)
    except Exception as e:
        st.error(f"An unexpected error occurred while processing STIX data (Standard Mode): {e}")
        st.text_area("Content being processed when error occurred:", cleaned_json_text, height=150)

    st.session_state.stix_objects = stix_objects_list
    st.session_state.bundle = bundle_obj_from_response

# UI Input Section (original structure)
input_type = st.radio(
    "Select input method:",
    ["Direct Description", "Web Threat Report", "PDF Upload"],
    help="Choose how you want to provide threat intelligence information."
)
scenario_description = "" 
if input_type == "Direct Description":
    scenario_description = st.text_area(
        "Describe the threat scenario in detail...", height=150, key="direct_desc_input"
    )
elif input_type == "Web Threat Report":
    url = st.text_input("Enter URL of the threat report:", key="web_url_input")
    if url:
        with st.spinner("Extracting content from webpage..."):
            content, error = extract_web_content(url)
        if error: st.error(error)
        elif content:
            st.success("Content extracted successfully!")
            scenario_description = content
            with st.expander("Preview extracted content", expanded=False):
                st.markdown(content[:1000] + "..." if len(content) > 1000 else content)
else: 
    uploaded_file = st.file_uploader("Upload PDF threat report", type="pdf", key="pdf_file_input")
    if uploaded_file is not None:
        with st.spinner("Extracting content from PDF..."):
            content, error = extract_pdf_content(uploaded_file)
        if error: st.error(error)
        elif content:
            st.success("Content extracted successfully!")
            scenario_description = content
            with st.expander("Preview extracted content", expanded=False):
                st.markdown(content[:1000] + "..." if len(content) > 1000 else content)

# Generate button (FIXED)
if st.button("Generate STIX Content"):
    if not verify_azure_openai_settings(): st.stop() 
    if not scenario_description or not scenario_description.strip():
        st.warning("Please provide input using one of the available methods.")
    else:
        st.session_state.stix_objects = []
        st.session_state.bundle = None
        st.session_state.chat_history = []
        st.session_state.advanced_conversations = {}

        if mode == "Standard":
            st.session_state.agents_initialized = False # Ensure standard agents re-init if needed
            with st.spinner("Agents are collaborating to generate STIX content..."):
                generate_stix_content(scenario_description)
        else:
            st.session_state.advanced_agents_initialized = False 
            with st.spinner("Advanced multi-agent pipeline processing... This may take some time."):
                advanced_stix_generation(scenario_description)


# Display results (original structure)
if mode == "Standard":
    tab1, tab2, tab3 = st.tabs(["Agent Conversation", "STIX Objects", "JSON Output"])
    with tab1:
        st.header("Agent Conversation")
        if st.session_state.chat_history:
            for msg in st.session_state.chat_history:
                role_display = msg.get("name", msg.get("role", "System")).capitalize()
                with st.chat_message(name=role_display): 
                    st.markdown(msg.get("content", ""))
        else: st.info("Generate STIX content to see agent conversation.")
    with tab2:
        st.header("Generated STIX Objects")
        if st.session_state.stix_objects:
            for i, obj in enumerate(st.session_state.stix_objects):
                obj_type_display = obj.type.replace('-', ' ').title()
                obj_name_display = getattr(obj, 'name', obj.id.split('--')[1][:12] + "...")
                with st.expander(f"{obj_type_display}: {obj_name_display} (`{obj.id}`)"):
                    st.json(obj.serialize(pretty=True)) 
        else: st.info("Generate STIX content to see STIX objects.")
    with tab3:
        st.header("STIX JSON Output")
        if st.session_state.bundle:
            bundle_json_str = st.session_state.bundle.serialize(pretty=True)
            st.json(bundle_json_str)
            st.download_button("Download STIX Bundle", bundle_json_str, "stix_bundle.json", "application/json")
        elif st.session_state.stix_objects: 
            st.warning("Bundle object not created, showing individual objects as a list.")
            st.json([obj.serialize(pretty=True) for obj in st.session_state.stix_objects])
        else: st.info("Generate STIX content to see JSON output.")
else: # Advanced mode tabs
    tab1_adv, tab2_adv, tab3_adv, tab4_adv = st.tabs(["Agent Conversations", "STIX Objects", "JSON Output", "Visualization"])
    with tab1_adv:
        st.header("Agent Conversations")
        if st.session_state.advanced_conversations:
            agent_names_order = ["orchestrator", "ti_analyst", "sdo_agent", "sco_agent", 
                                 "pattern_agent", "sro_agent", "validator"] 
            for agent_key_str in agent_names_order:
                agent_obj_for_name = st.session_state.advanced_agents.get(agent_key_str)
                display_name = agent_obj_for_name.name if agent_obj_for_name and hasattr(agent_obj_for_name, 'name') else agent_key_str.replace('_', ' ').title()

                conv_list = None
                if agent_obj_for_name in st.session_state.advanced_conversations:
                    conv_list = st.session_state.advanced_conversations[agent_obj_for_name]
                elif agent_key_str in st.session_state.advanced_conversations: 
                     conv_list = st.session_state.advanced_conversations[agent_key_str]

                if conv_list:
                    with st.expander(f"Conversation with: {display_name}"):
                        for msg in conv_list:
                             role_display_adv = msg.get("name", msg.get("role", "System")).capitalize()
                             with st.chat_message(name=role_display_adv):
                                st.markdown(msg.get("content", ""))
        else: st.info("Generate STIX content using Advanced mode to see agent conversations.")
    with tab2_adv:
        st.header("Generated STIX Objects")
        if st.session_state.stix_objects:
            col1, col2, col3 = st.columns(3)
            sdo_types_list = ['threat-actor', 'malware', 'attack-pattern', 'campaign', 'identity', 'intrusion-set', 'report', 'tool', 'vulnerability', 'course-of-action', 'infrastructure'] 
            sco_types_list = ['file', 'ipv4-addr', 'ipv6-addr', 'url', 'domain-name', 'email-addr', 'network-traffic', 'process', 'artifact', 'x509-certificate'] 
            sro_indicators_list = ['relationship', 'sighting', 'indicator'] 
            
            sdo_objects = [o for o in st.session_state.stix_objects if o.type in sdo_types_list]
            sco_objects = [o for o in st.session_state.stix_objects if o.type in sco_types_list]
            sro_indicators = [o for o in st.session_state.stix_objects if o.type in sro_indicators_list]
            
            def display_objects_in_column(column, title, objects):
                with column:
                    st.subheader(title)
                    if objects:
                        for obj in objects:
                            obj_type_display = obj.type.replace('-', ' ').title()
                            obj_name_display = getattr(obj, 'name', obj.id.split('--')[1][:8] + "...")
                            with st.expander(f"{obj_type_display}: {obj_name_display} (`{obj.id}`)"):
                                st.json(obj.serialize(pretty=True))
                    else: st.info(f"No {title.lower()} generated.")
            display_objects_in_column(col1, "Domain Objects (SDOs)", sdo_objects)
            display_objects_in_column(col2, "Cyber Observables (SCOs)", sco_objects)
            display_objects_in_column(col3, "Relationships & Indicators", sro_indicators)
        else: st.info("Generate STIX content to see STIX objects.")
    with tab3_adv:
        st.header("STIX JSON Output")
        if st.session_state.bundle:
            bundle_json_str_adv = st.session_state.bundle.serialize(pretty=True)
            st.json(bundle_json_str_adv)
            st.download_button("Download STIX Bundle", bundle_json_str_adv, "stix_bundle_advanced.json", "application/json")
        else: st.info("Generate STIX content to see JSON output.")
    with tab4_adv:
        st.header("STIX Visualization")
        if st.session_state.stix_objects:
            st.warning("Visualization feature is under development. Basic relationship list shown.")
            relationships = [obj for obj in st.session_state.stix_objects if obj.type == 'relationship']
            if relationships:
                st.subheader("Relationship Summary")
                nodes_lookup = {obj.id: getattr(obj, 'name', obj.id) for obj in st.session_state.stix_objects}
                for rel in relationships:
                    source_name = nodes_lookup.get(rel.source_ref, rel.source_ref)
                    target_name = nodes_lookup.get(rel.target_ref, rel.target_ref)
                    st.write(f"**{source_name}** ` {rel.relationship_type.replace('-', ' ')} ` **{target_name}**")
            else: st.info("No relationships found to visualize.")
        else: st.info("Generate STIX content to see visualization.")

# Footer (original structure)
st.markdown("---")
st.markdown("📝 **STIX 2.1 Generator** | This app uses AI agents to generate structured threat intelligence in STIX 2.1 format")
st.markdown("Built with ❤️ using AutoGen, Streamlit, and the STIX2 library")