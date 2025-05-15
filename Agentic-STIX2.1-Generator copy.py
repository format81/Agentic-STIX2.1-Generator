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
import time
import re
import uuid
from dotenv import load_dotenv
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import PyPDF2
import io
from urllib.parse import urlparse
import markitdown

# Load .env from the same directory as the script
env_path = Path(__file__).resolve().parent / "my.env"
load_dotenv(dotenv_path=env_path)


## Verify Azure OpenAI settings are properly configured
#if not verify_azure_openai_settings():
#    st.stop()

# Safe version of UserProxyAgent to avoid executing JSON, YAML, STIX
import re
from autogen import UserProxyAgent

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
            return 0, "Non-executable content (JSON/YAML detected)", None

        # 3. Altrimenti, passa al super con il codice ripulito
        #    Rimuovi eventuali kwargs non supportati
        supported_kwargs = {k: v for k, v in kwargs.items() if k not in ['non_executable_languages']}
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
if 'advanced_conversations' not in st.session_state:
    st.session_state.advanced_conversations = {}

# Function to create a UUID for STIX objects
def generate_stix_id(object_type):
    return f"{object_type}--{str(uuid.uuid4())}"

# Function to extract content from web page
def extract_web_content(url):
    try:
        # Validate URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return None, "Invalid URL. Please provide a complete URL including http:// or https://"
        
        # Send request
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script, style, and other non-content elements
        for tag in soup(['script', 'style', 'header', 'footer', 'nav', 'aside']):
            tag.decompose()
        
        # Extract title
        title = soup.title.string if soup.title else "Web Content"
        
        # Extract main content - prioritize article or main tags
        content_tags = soup.find_all(['article', 'main', 'div.content', 'div.article'])
        if content_tags:
            text = " ".join([tag.get_text(separator=' ', strip=True) for tag in content_tags])
        else:
            # Fallback to body content
            text = soup.body.get_text(separator=' ', strip=True) if soup.body else ""
        
        # Clean the text
        processed_text = clean_text(text)
        
        return f"Title: {title}\n\n{processed_text}", None
    except requests.exceptions.RequestException as e:
        return None, f"Error fetching URL: {str(e)}"
    except Exception as e:
        return None, f"Error processing web content: {str(e)}"

def clean_text(text):
    """Clean and format extracted text"""
    # Replace multiple newlines with a single one
    text = re.sub(r'\n+', '\n', text)
    # Replace multiple spaces with a single one
    text = re.sub(r' +', ' ', text)
    # Remove leading/trailing whitespace
    text = text.strip()
    return text

# Function to extract content from PDF
def extract_pdf_content(pdf_file):
    try:
        # Read PDF file
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        
        # Extract text from each page
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        
        # Use markitdown to format and clean the text
        processed_text = markitdown.markitdown(text)
        
        return processed_text, None
    except Exception as e:
        return None, f"Error processing PDF file: {str(e)}"

# Add a function to verify Azure OpenAI settings in the app
def verify_azure_openai_settings():
    required_vars = [
        "AZURE_OPENAI_API_KEY", 
        "AZURE_OPENAI_ENDPOINT", 
        "AZURE_OPENAI_DEPLOYMENT_NAME",
        "AZURE_OPENAI_API_VERSION"
    ]
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        st.error(f"Missing required Azure OpenAI environment variables: {', '.join(missing_vars)}")
        st.error("Please set these in your .env file or environment.")
        return False
    return True

# Function to initialize the standard AutoGen agents
def initialize_agents():
    # Ensure all necessary environment variables are set
    if not verify_azure_openai_settings():
        st.stop()

    # Azure OpenAI config (flat format, no config_list)
    llm_config = {
        "model": os.environ["AZURE_OPENAI_DEPLOYMENT_NAME"],
        "api_type": "azure",
        "api_key": os.environ["AZURE_OPENAI_API_KEY"],
        "base_url": os.environ["AZURE_OPENAI_ENDPOINT"],
        "api_version": os.environ["AZURE_OPENAI_API_VERSION"]
    }

    # Create a threat intelligence expert agent
    ti_expert = AssistantAgent(
        name="ThreatIntelligenceExpert",
        llm_config=llm_config,
        system_message="""You are a threat intelligence expert who specializes in creating STIX 2.1 content.
        Your job is to analyze threat scenarios and convert them into appropriate STIX objects.
        Focus on technical accuracy and adherence to the STIX 2.1 standard."""
    )

    # Create a STIX formatter agent
    stix_formatter = AssistantAgent(
        name="STIXFormatter",
        llm_config=llm_config,
        system_message="""You are a STIX 2.1 specialist who converts threat information into valid STIX JSON.
        You ensure that all STIX objects have required fields and follow the proper format.
        You only output valid STIX 2.1 JSON that can be parsed by the stix2 Python library."""
    )

    # Create a user proxy agent that interacts with the human
    # In your initialize_agents function
    user_proxy = SafeUserProxyAgent(
        name="UserProxy",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=30,
        is_termination_msg=lambda x: "TERMINATE" in x.get("content", ""),
        code_execution_config={
            "use_docker": False
        }
    )

    # Force cleanup to avoid crash
    user_proxy._code_execution_config = {
        "use_docker": False
    }


    return ti_expert, stix_formatter, user_proxy


def create_advanced_agents():
    """Create specialized agents for advanced STIX generation"""

    llm_config = {
        "model": os.environ["AZURE_OPENAI_DEPLOYMENT_NAME"],
        "api_type": "azure",
        "api_key": os.environ["AZURE_OPENAI_API_KEY"],
        "base_url": os.environ["AZURE_OPENAI_ENDPOINT"],
        "api_version": os.environ["AZURE_OPENAI_API_VERSION"]
    }

    #orchestrator = AssistantAgent(
    #    name="Orchestrator",
    #    llm_config=llm_config,
    #    #system_message="You are an orchestration agent that coordinates the creation of STIX 2.1 content..."
    #    system_message="""You are an orchestration agent that coordinates the creation of STIX 2.1 bundle.
    #      Focus on the overall process and ensure that each agent performs its task effectively."""
    #)
    from autogen import AssistantAgent

    orchestrator = AssistantAgent(
        name="Orchestrator",
        llm_config=llm_config,
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
        name="ThreatAnalyst",
        llm_config=llm_config,
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
        name="SDOSpecialist",
        llm_config=llm_config,
        system_message="""You are a STIX 2.1 Domain Object (SDO) creation specialist.
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

    For **ThreatActor** objects:
    -   The `name` property is REQUIRED (e.g., "Antonio-Devil").
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings. Examples: `["crime-syndicate"]`, `["nation-state"]`, `["hacktivist"]`. If the specific type is unclear from the analysis, use a sensible default like `["unknown-threat-actor-type"]` or `["criminal"]` based on context. At least one label is mandatory.
    -   Include other relevant properties if inferable: `description`, `aliases`, `first_seen`, `last_seen`, `roles`, `goals`, `sophistication`, `resource_level`, `primary_motivation`.

    For **Malware** objects:
    -   The `name` property is REQUIRED (e.g., "F0rmat").
    -   The `is_family` property (boolean) is REQUIRED. Output it as `true` or `false` (lowercase, not as a string). Example: `"is_family": false`.
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings representing categories or descriptive terms for the malware. Examples: `["trojan"]`, `["ransomware", "dropper"]`, `["spyware"]`. At least one label is mandatory.
    -   Include other relevant properties if inferable: `description`, `malware_types` (e.g., `["trojan"]`, `["backdoor"]`), `aliases`, `first_seen`, `last_seen`, `architecture_execution_envs`, `implementation_languages`, `capabilities`.

    For **Infrastructure** objects:
    -   The `name` property is REQUIRED (e.g., "Compromised IP 1.2.3.4", "Malicious C2 Server").
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings. Examples: `["command-and-control"]`, `["malware-hosting"]`, `["anonymization"]`. If the specific type is unclear, use a sensible default like `["compromised-infrastructure"]` or `["malicious-infrastructure"]`. At least one label is mandatory.
    -   The `infrastructure_types` property is REQUIRED. It MUST be a JSON array of strings from the `infrastructure-type-ov` open vocabulary (e.g., `["command-and-control-server"]`, `["hosting-malware"]`, `["anonymization-service"]`). If unknown, use `["unknown"]`.
    -   Include other relevant properties if inferable: `description`, `aliases`, `first_seen`, `last_seen`.

    For **Identity** objects:
    -   The `name` property is REQUIRED (e.g., "FSI organizations", "ACME Corp").
    -   The `identity_class` property is REQUIRED (e.g., `"organization"`, `"individual"`, `"group"`, `"class"`).
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings describing the identity. Examples for an organization targeted: `["victim"]`, `["financial-services-sector"]`. For a company identity: `["company"]`. At least one label is mandatory.
    -   Include other relevant properties if inferable: `description`, `roles`, `sectors` (from `industry-sector-ov`).

    For **Tool** objects:
    -   The `name` property is REQUIRED.
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings. Examples: `["network-scanner"]`, `["exploitation-tool"]`, `["remote-access-software"]`. At least one label is mandatory.
    -   Include other relevant properties if inferable: `description`, `tool_types` (e.g., `["remote-access-trojan"]`, `["denial-of-service"]`), `aliases`, `tool_version`.


    For **Attack-Pattern** objects (TTPs):
    -   The `name` property is REQUIRED.
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings. Example: `["phishing"]`. At least one label is mandatory.
    -   Include `description` if available. External references (e.g., to MITRE ATT&CK) are highly encouraged in the `external_references` property.

    For **Campaign** and **Intrusion-Set** objects:
    -   The `name` property is REQUIRED.
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings. Examples for Campaign: `["phishing-campaign"]`. Examples for Intrusion Set: `["apt-group"]`. At least one label is mandatory.
    -   Include `description`, `aliases`, `first_seen`, `last_seen` if available.

    For **Vulnerability** objects:
    -   The `name` property is REQUIRED (often a CVE ID, e.g., "CVE-2021-44228").
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings. Example: `["log4shell"]`. At least one label is mandatory.
    -   Include `description` and `external_references` (especially one to the CVE database) if available.

    For **Course-of-Action** objects:
    -   The `name` property is REQUIRED.
    -   The `labels` property is REQUIRED. It MUST be a JSON array of strings. Example: `["patch-vulnerability"]`. At least one label is mandatory.
    -   Include `description`.

    IMPORTANT FINAL INSTRUCTIONS:
    - Your output MUST be ONLY the valid JSON array `[...]`.
    - Do NOT wrap the JSON in markdown code blocks (no triple backticks).
    - Do NOT include any conversational text, comments, explanations, or markdown formatting outside the JSON array.
    - After providing the valid JSON array as requested, add the word 'TERMINATE' on a new line by itself at the very end of your response. Output absolutely nothing after 'TERMINATE'.
    """
    )

    sco_agent = AssistantAgent(
        name="SCOSpecialist",
        llm_config=llm_config,
        system_message="""You are tasked with creating STIX 2.1 Cyber-observable Objects (SCOs) based on the provided threat intelligence write-up.
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
        name="SROSpecialist",
        llm_config=llm_config,
        system_message="""You are a STIX 2.1 Relationship Object (SRO) Specialist.
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
        name="PatternSpecialist",
        llm_config=llm_config,
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
        name="Validator",
        llm_config=llm_config,
        system_message="""
        You are a STIX 2.1 Validation and Bundling Specialist.

        Your tasks are:
        - Review all provided STIX 2.1 objects (SDOs, SCOs, SROs, Indicators).
        - Validate that each object strictly complies with the STIX 2.1 specification.
        - **Correct minor issues if possible. This includes ensuring all required fields are present for each object type.**
        - **For example, `threat-actor` objects MUST have a `labels` property (e.g., `["unknown"]` if no other label is appropriate).**
        - **`malware` objects MUST have `is_family` (as "true" or "false") and `labels`.**
        - **`infrastructure` objects MUST have `labels`.**
        - Ensure `id` properties are correctly formatted (e.g., "threat-actor--<UUID>"). Generate new valid UUIDs if placeholders like "threat-actor--" are present.
        - Ensure timestamps are in ISO 8601 format.
        - Assemble all valid and corrected objects into a single STIX 2.1 Bundle object.
        - Ensure the bundle includes type, id, spec_version ("2.1"), and objects fields.
        - Use a freshly generated bundle ID (e.g., "bundle--<UUID>").
        - The "objects" field must be a list of all validated STIX objects.

        Return ONLY the full STIX 2.1 Bundle as pure JSON.
        Do NOT include any extra text, explanations, comments, or markdown formatting. The output must be parsable by the stix2 Python library without errors.
        IMPORTANT: After providing the valid JSON output as requested, add the word 'TERMINATE' on a new line by itself at the very end of your response. Output absolutely nothing after 'TERMINATE'.
        """
    )

    user_proxy = SafeUserProxyAgent(
        name="UserProxy",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=30,
        is_termination_msg=lambda x: "TERMINATE" in x.get("content", ""),
        code_execution_config={
            "use_docker": False
        }
    )

    # Force cleanup to avoid crash
    user_proxy._code_execution_config = {
        "use_docker": False
    }

    return {
        "orchestrator": orchestrator,
        "ti_analyst": ti_analyst,
        "sdo_agent": sdo_agent,
        "sco_agent": sco_agent,
        "sro_agent": sro_agent,
        "pattern_agent": pattern_agent,
        "validator": validator,
        "user_proxy": user_proxy
    }


# Function to generate STIX content using standard mode
def generate_stix_content(scenario_description):
    # Initialize agents if not already done
    if not st.session_state.agents_initialized:
        st.session_state.ti_expert, st.session_state.stix_formatter, st.session_state.user_proxy = initialize_agents()
        st.session_state.agents_initialized = True
    
    # Access the agents
    ti_expert = st.session_state.ti_expert
    stix_formatter = st.session_state.stix_formatter
    user_proxy = st.session_state.user_proxy
    
    # Clear previous chat history for a new conversation
    chat_messages = []
    
    # Start the conversation
    user_proxy.initiate_chat(
        ti_expert,
        message=f"""
        Please analyze this threat scenario and suggest appropriate STIX 2.1 objects:
        
        {scenario_description}
        
        Focus on identifying key entities, indicators, attack patterns, and relationships.
        """
    )
    
    # Extract chat messages from the conversation
    for msg in user_proxy.chat_messages[ti_expert]:
        chat_messages.append({"role": msg["role"], "content": msg["content"]})
    
    # Now have the STIX formatter convert this into valid STIX JSON
    user_proxy.initiate_chat(
        stix_formatter,
        message=f"""
        Based on the threat analysis below, please create valid STIX 2.1 JSON objects:
        
        {user_proxy.chat_messages[ti_expert][-1]["content"]}
        
        Return only the JSON for each STIX object, properly formatted according to STIX 2.1 specifications.
        """
    )
    
    # Extract more chat messages
    for msg in user_proxy.chat_messages[stix_formatter]:
        chat_messages.append({"role": msg["role"], "content": msg["content"]})
    
    # Store chat history in session state
    st.session_state.chat_history = chat_messages
    
    # Extract STIX objects from the STIX formatter's response
    extract_stix_objects(user_proxy.chat_messages[stix_formatter][-1]["content"])

# Function to generate STIX content using advanced mode
def advanced_stix_generation(scenario_description):
    """Generate STIX content using the advanced multi-agent architecture"""
    # Initialize agents if not already done
    if not st.session_state.advanced_agents_initialized:
        st.session_state.advanced_agents = create_advanced_agents()
        st.session_state.advanced_agents_initialized = True

    # Access agents
    agents = st.session_state.advanced_agents
    user_proxy = agents["user_proxy"]

    # Dictionary to store all conversations and processed outputs
    all_conversations = {}
    processed_outputs = {} # Store the cleaned/parsed output of each step

    # Helper function to extract and parse last response
    # CHANGE: Accept agent_object instead of agent_key (string)
    def get_and_parse_last_response(agent_object):
        agent_name = agent_object.name # Get name for logging if needed
        # CHANGE: Use agent_object as the key
        if agent_object not in user_proxy.chat_messages or not user_proxy.chat_messages[agent_object]:
             st.error(f"No response received from {agent_name} in chat_messages.")
             # Add more debug info
             st.write("Available keys in chat_messages:", list(user_proxy.chat_messages.keys()))
             return None
        try:
            # CHANGE: Use agent_object as the key
            last_message = user_proxy.chat_messages[agent_object][-1]["content"]
            # Remove TERMINATE signal and clean whitespace
            cleaned_json_str = last_message.replace("TERMINATE", "").strip()
            if not cleaned_json_str:
                 st.warning(f"Received empty content (after cleaning) from {agent_name}. Trying previous message.")
                 # CHANGE: Use agent_object as the key
                 if len(user_proxy.chat_messages[agent_object]) > 1:
                      last_message = user_proxy.chat_messages[agent_object][-2]["content"]
                      cleaned_json_str = last_message.replace("TERMINATE", "").strip()
                      if not cleaned_json_str:
                           st.error(f"Previous message from {agent_name} also empty after cleaning.")
                           return None
                 else:
                    st.error(f"Received empty content from {agent_name} and no previous message available.")
                    return None

            # Parse the JSON
            parsed_data = json.loads(cleaned_json_str)
            return parsed_data
        except json.JSONDecodeError as e:
            st.error(f"Failed to parse JSON response from {agent_name}: {e}\nRaw response:\n{last_message}")
            return None
        except Exception as e:
            st.error(f"Error processing response from {agent_name}: {e}\nRaw response:\n{last_message}")
            return None

    # Progress bar for multi-step process
    progress_bar = st.progress(0)
    progress_text = st.empty()

    # --- Step 1: Orchestrator creates a plan (Remains mostly the same) ---
    progress_text.text("Step 1/7: Orchestrator creating a plan...")
    user_proxy.initiate_chat(
        agents["orchestrator"],
        message=f"Create a STIX generation plan for this scenario: {scenario_description}",
        # Clear history for this specific interaction if needed
        clear_history=True
    )
    # Store conversation, generation_plan extracted just for potential debugging/logging
    all_conversations["orchestrator"] = user_proxy.chat_messages.get(agents["orchestrator"], [])
    generation_plan_raw = user_proxy.chat_messages[agents["orchestrator"]][-1]["content"] if all_conversations["orchestrator"] else "No plan generated."
    progress_bar.progress(10)

    # --- Step 2: TI Analyst performs initial analysis ---
    progress_text.text("Step 2/7: Threat Intelligence Analyst analyzing scenario...")
    ti_analyst_input_message = f"""Generate a structured analysis in JSON with these four sections: "sdos", "scos", "relationships", "patterns".

Scenario: {scenario_description}
Do NOT include the original plan in your response, just the JSON analysis.
""" # Removed plan from input to simplify prompt for the analyst
    user_proxy.initiate_chat(
        agents["ti_analyst"],
        message=ti_analyst_input_message,
        clear_history=True
    )
    all_conversations["ti_analyst"] = user_proxy.chat_messages.get(agents["ti_analyst"], [])
    ti_analysis_data = get_and_parse_last_response(agents["ti_analyst"])
    if ti_analysis_data is None: return None # Stop if parsing failed
    processed_outputs["ti_analysis"] = ti_analysis_data
    progress_bar.progress(20)

    # --- Step 3: Generate SDOs ---
    progress_text.text("Step 3/7: Creating STIX Domain Objects (SDOs)...")
    sdo_input_message = f"""
Based on this analysis: {json.dumps(processed_outputs["ti_analysis"], indent=2)}

Create valid STIX Domain Objects (SDOs) as a JSON array for relevant entities identified in the analysis 'sdos' section.
"""
    user_proxy.initiate_chat(
        agents["sdo_agent"],
        message=sdo_input_message,
        clear_history=True
    )
    all_conversations["sdo_agent"] = user_proxy.chat_messages.get(agents["sdo_agent"], [])
    sdo_data = get_and_parse_last_response(agents["sdo_agent"])
    if sdo_data is None: return None
    processed_outputs["sdos"] = sdo_data
    progress_bar.progress(35)

    # --- Step 4: Generate SCOs ---
    progress_text.text("Step 4/7: Creating STIX Cyber Observable Objects (SCOs)...")
    sco_input_message = f"""
Based on this analysis: {json.dumps(processed_outputs["ti_analysis"], indent=2)}

Create valid STIX Cyber Observable Objects (SCOs) as a JSON array for technical observables identified in the 'scos' section.
"""
    user_proxy.initiate_chat(
        agents["sco_agent"],
        message=sco_input_message,
        clear_history=True
    )
    all_conversations["sco_agent"] = user_proxy.chat_messages.get(agents["sco_agent"], [])
    sco_data = get_and_parse_last_response(agents["sco_agent"])
    # It's okay if SCOs are sometimes empty, don't stop execution
    processed_outputs["scos"] = sco_data if sco_data is not None else []
    progress_bar.progress(50)

    # --- Step 5: Generate pattern expressions for indicators ---
    progress_text.text("Step 5/7: Creating indicator patterns...") # Modificato testo progresso
    sco_content_str = json.dumps(processed_outputs.get("scos", []), indent=2)
    # Passare solo le sezioni rilevanti dell'analisi o l'intero scenario se PatternSpecialist ne ha bisogno
    # per nome/descrizione dell'indicatore.
    ti_analysis_for_pattern_str = json.dumps(processed_outputs.get("ti_analysis", {}).get("patterns", []), indent=2)
    scenario_for_pattern_str = scenario_description # Fornire lo scenario originale per il contesto

    pattern_input_message = f"""
    Based on these cyber observables (if any): {sco_content_str}
    And the overall scenario analysis: {ti_analysis_for_pattern_str}

    Generate a JSON array of STIX Indicator objects.
    """
    user_proxy.initiate_chat(
        agents["pattern_agent"],
        message=pattern_input_message,
        clear_history=True
    )
    all_conversations["pattern_agent"] = user_proxy.chat_messages.get(agents["pattern_agent"], [])
    # pattern_data 
    pattern_output_data = get_and_parse_last_response(agents["pattern_agent"])
    
    actual_indicators = []
    if pattern_output_data and isinstance(pattern_output_data, list):
        for item in pattern_output_data:
            if isinstance(item, dict) and item.get("type") == "indicator" and "id" in item:
                actual_indicators.append(item)
            else:
                # Qui si verificava il warning precedente. Con il prompt semplificato,
                # PatternSpecialist dovrebbe restituire direttamente oggetti indicator.
                st.warning(f"PatternSpecialist produced an item that is not a STIX indicator: {item}")
    elif pattern_output_data is not None: # Se non è None ma non è una lista
        st.error(f"PatternSpecialist output was not a list as expected: {pattern_output_data}")
    # Se pattern_output_data è None, get_and_parse_last_response ha già mostrato un errore

    processed_outputs["indicators"] = actual_indicators if actual_indicators else [] # Assicura che sia una lista
    progress_bar.progress(65)

    # --- Step 6: Generate relationships ---
    # Rimuoviamo temporaneamente indicator_relationship_hints dall'input di SROSpecialist
    # Dovrai rivedere il prompt di SROSpecialist per non aspettarseli più
    # o per dedurre le relazioni degli indicatori in altro modo.
    progress_text.text("Step 6/7: Creating relationships between objects...")
    sdo_content_str = json.dumps(processed_outputs.get("sdos", []), indent=2)
    sco_content_str = json.dumps(processed_outputs.get("scos", []), indent=2)
    indicators_content_str = json.dumps(processed_outputs.get("indicators", []), indent=2)
    ti_analysis_str = json.dumps(processed_outputs.get("ti_analysis", {}), indent=2)
    # indicator_hints_str NON è più generato qui

    sro_input_message = f"""
    Based on the following STIX objects:
    SDOs: {sdo_content_str}
    SCOs: {sco_content_str}
    Indicators: {indicators_content_str}

    And the overall threat analysis:
    Threat Analysis: {ti_analysis_str}

    Your task:
    1. Create relationship objects based on the 'relationships' section of the 'Threat Analysis'.
    2. For each Indicator in the 'Indicators' list, if appropriate and supported by the 'Threat Analysis', create an 'indicates' relationship linking it to a relevant SDO (e.g., Malware, Infrastructure, Threat Actor). You will need to infer these relationships based on the indicator's pattern and the SDOs' properties.
    3. You may also create 'attributed-to' relationships from Indicators to Threat Actors if specified or strongly implied.
    4. Ensure all source_ref and target_ref IDs in your relationship objects correctly match the IDs of the SDOs or Indicators provided.
    5. Return a single JSON array of all created STIX Relationship Objects.
    """
    user_proxy.initiate_chat(
        agents["sro_agent"],
        message=sro_input_message,
        clear_history=True
    )
    all_conversations["sro_agent"] = user_proxy.chat_messages.get(agents["sro_agent"], [])
    sro_data = get_and_parse_last_response(agents["sro_agent"])
    processed_outputs["relationships"] = sro_data if sro_data is not None else []
    progress_bar.progress(80)

    # --- Step 7: Validate and format the final bundle ---
    progress_text.text("Step 7/7: Validating and formatting final STIX bundle...")
    # Prepare final inputs for validator
    sdo_content_str = json.dumps(processed_outputs["sdos"], indent=2)
    sco_content_str = json.dumps(processed_outputs["scos"], indent=2)
    pattern_content_str = json.dumps(processed_outputs["indicators"], indent=2)
    sro_content_str = json.dumps(processed_outputs["relationships"], indent=2)

    validator_input_message = f"""
Assemble and validate these STIX objects into a single, valid STIX 2.1 bundle:

SDOs: {sdo_content_str}
SCOs: {sco_content_str}
Indicators: {pattern_content_str}
Relationships: {sro_content_str}

Ensure the final output is a single, complete, valid STIX 2.1 Bundle JSON object. Generate necessary IDs if missing.
"""
    user_proxy.initiate_chat(
        agents["validator"],
        message=validator_input_message,
        clear_history=True
    )
    all_conversations["validator"] = user_proxy.chat_messages.get(agents["validator"], [])
    final_bundle_data = get_and_parse_last_response(agents["validator"])
    if final_bundle_data is None: return None
    processed_outputs["final_bundle"] = final_bundle_data
    progress_bar.progress(100)
    progress_text.text("STIX generation complete!")

    # --- Final Processing ---
    # Instead of calling extract_stix_objects, directly use the final bundle
    if processed_outputs.get("final_bundle"):
        try:
            # Validate the final bundle using stix2 library
            final_bundle_obj = stix2.parse(processed_outputs["final_bundle"], allow_custom=True)
            # Store the validated bundle object
            st.session_state.bundle = final_bundle_obj
            # Extract individual objects from the bundle for display purposes if needed
            st.session_state.stix_objects = final_bundle_obj.objects if hasattr(final_bundle_obj, 'objects') else []
            st.success("STIX Bundle generated and validated successfully!")
        except Exception as e:
            st.error(f"Error parsing or validating the final bundle from Validator: {e}")
            st.session_state.bundle = None
            st.session_state.stix_objects = []
            # Display the potentially invalid JSON for debugging
            st.subheader("Raw JSON from Validator (Potential Error):")
            st.json(processed_outputs["final_bundle"])
    else:
         st.error("Failed to generate the final STIX bundle.")
         st.session_state.bundle = None
         st.session_state.stix_objects = []


    # Return all conversations for display
    st.session_state.advanced_conversations = all_conversations # Store conversations for UI
    return all_conversations # Return conversations

# Function to extract and parse STIX objects from text
def extract_stix_objects(text):
    # Initialize an empty list for STIX objects
    stix_objects = []
    
    # Try to find JSON objects in the text
    try:
        # Look for JSON blocks in markdown format (```json ... ```)
        import re
        json_block_pattern = r'```json\s*(.*?)\s*```'
        json_blocks = re.findall(json_block_pattern, text, re.DOTALL)
        
        if json_blocks:
            for json_str in json_blocks:
                try:
                    # Parse the JSON string
                    stix_dict = json.loads(json_str)
                    
                    # Check if it has a 'type' field, which is required for STIX objects
                    if 'type' in stix_dict and 'id' in stix_dict:
                        # Create a STIX object based on the type
                        if stix_dict['type'] == 'indicator':
                            stix_obj = stix2.Indicator(**stix_dict)
                        elif stix_dict['type'] == 'threat-actor':
                            stix_obj = stix2.ThreatActor(**stix_dict)
                        elif stix_dict['type'] == 'malware':
                            stix_obj = stix2.Malware(**stix_dict)
                        elif stix_dict['type'] == 'identity':
                            stix_obj = stix2.Identity(**stix_dict)
                        elif stix_dict['type'] == 'relationship':
                            stix_obj = stix2.Relationship(**stix_dict)
                        elif stix_dict['type'] == 'attack-pattern':
                            stix_obj = stix2.AttackPattern(**stix_dict)
                        elif stix_dict['type'] == 'campaign':
                            stix_obj = stix2.Campaign(**stix_dict)
                        elif stix_dict['type'] == 'intrusion-set':
                            stix_obj = stix2.IntrusionSet(**stix_dict)
                        elif stix_dict['type'] == 'report':
                            stix_obj = stix2.Report(**stix_dict)
                        elif stix_dict['type'] == 'tool':
                            stix_obj = stix2.Tool(**stix_dict)
                        elif stix_dict['type'] == 'vulnerability':
                            stix_obj = stix2.Vulnerability(**stix_dict)
                        elif stix_dict['type'] == 'course-of-action':
                            stix_obj = stix2.CourseOfAction(**stix_dict)
                        elif stix_dict['type'] == 'infrastructure':
                            stix_obj = stix2.Infrastructure(**stix_dict)
                        elif stix_dict['type'] == 'observed-data':
                            stix_obj = stix2.ObservedData(**stix_dict)
                        elif stix_dict['type'] == 'file':
                            stix_obj = stix2.File(**stix_dict)
                        elif stix_dict['type'] == 'url':
                            stix_obj = stix2.URL(**stix_dict)
                        elif stix_dict['type'] == 'ipv4-addr':
                            stix_obj = stix2.IPv4Address(**stix_dict)
                        elif stix_dict['type'] == 'ipv6-addr':
                            stix_obj = stix2.IPv6Address(**stix_dict)
                        elif stix_dict['type'] == 'domain-name':
                            stix_obj = stix2.DomainName(**stix_dict)
                        elif stix_dict['type'] == 'email-addr':
                            stix_obj = stix2.EmailAddress(**stix_dict)
                        elif stix_dict['type'] == 'bundle':
                            # Try to extract objects from the bundle
                            bundle_objects = []
                            for obj_dict in stix_dict.get('objects', []):
                                if 'type' in obj_dict and 'id' in obj_dict:
                                    try:
                                        if obj_dict['type'] == 'bundle':
                                            continue  # Skip nested bundles
                                        bundle_objects.append(obj_dict)
                                    except Exception as e:
                                        st.warning(f"Error parsing object in bundle: {str(e)}")
                            
                            if bundle_objects:
                                try:
                                    stix_obj = stix2.Bundle(objects=bundle_objects, allow_custom=True)
                                    stix_objects.append(stix_obj)
                                    # Also store the bundle separately
                                    st.session_state.bundle = stix_obj
                                except Exception as e:
                                    st.warning(f"Error creating bundle: {str(e)}")
                            continue  # Skip adding the bundle itself as we've processed its objects
                        else:
                            # For other types, use the generic _STIXBase
                            try:
                                stix_obj = stix2.v21.base._STIXBase(**stix_dict)
                            except Exception as e:
                                st.warning(f"Could not create generic STIX object: {str(e)}")
                                continue
                        
                        stix_objects.append(stix_obj)
                except json.JSONDecodeError:
                    # Not valid JSON
                    pass
                except Exception as e:
                    st.warning(f"Error creating STIX object from JSON block: {str(e)}")
        
        # Also try the existing pattern for JSON objects (between curly braces)
        json_pattern = r'\{(?:[^{}]|(?R))*\}'
        json_matches = re.findall(r'\{(?:[^{}]|(?R))*\}', text)
        
        if json_matches:
            for json_str in json_matches:
                try:
                    # Parse the JSON string
                    stix_dict = json.loads(json_str)
                    
                    # Check if it has a 'type' field, which is required for STIX objects
                    if 'type' in stix_dict and 'id' in stix_dict:
                        # Create a STIX object based on the type
                        if stix_dict['type'] == 'indicator':
                            stix_obj = stix2.Indicator(**stix_dict)
                        elif stix_dict['type'] == 'threat-actor':
                            stix_obj = stix2.ThreatActor(**stix_dict)
                        elif stix_dict['type'] == 'malware':
                            stix_obj = stix2.Malware(**stix_dict)
                        elif stix_dict['type'] == 'identity':
                            stix_obj = stix2.Identity(**stix_dict)
                        elif stix_dict['type'] == 'relationship':
                            stix_obj = stix2.Relationship(**stix_dict)
                        elif stix_dict['type'] == 'attack-pattern':
                            stix_obj = stix2.AttackPattern(**stix_dict)
                        elif stix_dict['type'] == 'campaign':
                            stix_obj = stix2.Campaign(**stix_dict)
                        elif stix_dict['type'] == 'intrusion-set':
                            stix_obj = stix2.IntrusionSet(**stix_dict)
                        elif stix_dict['type'] == 'report':
                            stix_obj = stix2.Report(**stix_dict)
                        elif stix_dict['type'] == 'tool':
                            stix_obj = stix2.Tool(**stix_dict)
                        elif stix_dict['type'] == 'vulnerability':
                            stix_obj = stix2.Vulnerability(**stix_dict)
                        elif stix_dict['type'] == 'course-of-action':
                            stix_obj = stix2.CourseOfAction(**stix_dict)
                        elif stix_dict['type'] == 'infrastructure':
                            stix_obj = stix2.Infrastructure(**stix_dict)
                        elif stix_dict['type'] == 'observed-data':
                            stix_obj = stix2.ObservedData(**stix_dict)
                        elif stix_dict['type'] == 'file':
                            stix_obj = stix2.File(**stix_dict)
                        elif stix_dict['type'] == 'url':
                            stix_obj = stix2.URL(**stix_dict)
                        elif stix_dict['type'] == 'ipv4-addr':
                            stix_obj = stix2.IPv4Address(**stix_dict)
                        elif stix_dict['type'] == 'ipv6-addr':
                            stix_obj = stix2.IPv6Address(**stix_dict)
                        elif stix_dict['type'] == 'domain-name':
                            stix_obj = stix2.DomainName(**stix_dict)
                        elif stix_dict['type'] == 'email-addr':
                            stix_obj = stix2.EmailAddress(**stix_dict)
                        elif stix_dict['type'] == 'bundle':
                            # Try to extract objects from the bundle
                            bundle_objects = []
                            for obj_dict in stix_dict.get('objects', []):
                                if 'type' in obj_dict and 'id' in obj_dict:
                                    try:
                                        if obj_dict['type'] == 'bundle':
                                            continue  # Skip nested bundles
                                        bundle_objects.append(obj_dict)
                                    except Exception as e:
                                        st.warning(f"Error parsing object in bundle: {str(e)}")
                            
                            if bundle_objects:
                                try:
                                    stix_obj = stix2.Bundle(objects=bundle_objects, allow_custom=True)
                                    stix_objects.append(stix_obj)
                                    # Also store the bundle separately
                                    st.session_state.bundle = stix_obj
                                except Exception as e:
                                    st.warning(f"Error creating bundle: {str(e)}")
                            continue  # Skip adding the bundle itself as we've processed its objects
                        else:
                            # For other types, use the generic _STIXBase
                            try:
                                stix_obj = stix2.v21.base._STIXBase(**stix_dict)
                            except Exception as e:
                                st.warning(f"Could not create generic STIX object: {str(e)}")
                                continue
                        
                        stix_objects.append(stix_obj)
                except json.JSONDecodeError:
                    # Not valid JSON
                    pass
                except Exception as e:
                    st.warning(f"Error creating STIX object: {str(e)}")
        
        # Attempt to find a full bundle in the text
        bundle_match = re.search(r'\{"type"\s*:\s*"bundle".*\}', text, re.DOTALL)
        if bundle_match:
            try:
                bundle_dict = json.loads(bundle_match.group(0))
                if 'type' in bundle_dict and bundle_dict['type'] == 'bundle' and 'objects' in bundle_dict:
                    # Create STIX objects from the bundle
                    bundle_objects = []
                    for obj_dict in bundle_dict['objects']:
                        try:
                            # Using _STIXBase as a generic way to create objects
                            obj = stix2.v21.base._STIXBase(**obj_dict)
                            bundle_objects.append(obj)
                            if obj not in stix_objects:
                                stix_objects.append(obj)
                        except Exception as e:
                            st.warning(f"Error parsing object in bundle: {str(e)}")
                    
                    # Create a bundle with all the objects
                    if bundle_objects:
                        st.session_state.bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
            except json.JSONDecodeError:
                pass
            except Exception as e:
                st.warning(f"Error processing bundle: {str(e)}")
    except Exception as e:
        st.error(f"Error extracting STIX objects: {str(e)}")
    
    # Store the STIX objects in session state
    st.session_state.stix_objects = stix_objects
    
    # Create a STIX bundle if we have objects and no bundle was created yet
    if stix_objects and not st.session_state.bundle:
        try:
            st.session_state.bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)
        except Exception as e:
            st.error(f"Error creating STIX bundle: {str(e)}")

# Add input type selection
input_type = st.radio(
    "Select input method:",
    ["Direct Description", "Web Threat Report", "PDF Upload"],
    help="Choose how you want to provide threat intelligence information."
)

# Create placeholders for different input types
direct_input_container = st.empty()
web_input_container = st.empty()
pdf_input_container = st.empty()

# Display appropriate input based on selection
if input_type == "Direct Description":
    with direct_input_container.container():
        scenario_description = st.text_area(
            "Describe the threat scenario in detail. Include information about actors, malware, indicators, and any relationships.",
            height=150
        )
elif input_type == "Web Threat Report":
    with web_input_container.container():
        url = st.text_input("Enter URL of the threat report:")
        if url:
            with st.spinner("Extracting content from webpage..."):
                content, error = extract_web_content(url)
                if error:
                    st.error(error)
                    scenario_description = ""
                else:
                    st.success("Content extracted successfully!")
                    with st.expander("Preview extracted content", expanded=False):
                        st.markdown(content[:1000] + "..." if len(content) > 1000 else content)
                    scenario_description = content
        else:
            scenario_description = ""
else:  # PDF Upload
    with pdf_input_container.container():
        uploaded_file = st.file_uploader("Upload PDF threat report", type="pdf")
        if uploaded_file is not None:
            with st.spinner("Extracting content from PDF..."):
                content, error = extract_pdf_content(uploaded_file)
                if error:
                    st.error(error)
                    scenario_description = ""
                else:
                    st.success("Content extracted successfully!")
                    with st.expander("Preview extracted content", expanded=False):
                        st.markdown(content[:1000] + "..." if len(content) > 1000 else content)
                    scenario_description = content
        else:
            scenario_description = ""

# Generate button
if st.button("Generate STIX Content"):
    if not scenario_description:
        st.warning("Please provide input using one of the available methods.")
    else:
        if mode == "Standard":
            with st.spinner("Agents are collaborating to generate STIX content..."):
                generate_stix_content(scenario_description)
        else:  # Advanced mode
            st.session_state.advanced_conversations = advanced_stix_generation(scenario_description)

# Display results based on the selected mode
if mode == "Standard":
    tab1, tab2, tab3 = st.tabs(["Agent Conversation", "STIX Objects", "JSON Output"])
    
    with tab1:
        st.header("Agent Conversation")
        
        if 'chat_history' in st.session_state and st.session_state.chat_history:
            for msg in st.session_state.chat_history:
                st.markdown(f"**{msg['role'].capitalize()}**: {msg['content']}")
        else:
            st.info("Generate STIX content to see agent conversation.")
    
    with tab2:
        st.header("Generated STIX Objects")
        
        if 'stix_objects' in st.session_state and st.session_state.stix_objects:
            for i, obj in enumerate(st.session_state.stix_objects):
                with st.expander(f"{obj.type.capitalize()} - {obj.id}"):
                    # Display object properties
                    for prop, value in obj.items():
                        if prop not in ['id', 'type']:
                            st.write(f"**{prop}:** {value}")
        else:
            st.info("Generate STIX content to see STIX objects.")
    
    with tab3:
        st.header("STIX JSON Output")
        
        if 'bundle' in st.session_state and st.session_state.bundle:
            st.json(st.session_state.bundle.serialize())
            
            # Add download button
            json_str = json.dumps(st.session_state.bundle.serialize(), indent=4)
            st.download_button(
                label="Download STIX Bundle",
                data=json_str,
                file_name="stix_bundle.json",
                mime="application/json"
            )
        else:
            st.info("Generate STIX content to see JSON output.")
else:
    # Advanced mode tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Agent Conversations", "STIX Objects", "JSON Output", "Visualization"])
    
    with tab1:
        st.header("Agent Conversations")
        
        if 'advanced_conversations' in st.session_state and st.session_state.advanced_conversations:
            agent_names = ["orchestrator", "ti_analyst", "sdo_agent", "sco_agent", 
                          "pattern_agent", "sro_agent", "validator"]
            
            for agent_name in agent_names:
                if agent_name in st.session_state.advanced_conversations:
                    with st.expander(f"{agent_name.replace('_', ' ').title()}"):
                        for msg in st.session_state.advanced_conversations[agent_name]:
                            st.markdown(f"**{msg['role'].capitalize()}**: {msg['content']}")
        else:
            st.info("Generate STIX content using Advanced mode to see agent conversations.")
    
    with tab2:
        st.header("Generated STIX Objects")
        
        if 'stix_objects' in st.session_state and st.session_state.stix_objects:
            # Create columns for different object types
            col1, col2, col3 = st.columns(3)
            
            # Group objects by type
            sdo_objects = []
            sco_objects = []
            sro_objects = []
            
            for obj in st.session_state.stix_objects:
                # SDO types
                if obj.type in ['threat-actor', 'malware', 'attack-pattern', 'campaign', 
                               'identity', 'intrusion-set', 'report', 'tool', 
                               'vulnerability', 'course-of-action', 'infrastructure']:
                    sdo_objects.append(obj)
                # SCO types
                elif obj.type in ['file', 'ipv4-addr', 'ipv6-addr', 'url', 'domain-name', 
                                 'email-addr', 'network-traffic', 'process', 'artifact',
                                 'x509-certificate']:
                    sco_objects.append(obj)
                # SRO types
                elif obj.type in ['relationship', 'sighting'] or obj.type == 'indicator':
                    # Indicators are technically SDOs but we're grouping them with SROs for UI purposes
                    sro_objects.append(obj)
            
            # Display SDOs in first column
            with col1:
                st.subheader("Domain Objects (SDOs)")
                if sdo_objects:
                    for obj in sdo_objects:
                        with st.expander(f"{obj.type.capitalize()} - {obj.id.split('--')[1][:8]}..."):
                            for prop, value in obj.items():
                                if prop not in ['id', 'type']:
                                    st.write(f"**{prop}:** {value}")
                else:
                    st.info("No domain objects generated.")
            
            # Display SCOs in second column
            with col2:
                st.subheader("Cyber Observables (SCOs)")
                if sco_objects:
                    for obj in sco_objects:
                        with st.expander(f"{obj.type.capitalize()} - {obj.id.split('--')[1][:8]}..."):
                            for prop, value in obj.items():
                                if prop not in ['id', 'type']:
                                    st.write(f"**{prop}:** {value}")
                else:
                    st.info("No cyber observables generated.")
            
            # Display SROs in third column
            with col3:
                st.subheader("Relationships & Indicators")
                if sro_objects:
                    for obj in sro_objects:
                        with st.expander(f"{obj.type.capitalize()} - {obj.id.split('--')[1][:8]}..."):
                            for prop, value in obj.items():
                                if prop not in ['id', 'type']:
                                    st.write(f"**{prop}:** {value}")
                else:
                    st.info("No relationships or indicators generated.")
        else:
            st.info("Generate STIX content to see STIX objects.")
    
    with tab3:
        st.header("STIX JSON Output")
        
        if 'bundle' in st.session_state and st.session_state.bundle:
            st.json(st.session_state.bundle.serialize())
            
            # Add download button
            json_str = json.dumps(st.session_state.bundle.serialize(), indent=4)
            st.download_button(
                label="Download STIX Bundle",
                data=json_str,
                file_name="stix_bundle.json",
                mime="application/json"
            )
        else:
            st.info("Generate STIX content to see JSON output.")
    
    with tab4:
        st.header("STIX Visualization")
        
        if 'stix_objects' in st.session_state and st.session_state.stix_objects:
            st.warning("Visualization feature is under development. In the future, this will show a network graph of STIX objects and their relationships.")
            
            # Placeholder for visualization
            st.info("A graph visualization would appear here showing relationships between STIX objects.")
            
            # You could integrate with libraries like pyvis, networkx, or d3.js for visualization
            # For now, just display a simple list of relationships
            relationships = [obj for obj in st.session_state.stix_objects if obj.type == 'relationship']
            
            if relationships:
                st.subheader("Relationship Summary")
                for rel in relationships:
                    try:
                        source_id = rel.source_ref
                        target_id = rel.target_ref
                        rel_type = rel.relationship_type
                        
                        # Find source and target object names if possible
                        source_name = source_id
                        target_name = target_id
                        
                        for obj in st.session_state.stix_objects:
                            if obj.id == source_id and hasattr(obj, 'name'):
                                source_name = obj.name
                            if obj.id == target_id and hasattr(obj, 'name'):
                                target_name = obj.name
                        
                        st.write(f"**{source_name}** *{rel_type}* **{target_name}**")
                    except Exception as e:
                        st.error(f"Error displaying relationship: {str(e)}")
            else:
                st.info("No relationships found to visualize.")
        else:
            st.info("Generate STIX content to see visualization.")

# Add footer
st.markdown("---")
st.markdown("📝 **STIX 2.1 Generator** | This app uses AI agents to generate structured threat intelligence in STIX 2.1 format")
st.markdown("Built with ❤️ using AutoGen, Streamlit, and the STIX2 library")