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

# Load environment variables
load_dotenv()

# Set the page configuration
st.set_page_config(
    page_title="STIX 2.1 Generator",
    page_icon="🛡️",
    layout="wide"
)

# App title and description
st.title("🛡️ GenAI STIX 2.1 Generator")
st.markdown("""
This application uses AI agents to help you generate STIX 2.1 content. 
You can describe a threat intelligence scenario, and the agents will collaborate to create structured STIX objects.
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

# Function to initialize the standard AutoGen agents
def initialize_agents():
    # Configure LLM
    config_list = [
        {
            "model": "gpt-4",
            "api_key": os.environ.get("OPENAI_API_KEY")
        }
    ]
    
    # Create a threat intelligence expert agent
    ti_expert = AssistantAgent(
        name="ThreatIntelligenceExpert",
        llm_config={"config_list": config_list},
        system_message="""You are a threat intelligence expert who specializes in creating STIX 2.1 content.
        Your job is to analyze threat scenarios and convert them into appropriate STIX objects.
        Focus on technical accuracy and adherence to the STIX 2.1 standard."""
    )
    
    # Create a STIX formatter agent
    stix_formatter = AssistantAgent(
        name="STIXFormatter",
        llm_config={"config_list": config_list},
        system_message="""You are a STIX 2.1 specialist who converts threat information into valid STIX JSON.
        You ensure that all STIX objects have required fields and follow the proper format.
        You only output valid STIX 2.1 JSON that can be parsed by the stix2 Python library."""
    )
    
    # Create a user proxy agent that interacts with the human
    user_proxy = UserProxyAgent(
        name="UserProxy",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=10,
        is_termination_msg=lambda x: "TERMINATE" in x.get("content", ""),
        code_execution_config={"use_docker": False},
    )
    
    return ti_expert, stix_formatter, user_proxy

# Function to initialize the advanced AutoGen agents
def create_advanced_agents():
    """Create specialized agents for advanced STIX generation"""
    config_list = [{"model": "gpt-4", "api_key": os.environ.get("OPENAI_API_KEY")}]
    llm_config = {"config_list": config_list}
    
    # Create specialized agents
    orchestrator = AssistantAgent(
        name="Orchestrator",
        llm_config=llm_config,
        system_message="""You are an orchestration agent that coordinates the creation of STIX 2.1 content.
        Your job is to analyze threat scenarios, distribute work to specialized agents, and ensure a coherent final product.
        You should identify what types of STIX objects will be needed and create a plan for their creation."""
    )
    
    ti_analyst = AssistantAgent(
        name="ThreatAnalyst",
        llm_config=llm_config,
        system_message="""You are a threat intelligence analyst who analyzes scenarios to identify key components.
        Your job is to break down a scenario into entities, actions, and technical observables that can be converted to STIX.
        Identify threat actors, malware, tools, attack patterns, and technical indicators."""
    )
    
    sdo_agent = AssistantAgent(
        name="SDOSpecialist",
        llm_config=llm_config,
        system_message="""You are a specialist in STIX 2.1 Domain Objects (SDOs).
        Create valid SDOs including threat-actors, malware, attack-patterns, campaigns, identities, and intrusion-sets.
        Ensure each object has all required properties and follows STIX 2.1 specifications.
        For each object, include:
        - id (use the format 'object-type--uuid')
        - type
        - spec_version (should be '2.1')
        - created and modified timestamps (in ISO format)
        - required fields specific to each object type
        Return only valid JSON objects."""
    )
    
    sco_agent = AssistantAgent(
        name="SCOSpecialist",
        llm_config=llm_config,
        system_message="""You are a specialist in STIX 2.1 Cyber Observable Objects (SCOs).
        Create valid SCOs including files, ipv4-addr, ipv6-addr, url, network-traffic, and artifacts.
        Ensure each object has all required properties and follows STIX 2.1 specifications.
        For each object, include:
        - id (use the format 'object-type--uuid')
        - type
        - spec_version (should be '2.1')
        - required fields specific to each object type
        Return only valid JSON objects."""
    )
    
    sro_agent = AssistantAgent(
        name="SROSpecialist",
        llm_config=llm_config,
        system_message="""You are a specialist in STIX 2.1 Relationship Objects (SROs).
        Create valid relationships between STIX objects with appropriate relationship types.
        Ensure all references point to valid objects and relationship types are appropriate.
        For each relationship, include:
        - id (use the format 'relationship--uuid')
        - type (should be 'relationship')
        - spec_version (should be '2.1')
        - created and modified timestamps (in ISO format)
        - source_ref (the ID of the source object)
        - target_ref (the ID of the target object)
        - relationship_type (e.g., 'uses', 'targets', 'mitigates')
        Return only valid JSON objects."""
    )
    
    pattern_agent = AssistantAgent(
        name="PatternSpecialist",
        llm_config=llm_config,
        system_message="""You are a specialist in STIX 2.1 patterns used in indicators.
        Create valid STIX pattern expressions following the pattern grammar.
        Ensure patterns accurately represent the observable data they are meant to detect.
        For each indicator, include:
        - id (use the format 'indicator--uuid')
        - type (should be 'indicator')
        - spec_version (should be '2.1')
        - created and modified timestamps (in ISO format)
        - name
        - description
        - indicator_types
        - pattern (using STIX patterning language)
        - pattern_type (should be 'stix')
        - valid_from (timestamp in ISO format)
        Return only valid JSON objects."""
    )
    
    validator = AssistantAgent(
        name="Validator",
        llm_config=llm_config,
        system_message="""You are a STIX 2.1 validator and formatter.
        Ensure all STIX objects conform to the specification, have required properties, and form a valid bundle.
        Fix any issues in the objects and create the final STIX bundle.
        Verify that:
        - All object IDs follow the correct format
        - All required properties are present
        - All references point to existing objects
        - Timestamps are in the correct ISO format
        - Object types are valid STIX types
        Return the complete and valid STIX bundle as JSON."""
    )
    
    user_proxy = UserProxyAgent(
        name="UserProxy",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=10,
        is_termination_msg=lambda x: "TERMINATE" in x.get("content", ""),
        code_execution_config={"use_docker": False}
    )
    
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
    
    # Dictionary to store all conversations
    all_conversations = {}
    
    # Progress bar for multi-step process
    progress_bar = st.progress(0)
    progress_text = st.empty()
    
    # Step 1: Orchestrator creates a plan (10%)
    progress_text.text("Step 1/7: Orchestrator creating a plan...")
    user_proxy.initiate_chat(
        agents["orchestrator"],
        message=f"Create a STIX generation plan for this scenario: {scenario_description}"
    )
    generation_plan = user_proxy.chat_messages[agents["orchestrator"]][-1]["content"]
    all_conversations["orchestrator"] = user_proxy.chat_messages[agents["orchestrator"]]
    progress_bar.progress(10)
    
    # Step 2: TI Analyst performs initial analysis (20%)
    progress_text.text("Step 2/7: Threat Intelligence Analyst analyzing scenario...")
    user_proxy.initiate_chat(
        agents["ti_analyst"],
        message=f"""
        Based on this plan: {generation_plan}
        
        Analyze this threat scenario: {scenario_description}
        
        Identify key entities, technical observables, and their relationships.
        """
    )
    ti_analysis = user_proxy.chat_messages[agents["ti_analyst"]][-1]["content"]
    all_conversations["ti_analyst"] = user_proxy.chat_messages[agents["ti_analyst"]]
    progress_bar.progress(20)
    
    # Step 3: Generate SDOs (35%)
    progress_text.text("Step 3/7: Creating STIX Domain Objects (SDOs)...")
    user_proxy.initiate_chat(
        agents["sdo_agent"],
        message=f"""
        Based on this analysis: {ti_analysis}
        
        Create valid STIX Domain Objects (SDOs) for all entities identified in the analysis.
        Return each object as valid JSON.
        """
    )
    sdo_content = user_proxy.chat_messages[agents["sdo_agent"]][-1]["content"]
    all_conversations["sdo_agent"] = user_proxy.chat_messages[agents["sdo_agent"]]
    progress_bar.progress(35)
    
    # Step 4: Generate SCOs (50%)
    progress_text.text("Step 4/7: Creating STIX Cyber Observable Objects (SCOs)...")
    user_proxy.initiate_chat(
        agents["sco_agent"],
        message=f"""
        Based on this analysis: {ti_analysis}
        
        Create valid STIX Cyber Observable Objects (SCOs) for all technical observables identified.
        Return each object as valid JSON.
        """
    )
    sco_content = user_proxy.chat_messages[agents["sco_agent"]][-1]["content"]
    all_conversations["sco_agent"] = user_proxy.chat_messages[agents["sco_agent"]]
    progress_bar.progress(50)
    
    # Step 5: Generate pattern expressions for indicators (65%)
    progress_text.text("Step 5/7: Creating indicator patterns...")
    user_proxy.initiate_chat(
        agents["pattern_agent"],
        message=f"""
        Based on these cyber observables: {sco_content}
        And the scenario analysis: {ti_analysis}
        
        Create STIX pattern expressions for these observables and construct indicator objects that use these patterns.
        Return each indicator object as valid JSON.
        """
    )
    pattern_content = user_proxy.chat_messages[agents["pattern_agent"]][-1]["content"]
    all_conversations["pattern_agent"] = user_proxy.chat_messages[agents["pattern_agent"]]
    progress_bar.progress(65)
    
    # Step 6: Generate relationships (80%)
    progress_text.text("Step 6/7: Creating relationships between objects...")
    user_proxy.initiate_chat(
        agents["sro_agent"],
        message=f"""
        Based on the following STIX objects:
        
        SDOs: {sdo_content}
        SCOs: {sco_content}
        Indicators: {pattern_content}
        
        Create relationship objects that connect these objects according to the analysis: {ti_analysis}
        Return each relationship object as valid JSON.
        """
    )
    sro_content = user_proxy.chat_messages[agents["sro_agent"]][-1]["content"]
    all_conversations["sro_agent"] = user_proxy.chat_messages[agents["sro_agent"]]
    progress_bar.progress(80)
    
    # Step 7: Validate and format the final bundle (100%)
    progress_text.text("Step 7/7: Validating and formatting final STIX bundle...")
    user_proxy.initiate_chat(
        agents["validator"],
        message=f"""
        Validate and format these STIX objects into a valid bundle:
        
        SDOs: {sdo_content}
        SCOs: {sco_content}
        Indicators: {pattern_content}
        Relationships: {sro_content}
        
        Ensure all objects have the required properties and fix any issues.
        Return the complete and valid STIX bundle as JSON.
        """
    )
    final_bundle = user_proxy.chat_messages[agents["validator"]][-1]["content"]
    all_conversations["validator"] = user_proxy.chat_messages[agents["validator"]]
    progress_bar.progress(100)
    progress_text.text("STIX generation complete!")
    
    # Extract STIX objects from the final bundle
    extract_stix_objects(final_bundle)
    
    # Return all conversations for display
    return all_conversations

# Function to extract and parse STIX objects from text
def extract_stix_objects(text):
    # Initialize an empty list for STIX objects
    stix_objects = []
    
    # Try to find JSON objects in the text
    try:
        # Look for JSON-like content (between curly braces)
        import re
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

# Create input area
st.header("Describe Your Threat Intelligence Scenario")
scenario_description = st.text_area(
    "Describe the threat scenario in detail. Include information about actors, malware, indicators, and any relationships.",
    height=150
)

# Generate button
if st.button("Generate STIX Content"):
    if not scenario_description:
        st.warning("Please enter a threat scenario description.")
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