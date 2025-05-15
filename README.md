# Agentic GenAI STIX 2.1 Generator

🛡️ **Agentic GenAI STIX 2.1 Generator** is a Streamlit web application that leverages the power of AI agents (powered by Microsoft Autogen and Azure OpenAI) to assist users in generating Structured Threat Intelligence eXchange (STIX) 2.1 content. Users can describe a threat intelligence scenario, provide a URL to a web-based threat report, or upload a PDF document, and the application will process the input to produce STIX 2.1 objects and bundles.

**Note:** This project is currently in an **early stage of development and testing**. Features and agent interactions are subject to change and refinement.

## Features

* **STIX 2.1 Generation:** Creates STIX Domain Objects (SDOs), Cyber Observable Objects (SCOs), Relationship Objects (SROs), and Indicators.
* **Multiple Input Methods:**
    * Direct text description of a threat scenario.
    * URL of a web-based threat report.
    * Upload of a PDF threat report.
* **Two Generation Modes:**
    * **Standard Mode:** A simpler two-agent setup for quick STIX object suggestions and formatting.
    * **Advanced (Multi-Agent) Mode:** A sophisticated pipeline of specialized AI agents for more detailed and structured STIX bundle generation.
* **AI-Powered Analysis:** Utilizes Autogen framework with Large Language Models (LLMs) via Azure OpenAI to understand and convert threat information.
* **Interactive UI:** Built with Streamlit, providing an intuitive interface for input, mode selection, and viewing results.
* **Safe Code Execution:** Implements a `SafeUserProxyAgent` to prevent the execution of potentially harmful code, especially when parsing JSON or YAML from agent responses.
* **Result Display:** Shows agent conversations, individual STIX objects, and the final STIX bundle in JSON format.
* **Downloadable Output:** Allows downloading of the generated STIX 2.1 bundle as a JSON file.

## Modes of Operation

The application offers two distinct modes for generating STIX content:

### 1. Standard Mode

This mode employs a basic two-agent workflow:

* **Agents Used:**
    1.  **`ThreatIntelligenceExpert`**: An `AssistantAgent` that analyzes the input threat scenario and suggests appropriate STIX 2.1 objects. It focuses on identifying key entities, indicators, attack patterns, and relationships.
    2.  **`STIXFormatter`**: An `AssistantAgent` that takes the analysis from the `ThreatIntelligenceExpert` and converts it into valid STIX 2.1 JSON. It ensures that all STIX objects have required fields and follow the proper format.
    3.  **`SafeUserProxyAgent`**: A custom `UserProxyAgent` that facilitates the conversation between the user (implicitly, through the app) and the assistant agents. It is configured to prevent direct code execution of JSON/YAML returned by agents, enhancing security.

* **Workflow:**
    1.  The user provides a threat scenario (text, URL, or PDF).
    2.  The input is passed to the `ThreatIntelligenceExpert`.
    3.  The `ThreatIntelligenceExpert` processes the scenario and proposes STIX objects.
    4.  The output from the `ThreatIntelligenceExpert` is then sent to the `STIXFormatter`.
    5.  The `STIXFormatter` generates STIX 2.1 compliant JSON.
    6.  The application parses this JSON to extract STIX objects and display them.

### 2. Advanced (Multi-Agent) Mode

This mode utilizes a more complex pipeline of specialized agents, each responsible for a specific part of the STIX generation process. This allows for a more granular and potentially more accurate STIX bundle.

* **Agents Used:**
    1.  **`Orchestrator`**: An `AssistantAgent` that initially plans the sequence of steps for generating the STIX bundle based on the input scenario.
    2.  **`ThreatAnalyst`**: An `AssistantAgent` that analyzes the threat scenario and returns a structured JSON object detailing candidate SDOs, SCOs, potential relationships, and patterns for indicators.
    3.  **`SDOSpecialist`**: An `AssistantAgent` focused on creating valid STIX 2.1 Domain Objects (e.g., `threat-actor`, `malware`, `identity`) based on the `ThreatAnalyst`'s output.
    4.  **`SCOSpecialist`**: An `AssistantAgent` dedicated to creating STIX 2.1 Cyber Observable Objects (e.g., `ipv4-addr`, `file`, `url`) from the analysis.
    5.  **`PatternSpecialist`**: An `AssistantAgent` that generates STIX Indicator objects, including their STIX patterns, based on the identified SCOs and analytical hints.
    6.  **`SROSpecialist`**: An `AssistantAgent` responsible for creating STIX Relationship Objects that link the various SDOs, SCOs, and Indicators together.
    7.  **`Validator`**: An `AssistantAgent` that takes all generated STIX objects, performs a final validation check, and assembles them into a single, compliant STIX 2.1 Bundle.
    8.  **`SafeUserProxyAgent`**: Similar to Standard Mode, this agent manages the interactions within the pipeline and ensures non-execution of textual data like JSON.

* **Workflow:**
    1.  User provides the threat scenario.
    2.  (Optional initial planning by `Orchestrator`).
    3.  The `ThreatAnalyst` receives the scenario and produces a structured JSON breakdown (entities, observables, relationships, patterns).
    4.  The `SDOSpecialist` receives the SDO candidates from the `ThreatAnalyst`'s output and generates full SDO JSON objects.
    5.  The `SCOSpecialist` receives the observable candidates and generates full SCO JSON objects.
    6.  The `PatternSpecialist` receives the SCOs and pattern suggestions and generates STIX Indicator JSON objects.
    7.  The `SROSpecialist` receives all generated SDOs, SCOs, Indicators, and relationship hints from the `ThreatAnalyst` to create STIX Relationship JSON objects.
    8.  The `Validator` gathers all SDOs, SCOs, Indicators, and SROs, validates them, and assembles them into a final STIX 2.1 Bundle JSON.
    9.  The application parses the final bundle for display and download.

## Setup

### Prerequisites

* Python 3.8+
* Access to Azure OpenAI Service:
    * An Azure OpenAI endpoint.
    * An API Key.
    * A deployment name for a suitable model (e.g., GPT-3.5-turbo, GPT-4).
    * The API version.

### Installation

1.  **Clone the repository (if applicable) or download the `app.py` file.**
2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    # On Windows
    venv\Scripts\activate