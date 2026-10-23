# SENTRY — Security Event Detection & Threat Investigation Platform

SENTRY is a Python-based mini Security Information and Event Management (SIEM) and Security Operations Center (SOC) platform. It processes security logs, detects suspicious activity, calculates risk scores, correlates related events, enriches alerts with local threat intelligence, and organizes findings into incidents for investigation.

The project includes a Streamlit dashboard for reviewing alerts, investigating incidents, managing analyst notes, and maintaining an offline threat-intelligence feed.

## Key Features

- **Log collection and parsing:** Collects sample security logs and converts them into structured events.
- **Security detection:** Applies detection rules to identify suspicious activity.
- **Risk scoring:** Calculates risk scores and assigns risk levels to detected activity.
- **Event correlation:** Groups related events to identify potentially connected security activity.
- **Incident management:** Creates incidents from correlated alerts and records relevant evidence and timelines.
- **Offline threat intelligence:** Enriches alerts using a local JSON feed of IP indicators.
- **Threat feed management:** Supports adding, updating, viewing, and removing local IP indicators.
- **Incident persistence:** Uses SQLite-backed storage for incident records, statuses, and analyst notes.
- **SOC dashboard:** Displays security metrics, alerts, correlations, processed events, threat-intelligence findings, and incident investigations.
- **Automated testing:** Uses pytest to validate application behavior.

## Architecture

The primary processing workflow is:

```text
Security Logs
     |
     v
Log Collection
     |
     v
Log Parsing
     |
     v
Detection Engine
     |
     v
Risk Scoring
     |
     v
Threat Intelligence Enrichment
     |
     v
Event Correlation
     |
     v
Incident Creation
     |
     v
SQLite Incident Storage
     |
     v
Streamlit SOC Dashboard
```

The pipeline also exposes processed events, alerts, correlations, and incidents to the dashboard.

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Dashboard | Streamlit |
| Data presentation | Pandas |
| Incident persistence | SQLite |
| Threat-intelligence storage | JSON |
| Automated testing | pytest |
| Development environment | Python virtual environment |

## Project Structure

```text
Sentry.soc/
├── app/
│   ├── __init__.py
│   ├── log_collector.py
│   ├── log_parser.py
│   ├── detection_engine.py
│   ├── risk_engine.py
│   ├── correlation_engine.py
│   ├── incident_engine.py
│   ├── incident_store.py
│   ├── pipeline.py
│   ├── threat_intel.py
│   └── threat_feed_manager.py
├── data/
│   └── threat_feed.json
├── dashboard/
│   └── dashboard.py
├── logs/
│   └── sample.log
├── rules/
│   ├── auth_rules.py
│   └── network_rules.py
├── tests/
│   ├── test_threat_intel.py
│   └── test_threat_feed_manager.py
├── venv/
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

The `venv/` directory is a local development environment and should not be committed to Git.

## Installation

### Prerequisites

- Python installed on your system
- Git
- A terminal such as PowerShell
- A web browser to access the dashboard

### 1. Clone the repository

```powershell
git clone https://github.com/Sukumar-Git/mini-siem-soc-dashboard.git
cd mini-siem-soc-dashboard
```

If your GitHub repository uses a different name, substitute its actual repository URL and directory.

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
python -m venv venv
```

### 3. Activate the environment

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

## Running SENTRY

### Run the security event pipeline

From the project root:

```powershell
python -m app.pipeline
```

This executes the processing pipeline and prints its results, including processed events, generated alerts, correlations, and incidents.

### Launch the SOC dashboard

```powershell
python -m streamlit run dashboard\dashboard.py
```

Open the local URL displayed by Streamlit, normally:

```text
http://localhost:8501
```

## Using the Dashboard

The SENTRY dashboard provides several sections for reviewing security activity.

### Security Overview

Displays event counts, generated alerts, incident statuses, and threat-intelligence metrics.

### Incident Management

Supports filtering incidents by risk level, type, and status. Selecting an incident opens its investigation details, including risk information, evidence, related events, and timeline.

### Security Alerts

Displays detection results, alert severity, risk scores, source IP addresses, and available threat-intelligence enrichment.

### Event Correlations

Shows correlations produced by the correlation engine, including source IP, event counts, time windows, and correlation reasons.

### Processed Security Events

Displays the structured security events produced by the pipeline.

### Threat Intelligence

Enriches alert source IP addresses against the local feed and displays matching information.

### Threat Intelligence Feed Management

Allows an analyst to view and maintain the local feed by adding, updating, and removing IP indicators.

## Local Threat Intelligence

SENTRY uses `data/threat_feed.json` to store IP indicators and their associated categories and descriptions.

Example entry:

```json
{
    "203.0.113.60": {
        "category": "test_indicator",
        "description": "Synthetic indicator for offline testing."
    }
}
```

The IP above belongs to a documentation-only address range and is suitable for demonstrations.

**Important limitations:**

- The local feed does not perform live threat-intelligence lookups.
- An IP absent from the feed is considered unmatched or unknown, not automatically safe.
- A feed match means the IP matches a locally configured indicator; it does not independently establish that the address is malicious.
- Demonstration indicators should not be treated as real threat intelligence.

## Running Tests

Run the complete automated test suite from the project root:

```powershell
python -m pytest
```

To run only threat-intelligence feed-management tests:

```powershell
python -m pytest tests\test_threat_feed_manager.py -v
```

To run only threat-intelligence enrichment tests:

```powershell
python -m pytest tests\test_threat_intel.py -v
```

The project test suite has passed locally during development. Run the tests in your current environment to verify the code after any changes.

## Data and Security Considerations

- Use the supplied sample logs for demonstrations and development.
- Keep API keys, credentials, private logs, and other sensitive information out of the repository.
- Review `.gitignore` before committing project files.
- The dashboard is a development prototype, not a production SIEM deployment.
- Validate local threat indicators before relying on them during an investigation.
- Review persistence, access control, logging, and deployment security before using the platform with real security data.

## Future Improvements

Potential future work, if required by project objectives, includes additional detection rules, richer investigation reporting, improved test coverage, and integration with trusted external threat-intelligence providers.

These are optional enhancements and are not claims about currently implemented functionality.

## Project Status

The current implementation includes the security event processing pipeline, risk scoring, correlation, incident creation and persistence, offline threat-intelligence enrichment, feed management, automated tests, and a Streamlit dashboard.

## License

See the `LICENSE` file in this repository for the applicable license terms.
