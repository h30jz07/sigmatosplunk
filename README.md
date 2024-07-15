# SIGMA Rule Convertor 
This Python script converts SIGMA rules to queries for various SIEMs. It supports converting multiple SIGMA rule files (in YAML format) into corresponding queries based on specified backend and optional custom pipelines.

## Usage
`cli here`
### Options
1. File source
   - Folder path
   - File path
   - (Default) Current folder
2. Output Formats
   - (Default) Plain SPL queries
   - `savedsearches`: Plain SPL in a savedsearches.conf file
   - `data_model`: Data model queries with tstats
   - `stanza`: Enterprise Security savedsearches.conf stanza
3. Backends
   - `opensearch` | `elasticsearch`: For LogRhythm and Lucene queries
   - `splunk`: Splunk SIEM
   - The following may not produce working queries. Use with care
   - `carbonblack`: "Carbon Black EDR"
   - `cortexxdr`: "Palo Alto Cortex XDR"
   - `crowdstrike_splunk`: "Crowdstrike Splunk Query"
   - `insightidr`: "Rapid7 InsightIDR SIEM"
   - `loki`: "Grafana Loki LogQL SIEM"
   - `microsoft365defender`: "Microsoft 365 Defender Advanced Hunting Query (KQL)"
   - `qradar`: "IBM QRadar"
   - `sentinelone`: "SentinelOne EDR"
   - `sigma`: "Original YAML/JSON Sigma Rule Output"
   - `stix`: "STIX 2.0 & STIX Shifter Queries"
4. Pipelines
   - `splunk_windows`: Splunk Query, Windows Mappings 
   - `splunk_windows_sysmon_acc`: Splunk Query, Sysmon Mappings 
   - `splunk_cim_dm`: Splunk Datamodel Field Mappings 
5. Destination
   - (Default) *./rules.conf*
   - Folder path

## Development
Utilizes [SigmAIQ](https://github.com/AttackIQ/SigmAIQ) - a wrapper for [pySigma](https://github.com/SigmaHQ/pySigma)
CLI development docs [Typer](https://typer.tiangolo.com/tutorial/options/callback-and-context/#validate-cli-parameters)

Development done in python 3.12.4
### Install Packages
Ensure you have Python installed, and install the required dependencies using `pip`
Some packages might be preinstalled

`pip install typer PyYAML sigma sigmaiq`
