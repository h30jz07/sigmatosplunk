# SIGMA Rule Convertor 
This Python script converts SIGMA rules to queries for various SIEMs. It supports converting multiple SIGMA rule files (in YAML format) into corresponding queries based on specified backend and optional custom pipelines.

## Usage
Basic usage

`python splunk_convert.py `
- Uses default values for all options
- Input SIGMA rules taken from *./rules*

Specify SIGMA rules source folder

`python splunk_convert.py -f <folder path>`

`python splunk_convert.py --folder C://Downloads/Sigma_Rules`
- Input folder for SIGMA rules from relative or absolute path

Specify output format

`python splunk_convert.py -o savedsearches`

`python splunk_convert.py --outputformat data_model`
- Change output format of the converted rules. Default for easy mass conversion. savedsearches for useful metadata

Specify backend

`python splunk_convert.py -b splunk`

`python splunk_convert.py --backend opensearch`
- The output rule language to convert a sigma rule into

Specify pipeline

`python splunk_convert.py -p splunk_windows`

`python splunk_convert.py --pipeline splunk_cim_dm`
- Pipeline for different mappings

Specify destination

`python splunk_convert.py -d <folder path>`

`python splunk_convert.py --destination C://Downloads/Sigma_Rules`
- Output folder for SIGMA rules to relative or absolute path



### Options
1. File source
   - (Default) Current folder
   - Folder path
   - File path
2. Output Formats
   - (Default) Plain SPL queries
   - `savedsearches`: Plain SPL in a savedsearches.conf file
   - `data_model`: Data model queries with tstats
   - `stanza`: Enterprise Security savedsearches.conf stanza
3. Backends
   - `opensearch` | `elasticsearch`: For LogRhythm and Lucene queries
   - `splunk`: Splunk SIEM

   The following may not produce working queries. Use with care
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
