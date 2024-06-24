# Conversion tool from SIGMA Rules to Splunk queries
Utilizes [SigmAIQ](https://github.com/AttackIQ/SigmAIQ) - a wrapper for [pySigma](https://github.com/SigmaHQ/pySigma)
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
3. Pipelines
   - `splunk_windows`: Splunk Query, Windows Mappings 
   - `splunk_windows_sysmon_acc`: Splunk Query, Sysmon Mappings 
   - `splunk_cim_dm`: Splunk Datamodel Field Mappings 

## Development
Development done in python 3.12.4
### Install Packages
Some packages might be preinstalled

`pip install PyYAML`

`pip install pysigma`

`pip install sigma`

`pip install sigmaiq`
