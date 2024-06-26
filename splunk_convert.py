from os import listdir, path, getcwd
from yaml import safe_load

import typer
from typing_extensions import Annotated, Optional

from sigmaiq import SigmAIQBackend, SigmAIQPipelineResolver
from sigma.collection import SigmaCollection, SigmaRule
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

OUTPUT_FORMATS = ["default",
                  "savedsearches",
                  "data_model",
                  "stanza"]

PROC_PIPELINES = ["splunk_windows", 
                  "splunk_windows_sysmon_acc",
                  "splunk_cim_dm",
                  "default"]

app = typer.Typer()

def get_files(directory):
    return [f for f in listdir(directory) if f.endswith(".yml")]

def parse_files(rule_source, directory):
    #parse  all yml files in current directory into dicts, then into a sigma collection
    if directory: 
        files = get_files(rule_source)
        if len(files) == 0:
            raise FileNotFoundError(f"No .yml files found in the specified folder: {rule_source}")
        paths = [path.join(rule_source, f) for f in files]
    else: paths = [rule_source]
    return paths

def convert_rules(paths, backend):
    rules = []
    for file in paths:
        try:
            yml = safe_load(open(file))
        except Exception as e:
            #print(e)
            print(f"Failed at opening file: {file}")
            continue

        try:
            rule = SigmaRule.from_dict(yml)
        except:
            print(f"Failed at processing yml file: {file}")
            continue

        try:
            rules.append(backend.translate(rule)[0])
        except SigmaFeatureNotSupportedByBackendError:
            print(f"Failed at converting SIGMA to query (likely a regex incompatibility in splunk): {file}")
            continue

    return rules

def rule_source_callback(value: str):
    if path.isdir(value):
        return value
    elif path.isdir(path.join(path.dirname(path.abspath(__file__)), value)):
        return path.join(path.dirname(path.abspath(__file__)), value)
    else:
        raise typer.BadParameter(f"Path to rule source not found at {value}")

def output_format_callback(value: str):
    if value not in OUTPUT_FORMATS:
        raise typer.BadParameter(f"Output format must be one of {OUTPUT_FORMATS}")
    return value

def output_file_callback(value: str):
    if path.isfile(value) or path.isfile(path.join(path.dirname(path.abspath(__file__)), value)):
        override = input(f"{value} already exists, override? (Y/n): ").lower()
        match override:
            case "y":
                return value
            case _:
                raise typer.BadParameter(f"Provide a valid output file or location.")
    else:
        return value

@app.command()
def convert(rule_source: Annotated[Optional[str], typer.Option("--folder", "-f", 
                                                                help="Source directory where SIGMA rules to be converted are stored. Defaults to current directory\\rules folder")] = path.join(path.dirname(path.realpath(__file__)), "rules"),
            output_format: Annotated[Optional[str], typer.Option("--outputformat", "-o", 
                                                                help="", 
                                                                show_default="Plain SPL queries", 
                                                                callback=output_format_callback)] = "default", 
            pipeline: Annotated[Optional[str], typer.Option("--pipeline", "-p", 
                                                                help=f"One of {PROC_PIPELINES}. Defaults to {PROC_PIPELINES[0]} and {PROC_PIPELINES[1]} combined\nNote: 'splunk_cim_dm' may contain faulty fields")] = "default",
            output_file: Annotated[Optional[str], typer.Option("--destination", "-d", 
                                                                help="Default output to rules.conf, in current directory",
                                                                callback=output_file_callback)] = "rules.conf"):
    
    print("\nConvert SIGMA rules to Splunk queries.")
    

    #resolving pipeline
    pipelines = ['splunk_windows','splunk_windows_sysmon_acc']
    if pipeline == "default" or pipeline not in PROC_PIPELINES:
        if pipeline not in PROC_PIPELINES:
            print("Provided pipeline not found, using default.")
        pipeline = SigmAIQPipelineResolver(processing_pipelines=pipelines).process_pipelines(name="Splunk pipelines")
    # generate backend
    backend = SigmAIQBackend(backend="splunk",
                             processing_pipeline=pipeline,
                             output_format=output_format).create_backend()

    #digest rules from rule source location
    try:
        paths = parse_files(rule_source, path.isdir(rule_source))
    except FileNotFoundError:
        print(f"No .yml files found in specified in directory: {rule_source}")
        exit()
    
    output = convert_rules(paths, backend)
    
    with open(output_file, "w") as file:
        for item in output:
            file.write(item + "\n")
    print(f"Output at: {path.join(getcwd(), output_file)}")
    

if __name__ == "__main__":
    app()