from os import listdir, path, getcwd
from yaml import safe_load

import typer
from typing_extensions import Annotated, Optional

from sigmaiq import SigmAIQBackend, SigmAIQPipelineResolver
from sigma.collection import SigmaCollection, SigmaRule
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

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
        except:
            print(f"Failed at opening file: {file}")
            continue

        try:
            rule = SigmaRule.from_dict(yml)
        except Exception as e:
            print(e)
            print(f"Failed at processing yml file: {file}")
            continue

        try:
            rules.append(backend.translate(rule)[0])
        except SigmaFeatureNotSupportedByBackendError:
            print(f"Failed at converting SIGMA to query: {file}")
            continue

    return rules

@app.command()
def convert(rule_source: Annotated[Optional[str], typer.Option("--folder", "-f", help="")] = path.join(path.dirname(path.realpath(__file__)), "rules"), #source for SIGMA rules, defaults to current directory
            output_format: Annotated[Optional[str], typer.Option("--outputformat", "-o", help="", show_default="Plain SPL queries")] = "default", 
            pipeline: Annotated[Optional[str], typer.Option("--pipeline", "-p", help="")] = "default",
            output_file: Annotated[Optional[str], typer.Option("--destination", "-d", help="")] = "rules.conf"):
    
    print("\nConvert SIGMA rules to Splunk queries.")
    

    #resolving pipeline
    pipelines = ['splunk_windows','splunk_windows_sysmon_acc']
    if pipeline == "default" or pipeline not in pipelines:
        pipeline = SigmAIQPipelineResolver(processing_pipelines=pipelines).process_pipelines(name="Splunk pipelines")
    
    
    # generate backend
    backend = SigmAIQBackend(backend="splunk",
                             processing_pipeline=pipeline,
                             output_format=output_format).create_backend()

    #handling rule input
    try:
        paths = parse_files(rule_source, path.isdir(rule_source))
    except FileNotFoundError:
        print(f"No .yml files found in specified in directory: {rule_source}")
        exit()
    
    output = convert_rules(paths, backend)
    
    file_name = input("Enter name of output file (.conf): ") + ".conf"
    """ 
    if path.isfile(path.join(rule_source, output_file)):
        print("True")
        running = True
        while running:
            override = input(f"{file_name} already exists, override? (Y/n): ")
            match override:
                case "Y":
                    with open(file_name, "w") as file:
                        for item in output:
                            file.write(item + "\n")
                    running = False
                case "n":
                    continue
                  
            
    else: """
    with open(file_name, "w") as file:
        for item in output:
            file.write(item + "\n")
    print(f"Output at: {path.join(getcwd(), file_name)}")
    

if __name__ == "__main__":
    app()