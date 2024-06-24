from os import listdir, path
from yaml import safe_load

from sigmaiq import SigmAIQBackend, SigmAIQPipelineResolver
from sigma.collection import SigmaCollection

def get_files(dir):
    return [f for f in listdir(dir) if f.endswith(".yml")]

def main():
    #get path of current directory
    directory = path.dirname(path.realpath(__file__))
    files = get_files(directory)

    #parse  all myl files in current directory into dicts, then into a sigma collection
    paths = [directory+"\\"+f for f in files]
    yaml_dicts = [safe_load(open(path)) for path in paths]
    rules = SigmaCollection.from_dicts(yaml_dicts)

    pipelines = ['splunk_windows','splunk_windows_sysmon_acc']

    pipeline = SigmAIQPipelineResolver(processing_pipelines=pipelines).process_pipelines(name="Splunk pipelines")
    # Necessary pipeline for output_format automatically applied
    backend = SigmAIQBackend(backend="splunk",
                             processing_pipeline=pipeline).create_backend()
    output = backend.translate(rules)

    
    file_name = input("Enter name of output file (.txt): ") + ".txt"
    with open(file_name, "w") as file:
        for item in output:
            file.write(item + "\n")

if __name__== "__main__":
    print("Convert SIGMA rules to Splunk queries.")
    main()