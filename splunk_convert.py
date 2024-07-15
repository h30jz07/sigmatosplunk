import codecs
from os import listdir, path, getcwd
from yaml import safe_load

import typer
from typing_extensions import Annotated, Optional

from sigmaiq import SigmAIQBackend, SigmAIQPipelineResolver, SigmAIQPipeline
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from custom_sigma.backends.elasticsearch import elasticsearch_lucene
from custom_sigma.pipelines.elasticsearch import windows

OUTPUT_FORMATS = ["default",
                  "savedsearches",
                  "data_model",
                  "stanza"]

app = typer.Typer()


def get_files(directory):
    return [f for f in listdir(directory) if f.endswith(".yml")]


def parse_files(rule_source, directory):
    # parse all yml files in current directory into dicts, then into a sigma collection
    if directory:
        files = get_files(rule_source)
        if len(files) == 0:
            raise FileNotFoundError(f"No .yml files found in the specified folder: {rule_source}")
        paths = [path.join(rule_source, f) for f in files]
    else:
        paths = [rule_source]
    return paths


def convert_rules(paths, backend):
    rules = []
    for file in paths:
        try:
            yml = open(file).read()

            rule = SigmaCollection.from_yaml(yml)
            # if "opensearch" in backend.name.lower() or "elasticsearch" in backend.name.lower():
            #     get_logrhythm_custom_pipeline().apply(rule)

            rule = backend.convert(rule)[0]
            rules.append(rule)
            # rules.append(codecs.escape_decode(bytes(rule, "utf-8"))[0].decode("utf-8"))

        except FileNotFoundError:
            print(f"Failed at opening file: {file}")
            continue
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
            case "n":
                new_output_file = input("enter new output file name:")
                output_file_callback(new_output_file)
            case _:
                return value
    else:
        return value

@app.command()
def convert(rule_source: Annotated[Optional[str], typer.Option("--folder", "-f",
                                                               help="Source directory where SIGMA rules to be "
                                                                    "converted are stored. Defaults to current "
                                                                    "directory\\rules folder")] = path.join(
    path.dirname(path.realpath(__file__)), "rules"),
        output_format: Annotated[Optional[str], typer.Option("--outputformat", "-o",
                                                             help="",
                                                             callback=output_format_callback)] = "default",
        backend_name: Annotated[Optional[str], typer.Option("--backend", "-b",
                                                            help="Select the SIEM you would to convert to",
                                                            show_default="splunk")] = "splunk",
        pipeline_name: Annotated[Optional[str], typer.Option("--pipeline", "-p",
                                                             help=f"Specify your pipeline")] = "",
        output_file: Annotated[Optional[str], typer.Option("--destination", "-d",
                                                           help="Default output to rules.conf, in current directory",
                                                           callback=output_file_callback)] = "rules.conf"):
    print(f"\nConvert SIGMA rules to {backend_name.capitalize()} queries.")

    pipeline = ""
    # resolving pipeline
    if pipeline_name:
        pipeline = SigmAIQPipelineResolver(processing_pipelines=pipeline_name.split()).process_pipelines()
    if backend_name.lower() in ["opensearch", "elasticsearch"]:
        # custom pipeline for lucene
        pipeline = windows.lr_windows()
        # pipeline = SigmAIQPipeline(processing_pipeline="zeek_raw").create_pipeline()

    # generate backend
    backend = SigmAIQBackend(backend=backend_name.lower()).create_backend()
    if pipeline:
        backend = SigmAIQBackend(backend=backend_name.lower(),
                                 processing_pipeline=pipeline,
                                 output_format=output_format).create_backend()
    if backend_name.lower() in ["opensearch", "elasticsearch"]:
        # custom backend for lucene
        backend = elasticsearch_lucene.LuceneBackend(pipeline)

    # digest rules from rule source location
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
