from sigma.pipelines.common import generate_windows_logsource_items
from sigma.processing.transformations import (
    FieldMappingTransformation,
    AddFieldnamePrefixTransformation,
)
from sigma.processing.conditions import (
    LogsourceCondition,
    IncludeFieldCondition,
    FieldNameProcessingItemAppliedCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline


def lr_windows() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="LogRhythm Windows log mappings",
        priority=20,
        allowed_backends=("logrhythm"),
        items=generate_windows_logsource_items("winlog.channel", "{source}")
        + [
            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "Computer": "impactedName",
                        "EventID": "vendorMessageId",
                        "EventType": "action",
                        "TargetObject": "object",
                        "CommandLine": "command",
                        "FileName": "objectName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "RuleName": "policy",
                        "Keywords": "result",
                        "Task": "vendorInfo",
                        "CurrentDirectory": "login",
                        "Loginid": "session",
                        "ParentProcessId": "parentProcessId",
                        "ParentImage":"parentProcessName",
                        "Protocol": "protolName",
                        "TargetFilename": "object",
                        "SourceIp": "originIp",
                        "SourceHostname": "originHostname",
                        "SourcePort": "originPort",
                        "DestinationIp": "impactedIp",
                        "DestinationHostname": "impactedHostname",
                        "DestinationPort": "impactedPort",
                        "ImageLoaded": "object",
                        # "Signed": "file.code_signature.signed",
                        # "SignatureStatus": "file.code_signature.status",
                        "SourceProcessId": "processId",
                        "SourceImage": "parentProcessName",
                        "State": "action",
                        "Level": "severity",
                        "Device": "object",
                        # "SourceThreadId": "process.thread.id",
                        # "PipeName": "file.name",
                        # "Destination": "process.executable",
                        "QueryName": "subject",
                        "QueryStatus": "status",
                        "User": "",
                        "WorkstationName": "domainOrigin",
                        "imphash": "hash",
                        "md5": "hash",
                        "sha1": "object",
                        "sha256": "hash",
                        "Hashes": "hash"
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows")],
            )
        ],
    )