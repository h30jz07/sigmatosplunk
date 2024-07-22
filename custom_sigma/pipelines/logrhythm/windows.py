from sigma.processing.transformations import (
    FieldMappingTransformation,
    DropDetectionItemTransformation, DetectionItemFailureTransformation, RuleFailureTransformation
)
from sigma.processing.conditions import (
    LogsourceCondition,
    IncludeFieldCondition,
    ExcludeFieldCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

event_id_1 = [
    {
        "version": 1,
        "mapping": {
            "EventID": "vendorMessageId",
            "Version": "version",
            "Level": "severity",
            "Execution": "parentProcessId",
            "Computer": "domainName",
            "Security": ["domain", "origin"],
            "ProcessId": "processId",
            "Image": "process",
            "CommandLine": "command",
            "User": ["domain", "login"],
            "Loginid": "sessionType",
            "TerminalSessionId": "session",
            "Hashes": "hash",
            "ParentProcessId": "parentProcessId",
            "ParentImage": "parentProcessName",
            "ParentCommandLine": "parentProcessPath"
        }
    },
    {
        "version": 2,
    }
]


def lr_windows() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="LogRhythm Windows log mappings",
        priority=20,
        allowed_backends=frozenset("logrhythm"),
        items=[
                  ProcessingItem(
                      identifier="Alert for unsupported fields",
                      field_name_conditions=[IncludeFieldCondition(fields=["Details"])],
                      transformation=DropDetectionItemTransformation(),
                      rule_conditions=[LogsourceCondition(product="windows")]
                  )
              ]
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
                              "CurrentDirectory": ["login", "domainOrigin"],
                              "Loginid": "session",
                              "ParentProcessId": "parentProcessId",
                              "ParentImage": "parentProcessName",
                              "Protocol": "protolName",
                              "TargetFilename": "object",
                              "SourceIp": "originIp",
                              "SourceHostname": "originHostname",
                              "SourcePort": "originPort",
                              "DestinationIp": "impactedIp",
                              "DestinationHostname": "impactedHostname",
                              "DestinationPort": "impactedPort",
                              "ImageLoaded": "object",
                              "SourceProcessId": "processId",
                              "SourceImage": "parentProcessName",
                              "State": "action",
                              "Level": "severity",
                              "Device": "object",
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
