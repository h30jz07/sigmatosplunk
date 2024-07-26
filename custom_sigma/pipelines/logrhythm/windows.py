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


def lr_windows_v2() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="LogRhythm Windows log mappings",
        priority=20,
        allowed_backends=frozenset("logrhythm"),
        items=
        #     ProcessingItem(
        #         identifier="Alert for unsupported fields",
        #         field_name_conditions=[IncludeFieldCondition(fields=["Details"])],
        #         transformation=DropDetectionItemTransformation(),
        #         rule_conditions=[LogsourceCondition(product="windows")]
        #     )
        # ]

        [
            # EVID 1 : Process Created (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "CommandLine": "command",
                        "CurrentDirectory": ['login', 'domain'],
                        "Logonid": "session",
                        "Hashes": "hash",
                        "ParentProcessId": "parentProcessId",
                        "ParentImage": "parentProcessPath",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="process_creation")],
            )
        ] + [
            # EVID 2 : File Creation Time Changed (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "TargetFileName": "object",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="file_change")],
            )
        ] + [
            # EVID 3 : Network Connection Detected (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "ProcessId": "processId",
                        "Image": "process",
                        "User": ['login', 'domain'],
                        "Protocol": ['application', 'protocolName', 'serviceName'],
                        "SourceIp": "originIp",
                        "SourceHostName": "originHostName",
                        "SourcePort": "originPort",
                        "DestinationIp": "impactedIp",
                        "DestinationHostName": "impactedName",
                        "DestinationPort": "impactedPort",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="network_connection")],
            )
        ] + [
            # EVID 4 : Service State Change (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "State": "action",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="sysmon_status")],
            )
        ] + [
            # EVID 5 : Process Terminated (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "CommandLine": "command",
                        "User": ['login', 'domain'],
                        "Logonid": "session",
                        "Hashes": "hash",
                        "ParentProcessId": "parentProcessId",
                        "ParentImage": ['parentProcessPath', 'parentProcessName'],
                        "ParentCommandLine": "object",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="process_termination")],
            )
        ] + [
            # EVID 6 : Driver Loaded (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "ImageLoaded": "object",
                        "Hashes": "hash",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="driver_load")],
            )
        ] + [
            # EVID 7 : Image Loaded (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessID": "processId",
                        "Image": "process",
                        "ImageLoaded": "object",
                        "Hashes": "hash",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="image_load")],
            )
        ] + [
            # EVID 8 : Create Remote Thread (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "SourceProcessId": "parentProcessId",
                        "SourceImage": "parentProcessName",
                        "TargetProcessId": "processId",
                        "TargetImage": "process",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="create_remote_thread")],
            )
        ] + [
            # EVID 9 : Raw Access Read (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "Device": "object",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="raw_access_thread")],
            )
        ] + [
            # EVID 10 : Process Access (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "SourceProcessId": "parentProcessId",
                        "SourceImage": "parentProcessName",
                        "TargetProcessId": "processId",
                        "TargetImage": "process",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="process_access")],
            )
        ] + [
            # EVID 11 : File Created (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "Security UserId": ['domain', 'login'],
                        "ProcessId": "processId",
                        "Image": "process",
                        "TargetFilename": "object",
                        "Hashes": "hash",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="file_event")],
            )
        ] + [
            # EVID 12 : Registry Event (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "EventType": "action",
                        "ProcessId": "processId",
                        "Image": "process",
                        "TargetObject": "object",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows",
                                                    category="['registry_delete', 'registry_add', 'registry_event']")],
            )
        ] + [
            # EVID 13 : Registry Value Set (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "EventType": "action",
                        "ProcessId": "processId",
                        "Image": "process",
                        "TargetObject": "object",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", category="['registry_event', 'registry_set']")],
            )
        ] + [
            # EVID 15 : File Create Stream Hash (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "TargetFilename": "object",
                        "Hash": "hash",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="create_stream_hash")],
            )
        ] + [
            # EVID 16 : Sysmon Configuration Change (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "Configuration": ['command', 'object'],
                        "ConfigurationFileHash": "hash",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="sysmon_status")],
            )
        ] + [
            # EVID 17 : Named Pipe Created (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="pipe_created")],
            )
        ] + [
            # EVID 18 : Named Pipe Connected (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Keywords": "result",
                        "Computer": "impactedName",
                        "ProcessId": "processId",
                        "Image": "process",
                        "RuleName": "policy",
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="pipe_created")],
            )
        ] + [
            # EVID 22 : DNS Query (Sysmon)

            ProcessingItem(  # Field mappings
                identifier="lr_windows_field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "vendorMessageId",
                        "Level": "severity",
                        "Task": "vendorInfo",
                        "Computer": "originHostName",
                        "RuleName": "policy",
                        "ProcessID": "processId",
                        "QueryName": "subject",
                        "QueryStatus": "status",
                        "QueryResults": "result",
                        "Image": "process",
                        "User": ['login', 'domain'],
                    }
                ),
                rule_conditions=[LogsourceCondition(product="windows", category="dns_query")],
            )
        ]
    )
