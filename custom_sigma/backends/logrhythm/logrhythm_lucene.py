import re
from typing import Iterable, ClassVar, Dict, List, Optional, Pattern, Tuple, Union, Any

from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import SigmaCompareExpression, SigmaNull, SigmaFieldReference
from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
import sigma


class LogRhythmBackend(TextQueryBackend):
    """
    Logrhythm query string backend. Generates query strings described here in the
    logrhythm documentation:

    <insert to logrhythm documenation>
    """

    # A descriptive name of the backend
    name: ClassVar[str] = "LogRhythm Lucene"
    # Output formats provided by the backend as name -> description mapping.
    # The name should match to finalize_output_<name>.
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain LogRhythm Lucene queries",
    }
    # Does the backend requires that a processing pipeline is provided?
    requires_pipeline: ClassVar[bool] = True

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionOR,
        ConditionAND,
    )
    # Expression for precedence override grouping as format string with {expr} placeholder
    group_expression: ClassVar[str] = "({expr})"
    parenthesize: bool = True

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    # Token inserted between field and value (without separator)
    eq_token: ClassVar[str] = ":"

    # String output
    # Fields
    # No quoting of field names
    # Escaping
    # Character to escape particular parts defined in field_escape_pattern.
    field_escape: ClassVar[str] = "\\"
    # All matches of this pattern are prepended with the string contained in field_escape.
    field_escape_pattern: ClassVar[Pattern] = re.compile("[\\s*]")

    # Values
    # string quoting character (added as escaping character)
    str_quote: ClassVar[str] = '"'
    str_quote_pattern: ClassVar[Pattern] = re.compile(r"^.*\s.*$")
    str_quote_pattern_negation: ClassVar[bool] = False
    # Escaping character for special characrers inside string
    escape_char: ClassVar[str] = "\\"
    # Character used as multi-character wildcard
    wildcard_multi: ClassVar[str] = "*"
    # Character used as single-character wildcard
    wildcard_single: ClassVar[str] = "?"
    # Characters quoted in addition to wildcards and string quote
    add_escaped: ClassVar[str] = '+-&&||!(){}[]^"~*?:\\'
    bool_values: ClassVar[Dict[bool, str]] = (
        {  # Values to which boolean values are mapped.
            True: "true",
            False: "false",
        }
    )

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    re_expression: ClassVar[str] = "{field}:/{regex}/"
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ("/",)
    # Don't escape the escape char
    re_escape_escape_char: ClassVar[bool] = False

    # cidr expressions
    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_expression: ClassVar[str] = "{field}:{network}\\/{prefixlen}"

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[str] = "{field}:{operator}{value}"
    # Mapping between CompareOperators elements and strings used as replacement
    # for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    # Expression for field has null value as format string with {field} placeholder for field name
    field_null_expression: ClassVar[str] = "NOT _exists_:{field}"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    # Convert OR as in-expression
    convert_or_as_in: ClassVar[bool] = True
    # Convert AND as in-expression
    convert_and_as_in: ClassVar[bool] = False
    # Values in list can contain wildcards. If set to False (default)
    # only plain values are converted into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = True
    # Expression for field in list of values as format string with
    # placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[str] = "{field}{op}({list})"
    # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    or_in_operator: ClassVar[str] = ":"
    # List element separator
    list_separator: ClassVar[str] = " OR "

    # Value not bound to a field
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[str] = "*{value}*"
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = "{value}"

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        index_names: List = (
                "apm-*-transaction*",
                "auditbeat-*",
                "endgame-*",
                "filebeat-*",
                "logs-*",
                "packetbeat-*",
                "traces-apm*",
                "winlogbeat-*",
                "-*elastic-cloud-logs-*",
        ),
        schedule_interval: int = 5,
        schedule_interval_unit: str = "m",
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors)
        self.index_names = index_names or [
            "apm-*-transaction*",
            "auditbeat-*",
            "endgame-*",
            "filebeat-*",
            "logs-*",
            "packetbeat-*",
            "traces-apm*",
            "winlogbeat-*",
            "-*elastic-cloud-logs-*",
        ]
        self.schedule_interval = schedule_interval or 5
        self.schedule_interval_unit = schedule_interval_unit or "m"
        self.severity_risk_mapping = {
            "INFORMATIONAL": 1,
            "LOW": 21,
            "MEDIUM": 47,
            "HIGH": 73,
            "CRITICAL": 99,
        }

    @staticmethod
    def _is_field_null_condition(cond: ConditionItem) -> bool:
        return isinstance(cond, ConditionFieldEqualsValueExpression) and isinstance(
            cond.value, SigmaNull
        )

    def convert_condition_field_eq_field(
        self, cond: SigmaFieldReference, state: ConversionState
    ) -> Any:
        raise SigmaFeatureNotSupportedByBackendError(
            "LogRhythm backend can't handle field references."
        )

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """When checking if a field is not null, convert "NOT NOT _exists_:field" to "_exists_:field"."""
        if LogRhythmBackend._is_field_null_condition(cond.args[0]):
            return f"_exists_:{cond.args[0].field}"

        return super().convert_condition_not(cond, state)

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        if ":" in cond.value.cidr:
            return (
                super()
                .convert_condition_field_eq_val_cidr(cond, state)
                .replace(":", r"\:")
                .replace(r"\:", ":", 1)
            )
        else:
            return super().convert_condition_field_eq_val_cidr(cond, state)

    def convert_condition_field_eq_expansion(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """
        Convert each value of the expansion with the field from the containing condition and OR-link
        all converted subconditions.
        """
        or_cond = ConditionOR(
            [
                ConditionFieldEqualsValueExpression(cond.field, value)
                for value in cond.value.values
            ],
            cond.source,
        )
        if self.decide_convert_condition_as_in_expression(or_cond, state):
            return self.convert_condition_as_in_expression(or_cond, state)
        else:
            return self.convert_condition_or(cond, state)

    def compare_precedence(self, outer: ConditionItem, inner: ConditionItem) -> bool:
        """Override precedence check for null field conditions."""
        if isinstance(inner, ConditionNOT) and LogRhythmBackend._is_field_null_condition(
            inner.args[0]
        ):
            # inner will turn into "_exists_:field", no parentheses needed
            return True

        if LogRhythmBackend._is_field_null_condition(inner):
            # inner will turn into "NOT _exists_:field", force parentheses
            return False

        return super().compare_precedence(outer, inner)

    def finalize_output_threat_model(self, tags: List[SigmaRuleTag]) -> Iterable[Dict]:
        attack_tags = [t for t in tags if t.namespace == "attack"]
        if not len(attack_tags) >= 2:
            return []

        techniques = [
            tag.name.upper() for tag in attack_tags if re.match(r"[tT]\d{4}", tag.name)
        ]
        tactics = [
            tag.name.lower()
            for tag in attack_tags
            if not re.match(r"[tT]\d{4}", tag.name)
        ]

        for tactic, technique in zip(tactics, techniques):
            if (
                not tactic or not technique
            ):  # Only add threat if tactic and technique is known
                continue

            try:
                if "." in technique:  # Contains reference to Mitre Att&ck subtechnique
                    sub_technique = technique
                    technique = technique[0:5]
                    sub_technique_name = mitre_attack_techniques[sub_technique]

                    sub_techniques = [
                        {
                            "id": sub_technique,
                            "reference": f"https://attack.mitre.org/techniques/{sub_technique.replace('.', '/')}",
                            "name": sub_technique_name,
                        }
                    ]
                else:
                    sub_techniques = []

                tactic_id = [
                    id
                    for (id, name) in mitre_attack_tactics.items()
                    if name == tactic.replace("_", "-")
                ][0]
                technique_name = mitre_attack_techniques[technique]
            except (IndexError, KeyError):
                # Occurs when Sigma Mitre Att&ck list is out of date
                continue

            yield {
                "tactic": {
                    "id": tactic_id,
                    "reference": f"https://attack.mitre.org/tactics/{tactic_id}",
                    "name": tactic.title().replace("_", " "),
                },
                "framework": "MITRE ATT&CK",
                "technique": [
                    {
                        "id": technique,
                        "reference": f"https://attack.mitre.org/techniques/{technique}",
                        "name": technique_name,
                        "subtechnique": sub_techniques,
                    }
                ],
            }

        for tag in attack_tags:
            tags.remove(tag)
