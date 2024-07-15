from .windows import lr_windows
from .zeek import ecs_zeek_beats, ecs_zeek_corelight, zeek_raw

pipelines = {
    "lr_windows": lr_windows,
    "ecs_zeek_beats": ecs_zeek_beats,
    "ecs_zeek_corelight": ecs_zeek_corelight,
    "zeek": zeek_raw,
}
