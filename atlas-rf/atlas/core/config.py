"""Small, strict YAML configuration; no arbitrary object loading or aliases."""
from dataclasses import dataclass, field
import math
import os
from pathlib import Path
from .errors import ConfigurationError


def data_path():
    return Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'atlas-rf/atlas.sqlite3'


@dataclass(frozen=True)
class StorageConfig:
    path: Path = field(default_factory=data_path)
    report_limit: int = 2000
    retention_days: int = 7

@dataclass(frozen=True)
class MonitorConfig:
    interval_seconds: float = 2.0
    max_rss_mb: int = 256
    min_available_mb: int = 128
    min_free_disk_mb: int = 64

@dataclass(frozen=True)
class LoggingConfig:
    level: str = 'INFO'
    file: Path | None = None

@dataclass(frozen=True)
class BridgeConfig:
    inbox: Path = Path('/mnt/shared/Documents/ATLAS-RF')

@dataclass(frozen=True)
class Config:
    storage: StorageConfig = field(default_factory=StorageConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    bridge: BridgeConfig = field(default_factory=BridgeConfig)


def mapping(value, allowed, name):
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise ConfigurationError(f'{name} must be a mapping with string keys')
    unknown = set(value) - set(allowed)
    if unknown:
        raise ConfigurationError(f'{name}: unknown settings: {", ".join(sorted(unknown))}')
    return value


def integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ConfigurationError(f'{name} must be an integer from {low} to {high}')
    return value


def path_value(value, base, name):
    if not isinstance(value, str) or not value.strip() or '\0' in value:
        raise ConfigurationError(f'{name} must be a nonempty path string')
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def validate_paths(config):
    if config.logging.file is not None and config.logging.file.resolve() == config.storage.path.resolve():
        raise ConfigurationError('logging.file must differ from storage.path')
    return config


def load_config(path=None):
    defaults = Config()
    if path is None:
        return defaults
    path = Path(path).expanduser().absolute()
    from atlas.bridge.bundle import BridgeError, read_limited
    try:
        raw = read_limited(path, 65536)
        import yaml
        # Bound parser work and reject references, tags, duplicate keys and deep documents.
        depth = 0
        for count, token in enumerate(yaml.scan(raw), 1):
            if count > 2048:
                raise ConfigurationError('too many YAML tokens')
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)):
                raise ConfigurationError('YAML aliases, anchors and explicit tags are unsupported')
            if isinstance(token, (yaml.tokens.BlockMappingStartToken, yaml.tokens.BlockSequenceStartToken,
                                  yaml.tokens.FlowMappingStartToken, yaml.tokens.FlowSequenceStartToken)):
                depth += 1
            if isinstance(token, (yaml.tokens.BlockEndToken, yaml.tokens.FlowMappingEndToken, yaml.tokens.FlowSequenceEndToken)):
                depth -= 1
            if depth > 8:
                raise ConfigurationError('configuration nesting exceeds eight levels')
        class StrictLoader(yaml.SafeLoader):
            pass
        def construct_mapping(loader, node):
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node)
                if not isinstance(key, str) or key in result:
                    raise ConfigurationError('YAML keys must be unique strings')
                result[key] = loader.construct_object(value_node)
            return result
        StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
        document = yaml.load(raw, Loader=StrictLoader)
    except ConfigurationError:
        raise
    except ImportError as exc:
        raise ConfigurationError('PyYAML is required for configuration; install the declared dependency') from exc
    except (OSError, BridgeError) as exc:
        raise ConfigurationError('cannot read configuration: requires a regular non-symlink file of at most 64 KiB') from exc
    except (ValueError, RecursionError) as exc:
        raise ConfigurationError('invalid YAML configuration') from exc
    except yaml.YAMLError as exc:
        # Do not echo YAML snippets that might contain sensitive operator values.
        raise ConfigurationError('invalid YAML configuration') from exc
    root = mapping({} if document is None else document, ('storage', 'monitor', 'logging', 'bridge'), 'configuration')
    s = mapping(root.get('storage', {}), ('path', 'report_limit', 'retention_days'), 'storage')
    m = mapping(root.get('monitor', {}), ('interval_seconds', 'max_rss_mb', 'min_available_mb', 'min_free_disk_mb'), 'monitor')
    l = mapping(root.get('logging', {}), ('level', 'file'), 'logging')
    b = mapping(root.get('bridge', {}), ('inbox',), 'bridge')
    interval = m.get('interval_seconds', defaults.monitor.interval_seconds)
    if type(interval) not in (int, float) or not 0.5 <= interval <= 3600 or not math.isfinite(interval):
        raise ConfigurationError('monitor.interval_seconds must be finite and between 0.5 and 3600')
    level = l.get('level', defaults.logging.level)
    if level not in ('DEBUG', 'INFO', 'WARNING', 'ERROR'):
        raise ConfigurationError('logging.level must be DEBUG, INFO, WARNING or ERROR')
    return validate_paths(Config(
        storage=StorageConfig(path_value(s['path'], path.parent, 'storage.path') if 'path' in s else defaults.storage.path,
                              integer(s.get('report_limit', defaults.storage.report_limit), 1, 10000, 'storage.report_limit'),
                              integer(s.get('retention_days', 7), 1, 3650, 'storage.retention_days')),
        monitor=MonitorConfig(float(interval),
            integer(m.get('max_rss_mb', defaults.monitor.max_rss_mb), 32, 1024, 'monitor.max_rss_mb'),
            integer(m.get('min_available_mb', defaults.monitor.min_available_mb), 0, 2048, 'monitor.min_available_mb'),
            integer(m.get('min_free_disk_mb', defaults.monitor.min_free_disk_mb), 0, 4096, 'monitor.min_free_disk_mb')),
        logging=LoggingConfig(level, path_value(l['file'], path.parent, 'logging.file') if l.get('file') is not None else None),
        bridge=BridgeConfig(path_value(b['inbox'], path.parent, 'bridge.inbox') if 'inbox' in b else defaults.bridge.inbox)))
