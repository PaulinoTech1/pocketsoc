"""Expected operational failures surfaced without a traceback."""
class AtlasError(Exception):
    pass

class ConfigurationError(AtlasError):
    pass

class StorageError(AtlasError):
    pass

class ResourceLimitError(AtlasError):
    pass
