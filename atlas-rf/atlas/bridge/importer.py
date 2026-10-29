"""Explicit file boundary; an Android companion is not bundled."""
from pathlib import Path
from atlas.core.errors import AtlasError


def import_export(path, store):
    path = Path(path)
    if path.suffix != '.jsonl' or not path.is_file():
        raise AtlasError('bridge export must be an existing regular .jsonl file')
    return store.ingest(path)


def status(inbox):
    inbox = Path(inbox)
    return dict(status='UNVERIFIED', transport='finalized-file-export', companion_implemented=False,
                companion_source_available=True, companion_build_verified=False,
                inbox=str(inbox), inbox_visible=inbox.is_dir(),
                note='Kotlin source exists; APK/build and Android-to-VM transfer remain unverified. No radio access from Debian.')
