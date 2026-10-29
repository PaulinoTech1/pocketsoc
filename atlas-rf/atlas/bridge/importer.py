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
    # Preserve the historical field (verified deployable companion), while making
    # the independent source/deployment states explicit for existing callers.
    return dict(status='UNVERIFIED', transport='authenticated-file-inbox', companion_implemented=False,
                companion_source_available=True, companion_build_verified=False,
                companion_implementation='KOTLIN_SOURCE_ONLY',
                companion_deployment='UNVERIFIED', automatic_ingestion_available=True,
                collection='ANDROID_APP_REQUIRED', sim_state='NOT_INSPECTED',
                inbox=str(inbox), inbox_visible=inbox.is_dir(),
                note='Kotlin source exists; APK/build and Android-to-VM transfer remain unverified. No radio access from Debian.')
