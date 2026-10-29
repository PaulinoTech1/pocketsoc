"""JSON event logs on stderr, with optional bounded private file rotation."""
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import stat
from .events import now


class JsonFormatter(logging.Formatter):
    def format(self, record):
        body = dict(schema_version=1, timestamp=now(), level=record.levelname,
                    event=getattr(record, 'event', 'message'), message=record.getMessage(),
                    data=getattr(record, 'data', {}))
        return json.dumps(body, ensure_ascii=True, allow_nan=False)


class PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        parent = Path(self.baseFilename).parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise ValueError('log parent must be owned and not group/world writable')
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND |
                     os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise ValueError('log must be an owned regular file with one link')
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)
        except BaseException:
            os.close(fd)
            raise


def configure(config, stream=None):
    logger = logging.getLogger('atlas')
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(config.level)
    logger.propagate = False
    console = logging.StreamHandler(stream)
    console.setFormatter(JsonFormatter())
    logger.addHandler(console)
    if config.file is not None:
        path = config.file
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        handler = PrivateRotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=2, encoding='utf-8')
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    return logger


def event(logger, name, message, level=logging.INFO, **data):
    logger.log(level, message, extra={'event': name, 'data': data})
