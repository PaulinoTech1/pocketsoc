"""Compatibility spelling for the single canonical atlas CLI implementation."""
import sys
from atlas.cli import main as canonical_main, parser
from atlas.ui.console import emit as output, write_report


def write_private(path,text):
    write_report(path,text,'markdown')


def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    index=0
    while index<len(args):
        value=args[index]
        if value in ('--db','--config'):
            index+=2
            continue
        if value.startswith('-'):
            index+=1
            continue
        if value=='import': args[index]='ingest'
        elif value=='probe': args[index:index+1]=['ip','probe']
        break
    return canonical_main(args)
