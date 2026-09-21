"""Run the offline regression suite and record the actual host platform."""
import argparse
import json
import platform
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',default=str(ROOT/'test-results'/'self-check.json'))
    args=parser.parse_args()
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'platform':platform.platform(),'python':sys.version,'sqlite':sqlite3.sqlite_version,
            'tests_run':result.testsRun,'passed':result.wasSuccessful(),'skipped':result.skipped,
            'failures':[(str(test),detail) for test,detail in result.failures],
            'errors':[(str(test),detail) for test,detail in result.errors],
            'scope':'Offline application tests. Live sources, browser interactions and engine replay are separate checks.'}
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Report:',output)
    return not result.wasSuccessful()


if __name__=='__main__':sys.exit(main())
