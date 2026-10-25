"""Linux 模块测试入口；测试结果与真实沙箱验收分别记录。"""
import json
from pathlib import Path
import sys
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'src'))

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(PROJECT / 'tests'), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    report = {'kind': 'module-tests', 'tests_run': result.testsRun,
              'failures': len(result.failures), 'errors': len(result.errors),
              'skipped': len(result.skipped), 'passed': result.wasSuccessful(),
              'note': '模块测试与真实沙箱验收分开记录；真实验收另见 report.json。'}
    directory = Path('/run/sandbox_model')
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'unit-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    raise SystemExit(0 if report['passed'] else 1)
