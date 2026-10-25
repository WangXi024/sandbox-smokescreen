"""最小技能脚本：沙箱里读取 CSV，生成汇总。"""
import csv
import json
from pathlib import Path

with Path('/workspace/inputs/input.csv').open(encoding='utf-8') as stream:
    rows = list(csv.DictReader(stream))
summary = {'items': len(rows), 'quantity': sum(int(row['quantity']) for row in rows),
           'amount': sum(int(row['quantity']) * float(row['price']) for row in rows)}
Path('/workspace/out/summary.json').write_text(json.dumps(summary, ensure_ascii=False))
print('销售汇总已生成')
