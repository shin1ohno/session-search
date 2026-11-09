"""Named boundary inputs shared by the line and record differential gates."""
import json


def records(include_caps=True):
    cases = [('collision-third', {f'password=abcdefg{c}': i for i,c in enumerate('hij',1)}),
             ('python-strip', {'password': '\x1cxxxabcdefgh'}),
             ('surrogate-last', {'x': '\U000103ff'}),
             ('slash-value', {'url': 'https://u:passw0rd@h'}),
             ('slash-key', {'https://u:passw0rd@h': 1}),
             ('vertical-tab-value', {'x': '\x0b\x0c'})]
    if not include_caps: return cases
    for n in (46,47,86,127,128,129):
        cases.append((f'key-chars-{n}', {'K'*40+'secret'+'K'*(n-46): 'abcdefghij'}))
    for n in (500001,999999,1000000,1000001):
        cases.append((f'value-chars-{n}', {'x':'é'*n}))
    for n in (3999999,4000000,4000001):
        # Array records charge only values, so these sit exactly on the budget.
        cases.append((f'record-chars-{n}', ['é'*1000000]*3+['é'*(n-3000000)]))
    cases.append(('record-byte-budget', {'a':'é'*1000000,'b':'é'*1000000,'c':'é'*1000000}))
    return cases


def lines():
    cases = [('skip-vt', b'\x0b'), ('skip-ff', b'\x0c')]
    for name,record in records(include_caps=False):
        text=json.dumps(record,ensure_ascii=True,separators=(',',':'))
        if name.startswith('slash-'): text=text.replace('/', r'\/')
        cases.append((name,text.encode()))
    return cases
