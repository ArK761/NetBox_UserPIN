#!/usr/bin/env python3
"""Builds the User PIN guides (Slovak and English) from the HTML fragments next to this file.

    python3 build.py            -> writes ../NAVOD_User_PIN_SK.pdf and ../GUIDE_User_PIN_EN.pdf (needs node + playwright)
"""
import html
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
VERSION = '2.0.1'
DATE = '2026-10-31'

DOCS = {
    'sk': dict(src='navod_sk.html', out='../NAVOD_User_PIN_SK.pdf', lang='sk',
               title='User PIN – kompletný návod', subtitle='Plugin pre NetBox 4.7+', toc='Obsah',
               meta='Verzia %s · %s' % (VERSION, DATE),
               foot='User PIN %s · návod' % VERSION),
    'en': dict(src='guide_en.html', out='../GUIDE_User_PIN_EN.pdf', lang='en',
               title='User PIN – complete guide', subtitle='A plugin for NetBox 4.7+', toc='Contents',
               meta='Version %s · %s' % (VERSION, DATE),
               foot='User PIN %s · guide' % VERSION),
}

CSS = """
@page { size: A4; margin: 18mm 16mm 20mm 16mm; }
* { box-sizing: border-box; }
body { font-family: 'DejaVu Sans', 'Liberation Sans', sans-serif; font-size: 9.4pt; line-height: 1.5; color: #1b2430; }
h1 { font-size: 17pt; color: #0b5c4d; border-bottom: 2px solid #0b5c4d; padding-bottom: 3px; margin: 22pt 0 8pt; break-after: avoid; }
h2 { font-size: 12pt; color: #12423a; margin: 14pt 0 5pt; break-after: avoid; }
p, li { orphans: 3; widows: 3; }
ul, ol { margin: 4pt 0 6pt 0; padding-left: 18pt; }
li { margin: 1.5pt 0; }
code { font-family: 'DejaVu Sans Mono', monospace; font-size: 8.4pt; background: #eef2f4; padding: 0 2px; border-radius: 2px; word-break: break-word; }
pre { font-family: 'DejaVu Sans Mono', monospace; font-size: 7.9pt; background: #14202b; color: #e6edf3; padding: 7pt 9pt; border-radius: 4px; white-space: pre-wrap; word-break: break-all; line-height: 1.4; break-inside: avoid; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 8pt; font-size: 8.6pt; }
th { background: #12423a; color: #fff; text-align: left; padding: 3pt 5pt; }
td { border: 1px solid #c9d3d8; padding: 3pt 5pt; vertical-align: top; }
tr { break-inside: avoid; }
tr:nth-child(even) td { background: #f5f8f9; }
.note, .warn { border-left: 4px solid #2a7fb8; background: #eaf3fa; padding: 5pt 8pt; margin: 6pt 0; border-radius: 3px; break-inside: avoid; }
.warn { border-left-color: #c77d0a; background: #fdf3df; }
.ok { color: #fff; background: #1f8f4e; padding: 0 5px; border-radius: 8px; font-size: 8pt; }
.no { color: #fff; background: #c0392b; padding: 0 5px; border-radius: 8px; font-size: 8pt; }
.cover { height: 235mm; display: flex; flex-direction: column; justify-content: center; break-after: page; }
.cover .k { font-size: 11pt; color: #0b5c4d; letter-spacing: 2px; text-transform: uppercase; }
.cover h1 { font-size: 34pt; border: 0; margin: 8pt 0; color: #0b5c4d; }
.cover .s { font-size: 14pt; color: #4a5a66; }
.cover .m { margin-top: 24pt; font-size: 10pt; color: #4a5a66; }
.toc { break-after: page; }
.toc h1 { margin-top: 0; }
.toc ol { list-style: none; padding-left: 0; columns: 2; column-gap: 10mm; }
.toc li { break-inside: avoid; }
.toc li { margin: 2pt 0; }
.toc li.h2 { padding-left: 16pt; font-size: 8.6pt; color: #4a5a66; }
.toc a { color: inherit; text-decoration: none; }
"""


def build(key):
    cfg = DOCS[key]
    body = (HERE / cfg['src']).read_text(encoding='utf-8')
    n1 = n2 = 0
    toc = []

    def number(match):
        nonlocal n1, n2
        level, text = match.group(1), match.group(2)
        if level == '1':
            n1 += 1
            n2 = 0
            label, anchor = f'{n1}. {text}', f'c{n1}'
        else:
            n2 += 1
            label, anchor = f'{n1}.{n2} {text}', f'c{n1}-{n2}'
        toc.append((level, label, anchor))
        return f'<h{level} id="{anchor}">{label}</h{level}>'

    body = re.sub(r'<h([12])>(.*?)</h\1>', number, body)
    items = ''.join(f'<li class="h{lv}"><a href="#{a}">{lab}</a></li>' for lv, lab, a in toc)
    page = f"""<!doctype html><html lang="{cfg['lang']}"><head><meta charset="utf-8">
<title>{html.escape(cfg['title'])}</title><style>{CSS}</style></head><body>
<div class="cover"><div class="k">NetBox plugin</div><h1>{html.escape(cfg['title'])}</h1>
<div class="s">{html.escape(cfg['subtitle'])}</div>
<div class="m">{html.escape(cfg['meta'])}<br>github.com/ArK761/NetBox_UserPIN</div></div>
<div class="toc"><h1>{cfg['toc']}</h1><ol>{items}</ol></div>
{body}
</body></html>"""
    tmp = HERE / f'_{key}.html'
    tmp.write_text(page, encoding='utf-8')
    out = (HERE / cfg['out']).resolve()
    subprocess.run(['node', str(HERE / 'render.js'), str(tmp), str(out), cfg['foot']], check=True)
    tmp.unlink()
    print('written', out)


if __name__ == '__main__':
    for key in (sys.argv[1:] or DOCS):
        build(key)
