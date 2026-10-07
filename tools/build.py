"""Build deterministic archives from pinned originals. Python 3.11+, UPX 5.2.1."""
import argparse,hashlib,io,json,os,shutil,subprocess,tarfile,urllib.request,zipfile
from pathlib import Path
from localize import localize
from repair_upx import repair
ROOT=Path(__file__).resolve().parents[1]
REPO='https://github.com/reliable-ly0411/SpaceSniffer-zh-cn'
def digest(data,alg='sha256'):return hashlib.new(alg,data).hexdigest()
def verify(data,row):
 for alg,key in [('md5','official_md5'),('sha1','official_sha1'),('sha256','archive_sha256')]:
  if digest(data,alg)!=row[key]:raise ValueError(row['version']+': original '+alg+' mismatch')
def download(row):
 p=ROOT/'.cache'/row['download_url'].rsplit('/',1)[-1]
 if p.exists():data=p.read_bytes();verify(data,row);return p
 sources=[row['download_url']]+[x['recovered_from'] for x in json.loads((ROOT/'upstream/recovery-sources.json').read_text()) if x['version']==row['version']]
 errors=[]
 for url in sources:
  try:
   data=urllib.request.urlopen(url,timeout=120).read();verify(data,row);p.parent.mkdir(exist_ok=True);p.write_bytes(data);return p
  except Exception as e:errors.append(str(e))
 raise RuntimeError(row['version']+': '+str(errors))
def upx():
 windows=os.name=='nt';name='upx-5.2.1-win64.zip' if windows else 'upx-5.2.1-amd64_linux.tar.xz';tool=ROOT/'.cache'/('upx.exe' if windows else 'upx')
 pin=json.loads((ROOT/'upstream/build-tools.json').read_text())[name];archive=ROOT/'.cache'/name
 data=archive.read_bytes() if archive.exists() else urllib.request.urlopen(pin['url'],timeout=120).read()
 assert digest(data)==pin['sha256'],'UPX archive hash mismatch'
 archive.write_bytes(data)
 if windows:
  with zipfile.ZipFile(io.BytesIO(data)) as z:raw=z.read(next(n for n in z.namelist() if n.endswith('/upx.exe')))
 else:
  with tarfile.open(fileobj=io.BytesIO(data)) as z:raw=z.extractfile(next(n for n in z.getnames() if n.endswith('/upx'))).read()
 tool.write_bytes(raw);tool.chmod(0o755);return tool
COPYRIGHT=f'''SpaceSniffer 的程序、图标、文档及商标归原作者 Uderzo Software / Umberto Uderzo 所有。
官方网站：https://www.uderzo.it/main_products/space_sniffer/
这是非官方简体中文资源汉化版，并非官方中文版，也未获得官方背书。
SpaceSniffer 是闭源免费软件；免费使用不等于开源，也不等于获准修改和再分发。
原版 Disclaimer.txt 原样保留，其条款包括不得修改软件文件；本项目的汉化并不改变原版权或授予再分发权利。
本仓库用于用户指定的私有研究和兼容性验证。未经权利人许可，请勿公开分发修改后的程序。
汉化仓库：{REPO}
汉化脚本与译文不包含原程序源代码。还原时请使用同一 Release 中未经修改的官方原版 ZIP。
'''
def build(row):
 archive=download(row);original=archive.read_bytes();work=ROOT/'build'/row['version'];work.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(archive) as z:
  members={n:z.read(n) for n in z.namelist() if not n.endswith('/')}
 data=members[row['exe_member']];assert digest(data)==row['exe_sha256'],'EXE pin mismatch'
 exe=work/'SpaceSniffer.exe';exe.write_bytes(data)
 packed=b'UPX0' in data[:1024]
 if packed:subprocess.run([str(upx()),'-d',str(exe)],check=True,capture_output=True);data=exe.read_bytes()
 data,repaired=repair(data,row['version'])
 (work/'unlocalized.exe').write_bytes(data)
 output,report=localize(data,json.loads((ROOT/'translations/zh-CN.json').read_text()))
 exe.write_bytes(output);report.update(version=row['version'],architecture=row['architecture'],original_archive_sha256=digest(original),original_exe_sha256=row['exe_sha256'],upx_unpacked=packed,upx_import_repaired=repaired)
 (work/'coverage.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 members[row['exe_member']]=output
 notes_notice='原版发布声明全文见保留的 Release Notes.txt' if 'Release Notes.txt' in members else '此版本是首次公开发布；原包未附 Release Notes.txt，官方发布声明见上述官网链接'
 members['COPYRIGHT-zh-CN.txt']=COPYRIGHT.encode('utf-8-sig')
 members['LOCALIZATION-REPOSITORY.txt']=(REPO+'\r\n').encode()
 readme=f'''SpaceSniffer {row['version']} 简体中文资源汉化 zh1 ({row['architecture']})
官方发布日期：{row['official_date']}
官方发布说明：{row['release_notes_url']}
{notes_notice}；原版权条款见 Disclaimer.txt。
汉化范围：{report['scope']}
已翻译窗体属性 {report['dfm_translated']} 项，常用字符串表 {len(report['stringtable_changes'])} 项。
这不是整个应用的百分比覆盖率。动态扫描状态、部分错误和帮助、PDF 手册仍为英文。
菜单快捷键、过滤语法、导出脚本和原作者署名保留；字体使用 Microsoft YaHei。
Windows 非交互会话启动测试不代表所有窗口、DPI 和交互流程完成视觉验收。
如旧版出现中文乱码，需使用简体中文系统区域设置；旧版扫描引擎仍有其原有兼容性限制。
恢复：退出程序，重新解压同版本原版 ZIP 到新目录。
仓库：{REPO}
'''
 members['README-zh-CN.txt']=readme.encode('utf-8-sig');members['localization-coverage.json']=json.dumps(report,ensure_ascii=False,indent=2).encode()
 out=ROOT/'dist'/row['version'];out.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(archive,out/archive.name)
 target=out/f"SpaceSniffer-{row['version']}-{row['architecture']}-zh-CN-zh1.zip"
 with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for name,content in sorted(members.items()):
   info=zipfile.ZipInfo(name,(2026,10,7,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.create_system=3;info.external_attr=0o100644<<16;z.writestr(info,content,compresslevel=9)
 sums={p.name:{a:digest(p.read_bytes(),a) for a in ('md5','sha1','sha256')} for p in (out/archive.name,target)}
 for alg in ('md5','sha1','sha256'):(out/(alg.upper()+'SUMS.txt')).write_text(''.join(f"{v[alg]}  {n}\n" for n,v in sums.items()))
 (out/'checksums.json').write_text(json.dumps(sums,indent=2)+'\n')
 body=f'''SpaceSniffer **{row['version']} ({row['architecture']})** · 非官方简体中文资源汉化 zh1

官方发布日期：**{row['official_date']}**（本站 Release 创建日期是汉化发布日期）。

官方发布声明：[Release notes]({row['release_notes_url']})；{notes_notice}；该原始声明归原作者所有。原版来源及发布日期：[官网下载页](https://www.uderzo.it/main_products/space_sniffer/download_alt.html)。

| Archive | Archive MD5 | Archive SHA1 |
| --- | --- | --- |
'''
 for n,v in sums.items():body+=f"| `{n}` | `{v['md5']}` | `{v['sha1']}` |\n"
 body+='\n官方发布声明摘要（中文转述）：'+json.loads((ROOT/'upstream/release-summaries-zh.json').read_text())[row['version']]+'\n'
 body+=f'''\n汉化说明：{report['scope']}已翻译 {report['dfm_translated']} 项窗体属性和 {len(report['stringtable_changes'])} 项字符串表文本；不代表全应用 100% 汉化。未更改扫描算法或过滤/脚本语法。1.1.3.0、1.1.3.1、1.1.4.0 另外修复了 UPX 解包导致的 DLL 导入名称损坏；修复限定于导入元数据，未改动机器代码。覆盖清单及版权说明见汉化 ZIP。

验证范围：PE 资源结构、原有代码节不变、版本及哈希锁定；Windows 启动和中文菜单检查结果见仓库 tests/runtime-results.json。尚未完成所有 DPI、弹窗和交互操作的视觉验收。

版权：SpaceSniffer © Uderzo Software / Umberto Uderzo，原版闭源版权及 Disclaimer.txt 保留。此为非官方修改，免费不等于允许修改/再分发；未经权利人许可不得公开分发修改程序。仓库：{REPO}。

原版 ZIP 字节保持不变；MD5/SHA1 用于与官网对照，另附 SHA256SUMS.txt、checksums.json。汉化 ZIP 内含仓库地址、中文版权说明和回退方法。
'''
 (out/'release.md').write_text(body)
 return {'version':row['version'],'forms':report['dfm_translated'],'strings':len(report['stringtable_changes']),'assets':[p.name for p in out.iterdir() if p.name!='release.md']}
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--version');args=parser.parse_args()
 rows=json.loads((ROOT/'upstream/releases.json').read_text())
 if args.version:rows=[r for r in rows if r['version']==args.version];assert rows,'unknown version'
 for row in rows:print(json.dumps(build(row),ensure_ascii=False),flush=True)
