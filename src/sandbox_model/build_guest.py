"""只在 gVisor 构建容器内使用：公共依赖安装，以及冻结后可信导出。"""
import base64
import json
import os
from pathlib import Path
import resource
import re
import stat
import subprocess
import sys
import tarfile
from urllib.parse import urlsplit

PREFIX = Path('/opt/env')
LIMIT = 128 * 1024 * 1024
HOSTS = {'pypi.org', 'files.pythonhosted.org', 'registry.npmjs.org'}


def public_url(value):
    # 锁文件中的下载地址同样需要校验，不能借依赖声明切换到其他包源。
    target = urlsplit(value)
    if (target.scheme != 'https' or target.hostname not in HOSTS or target.username
            or target.password or target.port not in (None, 443) or target.query or target.fragment):
        raise ValueError('DEPENDENCY_SOURCE_NOT_ALLOWED')


def run(args):
    # 原始安装日志只能留在构建 RAM，不进入服务日志或结果报告。
    with open('/tmp/install.log', 'wb') as output:
        result = subprocess.run(args, stdout=output, stderr=output, timeout=180,
                                env=os.environ | {'PIP_CONFIG_FILE':'/dev/null', 'PIP_DISABLE_PIP_VERSION_CHECK':'1',
                                    'PYTHONNOUSERSITE':'1', 'npm_config_audit':'false', 'npm_config_fund':'false'})
    if result.returncode:
        tail = Path('/tmp/install.log').read_bytes()[-65536:].lower()
        if b'resolutionimpossible' in tail or b'conflicting dependencies' in tail:
            raise ValueError('DEPENDENCY_CONFLICT')
        if b'no matching distribution' in tail or b'notarget' in tail or b'e404' in tail:
            raise ValueError('DEPENDENCY_NOT_FOUND_OR_UNSUPPORTED')
        if b'proxyerror' in tail or b'etimedout' in tail or b'connection' in tail or b'certificate' in tail:
            raise ValueError('DEPENDENCY_DOWNLOAD_FAILED')
        raise ValueError('DEPENDENCY_INSTALL_FAILED')


def install(spec):
    # 仅安装公共依赖，不接收任务数据；同时为单文件写入设定上限。
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    dependencies = spec['dependencies']
    if spec['environment'] == 'python':
        args = [sys.executable, '-m', 'pip']
        common = ['--index-url', 'https://pypi.org/simple', '--no-build-isolation', '--retries', '1', '--timeout', '15']
        # 编译后端由固定构建模板提供；不自动安装未知构建后端。
        if spec.get('lock'):
            # 镜像被清理后重建时，沿用已登记的间接依赖和摘要。
            items = spec['lock']['packages']
        else:
            run(args + ['install', '--dry-run', '--ignore-installed', '--report', '/tmp/resolved.json', *common, *dependencies])
            report = json.loads(Path('/tmp/resolved.json').read_text())
            items = []
            for entry in report['install']:
                download = entry['download_info']
                public_url(download['url'])
                digest = download['archive_info']['hashes']['sha256']
                name, version = entry['metadata']['name'], entry['metadata']['version']
                if not re.fullmatch(r'[0-9a-f]{64}', digest):
                    raise ValueError('DEPENDENCY_HASH_INVALID')
                items.append({'name':name, 'version':version, 'url':download['url'], 'sha256':digest})
            if not 0 < len(items) <= 256:
                raise ValueError('DEPENDENCY_COUNT_LIMIT')
        requirements = ''.join(f"{x['name']}=={x['version']} --hash=sha256:{x['sha256']}\n" for x in items)
        # 先解析并固定所有依赖，再按摘要安装，避免运行期重新选择依赖版本。
        Path('/tmp/locked.txt').write_text(requirements)
        run([sys.executable, '-m', 'venv', '--without-pip', '--copies', str(PREFIX/'python')])
        run(args + ['--python', str(PREFIX/'python/bin/python'), 'install', '--no-index', '--find-links=/opt/build-wheels', 'setuptools==80.9.0', 'wheel==0.45.1'])
        run(args + ['--python', str(PREFIX/'python/bin/python'), 'install', '--require-hashes', '--no-deps',
                    '--no-compile', '--no-cache-dir', '-r', '/tmp/locked.txt', *common])
        run(args + ['--python', str(PREFIX/'python/bin/python'), 'check'])
        lock = {'language':'python', 'build_tools':{'setuptools':'80.9.0','wheel':'0.45.1','pip':'25.3'}, 'packages':sorted(items, key=lambda x:x['name'].lower())}
    else:
        directory = PREFIX/'node'
        directory.mkdir()
        package = {'name':'sandbox-public-environment', 'version':'1.0.0', 'private':True,
                   'dependencies':dict(item.rsplit('@',1) for item in dependencies)}
        (directory/'package.json').write_text(json.dumps(package))
        os.chdir(directory)
        options = ['--registry=https://registry.npmjs.org', '--cache=/tmp/npm-cache', '--no-audit', '--no-fund',
                   '--fetch-retries=1', '--fetch-timeout=15000']
        if spec.get('lock'):
            lock = spec['lock']['lockfile']
            (directory/'package-lock.json').write_text(json.dumps(lock))
        else:
            # 先生成锁文件且不运行安装脚本，检查包源后才执行 npm ci。
            run(['npm', 'install', '--package-lock-only', '--ignore-scripts', *options])
            lock = json.loads((directory/'package-lock.json').read_text())
        if len(lock.get('packages',{})) > 256:
            raise ValueError('DEPENDENCY_COUNT_LIMIT')
        for name, entry in lock.get('packages',{}).items():
            if name:
                public_url(entry.get('resolved',''))
                if not entry.get('integrity','').startswith('sha512-') or entry.get('link'):
                    raise ValueError('DEPENDENCY_HASH_INVALID')
        run(['npm', 'ci', *options])
        # lifecycle 脚本不得改写锁文件后冒充另一个构建结果。
        if json.loads((directory/'package-lock.json').read_text()) != lock:
            raise ValueError('DEPENDENCY_LOCK_CHANGED')
        run(['npm', 'ls', '--all', '--json'])
        lock = {'language':'node', 'lockfile':lock}
    (PREFIX/'lock.json').write_text(json.dumps(lock, sort_keys=True, separators=(',',':')))


def export():
    """安装进程已被可信管理侧终止；不跟随链接、不导出前缀外数据。"""
    total, count = 0, 0
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|', format=tarfile.PAX_FORMAT) as archive:
        for directory, subdirs, files in os.walk(PREFIX, followlinks=False):
            for name in sorted(subdirs + files):
                path = Path(directory)/name
                info = path.lstat()
                count += 1
                if count > 20000 or info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    raise ValueError('BUILD_EXPORT_LIMIT')
                relative = path.relative_to(PREFIX).as_posix()
                member = tarfile.TarInfo('env/' + relative)
                # 导出统一所有权和权限；只保留运行依赖所需的可执行位。
                member.uid = member.gid = 0
                member.mode = 0o755 if info.st_mode & 0o111 else 0o644
                if stat.S_ISLNK(info.st_mode):
                    destination = os.readlink(path)
                    resolved = (path.parent/destination).resolve()
                    if os.path.isabs(destination) or not resolved.is_relative_to(PREFIX):
                        raise ValueError('BUILD_EXPORT_UNSAFE_LINK')
                    member.type = tarfile.SYMTYPE
                    member.linkname = destination
                    archive.addfile(member)
                elif stat.S_ISDIR(info.st_mode):
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o755
                    archive.addfile(member)
                elif stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    if total > LIMIT:
                        raise ValueError('BUILD_EXPORT_LIMIT')
                    member.size = info.st_size
                    with path.open('rb') as stream:
                        archive.addfile(member, stream)
                else:
                    raise ValueError('BUILD_EXPORT_SPECIAL_FILE')


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'export':
            export()
        else:
            install(json.loads(base64.b64decode(sys.argv[1], validate=True)))
    except Exception as error:
        # 包的任意原始异常文本不向节点输出。
        code = str(error)
        if not re.fullmatch(r'(DEPENDENCY|BUILD)_[A-Z_]+', code):
            code = 'DEPENDENCY_PREPARATION_FAILED'
        print(code, file=sys.stderr if sys.argv[1] == 'export' else sys.stdout)
        sys.exit(1)
