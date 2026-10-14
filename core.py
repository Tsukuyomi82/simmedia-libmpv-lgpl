"""Real CMake/Ninja preparation, compilation and static qualification.
Runs only after the separately reviewed input lock passes ci.validate().
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tarfile
import posixpath
import urllib.request

import ci

def run(argv, cwd, evidence, label, env):
    if not re.fullmatch(r'[a-zA-Z0-9_.-]+', label):
        raise ValueError('invalid log label')
    ci.write_json(evidence / (label + '.command.json'), {'argv': argv, 'cwd': str(cwd)})
    with (evidence / (label + '.stdout')).open('xb') as stdout, (evidence / (label + '.stderr')).open('xb') as stderr:
        subprocess.run(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                       timeout=14400, check=True, start_new_session=True)
    return (evidence / (label + '.stdout')).read_text(errors='strict')

def unpack(archive, target, strip_components=1, existing_empty=False):
    # Reject traversal, links, devices, duplicate files and existing destinations.
    if type(strip_components) is not int or strip_components not in (0, 1):
        raise ValueError('BLOCKED: unsupported locked archive layout')
    if existing_empty and target.exists():
        if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
            raise ValueError('BLOCKED: archive destination is not an owned empty directory')
    else:
        target.mkdir(exist_ok=False)
    with tarfile.open(archive) as t:
        members = t.getmembers()
        roots = {PurePosixPath(m.name).parts[0] for m in members if PurePosixPath(m.name).parts}
        if strip_components == 1 and len(roots) != 1:
            raise ValueError('BLOCKED: archive must have one source root')
        seen = set()
        lookup = {}
        for member in members:
            if member.name in lookup:
                raise ValueError('BLOCKED: duplicate archive member')
            lookup[member.name] = member
        def regular(member, chain=()):
            if member.name in chain:
                raise ValueError('BLOCKED: archive link cycle')
            if member.isfile() or member.isdir():
                return member
            if not (member.issym() or member.islnk()):
                raise ValueError('BLOCKED: archive link is not a regular file')
            name = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), member.linkname)
                                      if member.issym() else member.linkname)
            if name.startswith('/') or name == '..' or name.startswith('../') or name not in lookup:
                raise ValueError('BLOCKED: archive link leaves archive')
            if strip_components and PurePosixPath(name).parts[0] not in roots:
                raise ValueError('BLOCKED: archive link leaves source root')
            return regular(lookup[name], (*chain, member.name))
        for m in members:
            p = PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or '\\' in m.name or ':' in m.name or not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
                raise ValueError('BLOCKED: unsafe archive member')
            rel = PurePosixPath(*p.parts[strip_components:])
            if not rel.parts:
                continue
            dest = target.joinpath(*rel.parts)
            if m.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            if str(rel) in seen:
                raise ValueError('BLOCKED: duplicate archive file')
            seen.add(str(rel)); dest.parent.mkdir(parents=True, exist_ok=True)
            resolved = regular(m)
            if resolved.isdir():
                dest.mkdir(exist_ok=False)
                prefix = resolved.name.rstrip('/') + '/'
                for child in members:
                    if not child.name.startswith(prefix):
                        continue
                    inside = PurePosixPath(child.name[len(prefix):])
                    if inside.is_absolute() or '..' in inside.parts or '\\' in str(inside) or ':' in str(inside):
                        raise ValueError('BLOCKED: unsafe directory link child')
                    outpath = dest.joinpath(*inside.parts)
                    if child.isdir():
                        outpath.mkdir(parents=True, exist_ok=True)
                    else:
                        source_member = regular(child, (m.name,))
                        if not source_member.isfile():
                            raise ValueError('BLOCKED: nested directory link requires review')
                        outpath.parent.mkdir(parents=True, exist_ok=True)
                        with t.extractfile(source_member) as source, outpath.open('xb') as out:
                            shutil.copyfileobj(source, out)
                        outpath.chmod(source_member.mode & 0o777)
            else:
                with t.extractfile(resolved) as source, dest.open('xb') as out:
                    shutil.copyfileobj(source, out)
                dest.chmod(resolved.mode & 0o777)

def acquire(item, root):
    # Receipts contain no headers, exception text, credentials or query strings.
    from urllib.parse import urlsplit
    import uuid
    def safe_url(value):
        parsed = urlsplit(value)
        public_aom = (parsed.scheme == 'https' and parsed.netloc == 'aomedia.googlesource.com'
                      and re.fullmatch(r'/aom/\+archive/[0-9a-f]{40}\.tar\.gz', parsed.path)
                      and not parsed.query and not parsed.fragment)
        return value if public_aom else {'scheme': parsed.scheme, 'url_sha256': hashlib.sha256(value.encode()).hexdigest(), 'address': 'REDACTED'}
    path = root.joinpath(*PurePosixPath(item['archive_path']).parts)
    if path.is_symlink() or not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError('BLOCKED: archive output escapes workspace')
    evidence = Path(os.environ.get('CI_EVIDENCE_DIR', str(root / 'restored-evidence')))
    receipts = evidence / 'acquisition-receipts'
    receipts.mkdir(parents=True, exist_ok=True)
    record = {'expected_size': item['archive_size'], 'expected_sha256': item['archive_sha256'],
              'source_url': safe_url(item['url']), 'http_status': None, 'redirect_destination': None,
              'mode': 'CACHE' if path.exists() else 'DOWNLOAD', 'received_size': 0, 'status': 'BLOCKED'}
    try:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            request = urllib.request.Request(item['url'], headers={'User-Agent': 'EF-Softworks-libmpv-CI'})
            with urllib.request.urlopen(request, timeout=90) as source, path.open('xb') as out:
                record['http_status'] = source.getcode()
                record['redirect_destination'] = safe_url(source.url)
                if not source.url.startswith('https://'):
                    raise ValueError('BLOCKED: insecure source redirect')
                for data in iter(lambda: source.read(1024 * 1024), b''):
                    record['received_size'] += len(data)
                    if record['received_size'] > item['archive_size']:
                        raise ValueError('BLOCKED: source exceeds locked size')
                    out.write(data)
        if path.stat().st_size != item['archive_size'] or ci.digest(path) != item['archive_sha256']:
            raise ValueError('BLOCKED: source size/hash mismatch')
        record['status'] = 'PASS'
        return path
    except Exception as error:
        record['error_type'] = type(error).__name__
        record['http_status'] = getattr(error, 'code', record['http_status'])
        # Avoid urllib exception strings which may disclose signed URLs.
        if isinstance(error, ValueError):
            raise
        raise ValueError('BLOCKED: source acquisition failed; see sanitized receipt') from None
    finally:
        record['actual_size'] = path.stat().st_size if path.is_file() else None
        record['actual_sha256'] = ci.digest(path) if path.is_file() else None
        ci.write_json(receipts / (str(uuid.uuid4()) + '.json'), record)

def bootstrap(lock, root, evidence):
    (root / 'tools').mkdir(exist_ok=False)
    merged = root / 'tools/rust'
    merged.mkdir()
    records = []
    for item in lock['tool_archives']:
        archive = acquire(item, root)
        dest = root / item['destination']
        unpack(archive, dest)
        if item.get('merge_rust_component'):
            component = ci.confined(dest, item['merge_rust_component'])
            # manifest.in is component-local installer bookkeeping, not runtime
            # payload. Preserve its exact bytes separately; no overwrite/ignore.
            manifest = ci.confined(component, 'manifest.in')
            manifest_dest = evidence / 'rust-installer-manifests' / Path(item['destination']).name / 'manifest.in'
            manifest_dest.parent.mkdir(parents=True, exist_ok=False)
            with manifest.open('rb') as inp, manifest_dest.open('xb') as out:
                shutil.copyfileobj(inp, out)
            if ci.digest(manifest_dest) != ci.digest(manifest):
                raise ValueError('BLOCKED: Rust installer manifest copy differs')
            ci.write_json(manifest_dest.parent / 'receipt.json', {
                'component': item['merge_rust_component'],
                'archive_sha256': item['archive_sha256'],
                'manifest_sha256': ci.digest(manifest_dest),
                'scope': 'COMPONENT_LOCAL_INSTALLER_METADATA'})
            for source in component.rglob('*'):
                if not source.is_file():
                    continue
                if source.relative_to(component).as_posix() == 'manifest.in':
                    continue
                target = merged / source.relative_to(component)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if ci.digest(target) != ci.digest(source):
                        raise ValueError('BLOCKED: Rust component file collision')
                else:
                    with source.open('rb') as inp, target.open('xb') as out:
                        shutil.copyfileobj(inp, out)
                    target.chmod(source.stat().st_mode & 0o777)
        records.append({'url': item['url'], 'archive_sha256': ci.digest(archive),
                        'destination': item['destination']})
    ci.write_json(evidence / 'tool-archive-receipts.json', records)
    runtime = []
    for item in lock['runtime_source_inputs']:
        archive = acquire(item, root)
        runtime.append({'name': item['name'], 'revision': item.get('revision'),
                        'url': item['url'], 'sha256': ci.digest(archive)})
    ci.write_json(evidence / 'toolchain-corresponding-source.json', runtime)
    sdk = {}
    for relative, item in lock['sdk_libraries'].items():
        path = ci.confined(root, relative)
        if ci.digest(path) != item['sha256']:
            raise ValueError('BLOCKED: SDK library hash differs')
        sdk[relative] = item
    ci.write_json(evidence / 'sdk-library-origins.json', sdk)

def environment(lock, root):
    tools = {}
    for name, entry in lock['toolchain'].items():
        if entry.get('kind') == 'container':
            p = Path(entry['path'])
            if str(p.resolve(strict=True)) != entry['real_path']:
                raise ValueError('BLOCKED: container tool resolution differs ' + name)
        else:
            p = ci.confined(root, entry['path'])
        if ci.digest(p) != entry['sha256']:
            raise ValueError('BLOCKED: tool hash differs ' + name)
        tools[name] = str(p)
    # Container's FFBUILD_CONFIGURE/CFLAGS/LDFLAGS/etc are not inherited.
    env = {'HOME': str(root / 'home'), 'PATH': lock['isolated_path'].replace('{root}', str(root)),
           'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'PKG_CONFIG_PATH': '', 'PKG_CONFIG_LIBDIR': str(root / 'stage/lib/pkgconfig'),
           'PKG_CONFIG_SYSROOT_DIR': '', 'SOURCE_DATE_EPOCH': str(lock['source_date_epoch']),
           'CARGO_HOME': str(root / 'tools/rust/.cargo'), 'CARGO_NET_OFFLINE': 'true',
           'CC_x86_64_unknown_linux_gnu': tools['host-cc'],
           'CXX_x86_64_unknown_linux_gnu': tools['host-cxx'],
           'CC_x86_64_pc_windows_gnullvm': str(root / 'tools/llvm/bin/x86_64-w64-mingw32-clang'),
           'CXX_x86_64_pc_windows_gnullvm': str(root / 'tools/llvm/bin/x86_64-w64-mingw32-clang++')}
    return tools, env

def prepare(lock, root, evidence):
    bootstrap(lock, root, evidence)
    tools, env = environment(lock, root)
    for name in ['home', 'sources', 'stage']:
        (root / name).mkdir(exist_ok=False)
    receipts = []
    for name in lock['active']:
        s = lock['sources'][name]
        archive = acquire(s, root)
        if ci.digest(archive) != s['archive_sha256']:
            raise ValueError('BLOCKED: source archive differs ' + name)
        dest = root / 'sources' / name
        unpack(archive, dest, s['strip_components'])
        for doc in s['license']['documents']:
            relative = '/'.join(doc['path'].split('/')[s['strip_components']:])
            actual = ci.confined(dest, relative)
            if ci.digest(actual) != doc['sha256']:
                raise ValueError('BLOCKED: license document differs ' + name)
        # A local import commit is explicitly distinct from the upstream revision.
        run([tools['git'], 'init'], dest, evidence, name + '.git-init', env)
        run([tools['git'], 'add', '.'], dest, evidence, name + '.git-add', env)
        run([tools['git'], '-c', 'user.name=EF Softworks CI', '-c', 'user.email=ci@example.invalid',
             'commit', '-m', 'Imported exact source archive'], dest, evidence, name + '.git-base', env)
        for i, item in enumerate(s['patches']):
            p = ci.confined(root, item['path'])
            if ci.digest(p) != item['sha256']:
                raise ValueError('BLOCKED: patch differs')
            run([tools['git'], 'apply', '--check', str(p)], dest, evidence, name + '.patch-check-' + str(i), env)
            run([tools['git'], 'apply', str(p)], dest, evidence, name + '.patch-apply-' + str(i), env)
            receipts.append({'component': name, 'patch': item['path'], 'sha256': item['sha256'], 'status': 'APPLIED'})
        for item in s.get('embedded_patches', []):
            patch = ci.confined(dest, item['path'])
            if ci.digest(patch) != item['sha256']:
                raise ValueError('BLOCKED: embedded patch hash differs')
            label = name + '.embedded-' + str(len(receipts))
            run([tools['git'], 'apply', '--check', str(patch)], dest, evidence, label + '.check', env)
            run([tools['git'], 'apply', str(patch)], dest, evidence, label + '.apply', env)
            receipts.append({'component': name, **item, 'status': 'APPLIED'})
        for item in s.get('transforms', []):
            path = ci.confined(dest, item['path'])
            if ci.digest(path) != item['before']:
                raise ValueError('BLOCKED: source transformation preimage differs')
            data = path.read_bytes()
            if item['kind'] == 'replace':
                if data.count(item['old'].encode()) != item['count']:
                    raise ValueError('BLOCKED: source replacement count differs')
                data = data.replace(item['old'].encode(), item['new'].encode())
            elif item['kind'] == 'remove_matching_lines':
                data = b''.join(line for line in data.splitlines(keepends=True)
                                if item['match'].encode() not in line)
            else:
                raise ValueError('BLOCKED: unknown source transformation')
            if hashlib.sha256(data).hexdigest() != item['after']:
                raise ValueError('BLOCKED: source transformation postimage differs')
            path.write_bytes(data)
            receipts.append({'component': name, **item, 'status': 'APPLIED'})
    for item in lock['submodules']:
        archive = acquire({'url': item['url'], 'archive_path': item['archive_path'],
                           'archive_size': item['size'], 'archive_sha256': item['sha256']}, root)
        dest = root / 'sources' / item['component'] / item['path']
        dest.parent.mkdir(parents=True, exist_ok=True)
        unpack(archive, dest, existing_empty=True)
        receipts.append({'component': item['component'], 'submodule': item['path'],
                         'revision': item['revision'], 'sha256': item['sha256'], 'status': 'MATERIALIZED'})
    for item in lock['vendors']:
        source = ci.confined(root / 'sources', item['from'])
        dest = root / 'sources' / item['component'] / item['path']
        if dest.is_symlink() or (dest.exists() and (not dest.is_dir() or any(dest.iterdir()))):
            raise ValueError('BLOCKED: vendor destination already exists')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, dest, ignore=shutil.ignore_patterns('.git'), dirs_exist_ok=True)
        receipts.append({**item, 'revision': lock['sources'][item['from']]['revision'], 'status': 'MATERIALIZED'})
    for name in lock['active']:
        dest = root / 'sources' / name
        run([tools['git'], 'add', '--intent-to-add', '--force', '.'], dest, evidence, name + '.include-new-files', env)
        run([tools['git'], 'diff', '--binary', 'HEAD'], dest, evidence, name + '.final-diff', env)
    ci.write_json(evidence / 'patch-receipts.json', receipts)
    ci.write_json(evidence / 'source-revisions.json', lock['sources'])
    vendor = root / 'rust-vendor'; vendor.mkdir(exist_ok=False)
    for item in lock['rust_crates']:
        archive = acquire(item, root)
        dest = vendor / (item['name'] + '-' + item['version'])
        unpack(archive, dest)
        checksums = {str(path.relative_to(dest)): ci.digest(path)
                     for path in dest.rglob('*') if path.is_file()}
        ci.write_json(dest / '.cargo-checksum.json', {'package': item['archive_sha256'], 'files': checksums})
    cargo_config = root / 'tools/rust/.cargo'
    cargo_config.mkdir(exist_ok=False)
    config = ('[net]\noffline = true\n[source.crates-io]\nreplace-with = "vendored-sources"\n'
              '[source.vendored-sources]\ndirectory = ' + json.dumps(str(vendor)) + '\n'
              '[target.x86_64-pc-windows-gnullvm]\nlinker = ' +
              json.dumps(str(root / 'tools/llvm/bin/x86_64-w64-mingw32-clang++')) + '\n')
    with (cargo_config / 'config.toml').open('x') as out:
        out.write(config)
    metadata = run([tools['cargo'], 'metadata', '--manifest-path', str(root / 'sources/subrandr/Cargo.toml'),
                    '--format-version', '1', '--locked', '--offline'], root, evidence, 'cargo-metadata', env)
    data = json.loads(metadata)
    expected = {(item['name'], item['version']) for item in lock['rust_crates']}
    for item in data['packages']:
        if item['source'] and (item['name'], item['version']) not in expected:
            raise ValueError('BLOCKED: Cargo resolved an unlocked source')
    ci.write_json(evidence / 'rust-resolved-graph.json', data)
    records = {}
    for name, entry in lock['toolchain'].items():
        version = run([tools[name], *entry['version_args']], root, evidence, 'version.' + name, env)
        if entry['version'] not in version:
            raise ValueError('BLOCKED: tool version differs ' + name)
        records[name] = {'sha256': ci.digest(Path(tools[name])), 'version_output': version}
    ci.write_json(evidence / 'toolchain-records.json', records)
    overlay = ci.confined(root, lock['recipe_overlay'])
    if ci.digest(overlay) != lock['files'][lock['recipe_overlay']]:
        raise ValueError('BLOCKED: recipe overlay differs')
    unpack(overlay, root / 'recipe')
    run([tools['cmake'], '-S', str(root / 'recipe'), '-B', str(root / 'build'), '-G', 'Ninja',
         '-DTARGET_ARCH=x86_64-w64-mingw32', '-DGCC_ARCH=x86-64', '-DCOMPILER_TOOLCHAIN=clang',
         '-DCMAKE_C_COMPILER=' + tools['host-cc'],
         '-DLLVM_ROOT=' + str(root / 'tools/llvm'), '-DMINGW_INSTALL_PREFIX=' + str(root / 'stage'),
         '-DRUSTUP_LOCATION=' + str(root / 'tools/rust'), '-DMAKEJOBS=2',
         '-DSINGLE_SOURCE_LOCATION=' + str(root / 'sources'), '-DENABLE_CCACHE=OFF',
         '-DCMAKE_MAKE_PROGRAM=' + tools['ninja'], '-DEVIDENCE_DIR=' + str(evidence)],
        root, evidence, 'configure', env)
    configured = json.loads((evidence / 'configured-graph.json').read_text())
    active = ci.closure(configured, 'mpv')
    graph = {name: configured[name] for name in sorted(active)}
    if active != set(lock['active']) or graph != lock['graph']:
        raise ValueError('BLOCKED: generated graph differs')
    ci.write_json(evidence / 'active-graph.json', graph)
    ci.write_json(evidence / 'configure-records.json', {'graph': graph, 'CMakeCache.sha256': ci.digest(root / 'build/CMakeCache.txt')})

def compile_(lock, root, evidence):
    tools, env = environment(lock, root)
    # Build the already validated graph in dependency order and bind installed
    # libraries to the component that produced them. No clean/update targets.
    visited, visiting, order = set(), set(), []
    def visit(name):
        if name in visiting:
            raise ValueError('BLOCKED: cyclic build graph')
        if name in visited:
            return
        visiting.add(name)
        for child in lock['graph'][name]:
            visit(child)
        visiting.remove(name); visited.add(name); order.append(name)
    visit('mpv')
    installed = {}
    for name in order:
        run([tools['ninja'], '-C', str(root / 'build'), '-v', '-j2', name],
            root, evidence, 'compile.' + name, env)
        for path in (root / 'stage').rglob('*'):
            if not path.is_file():
                continue
            if path.is_symlink() or not path.resolve().is_relative_to((root / 'stage').resolve()):
                raise ValueError('BLOCKED: installed library path escapes stage')
            if path.suffix.lower() not in ('.a', '.lib', '.dll'):
                continue
            key = str(path.relative_to(root)); value = ci.digest(path)
            if key in installed and installed[key]['sha256'] != value:
                raise ValueError('BLOCKED: component overwrote installed library ' + key)
            installed.setdefault(key, {'component': name, 'sha256': value})
    ci.write_json(evidence / 'installed-library-origins.json', installed)
    capture_rust_usage(lock, root, evidence)

def capture_rust_usage(lock, root, evidence):
    metadata = json.loads((evidence / 'rust-resolved-graph.json').read_text())
    packages = {item['id']: item for item in metadata['packages']}
    locked = {(item['name'], item['version']): item for item in lock['rust_crates']}
    used = set()
    for log in (root / 'build').rglob('*'):
        if not log.is_file() or log.suffix not in ('.log', '.stdout'):
            continue
        for line in log.read_text(errors='replace').splitlines():
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get('reason') == 'compiler-artifact':
                identity = message.get('package_id')
                if identity not in packages:
                    raise ValueError('BLOCKED: compiled Cargo package absent from locked metadata')
                used.add(identity)
    if not used:
        raise ValueError('BLOCKED: actual Rust compiler-artifact evidence absent')
    records = []
    destination = evidence / 'rust-used-source'
    destination.mkdir(exist_ok=False)
    for identity in sorted(used):
        item = packages[identity]
        row = {'package_id': identity, 'name': item['name'], 'version': item['version'],
               'source': item['source'], 'license': item.get('license')}
        if item['source']:
            key = (item['name'], item['version'])
            if key not in locked:
                raise ValueError('BLOCKED: compiled Rust source is not locked')
            pin = locked[key]
            if not pin.get('license_documents') or not pin.get('selected_license'):
                raise ValueError('BLOCKED: compiled Rust license text/selection missing')
            archive = ci.confined(root, pin['archive_path'])
            if ci.digest(archive) != pin['archive_sha256']:
                raise ValueError('BLOCKED: compiled Rust source checksum differs')
            target = destination / archive.name
            with archive.open('rb') as inp, target.open('xb') as out:
                shutil.copyfileobj(inp, out)
            row.update({'archive': str(target.relative_to(evidence)),
                        'sha256': pin['archive_sha256'], 'license_documents': pin['license_documents'], 'selected_license': pin['selected_license']})
        else:
            manifest = Path(item['manifest_path']).resolve(strict=True)
            if not manifest.is_relative_to((root / 'sources/subrandr').resolve()):
                raise ValueError('BLOCKED: local Cargo source outside locked subrandr')
            row['source_component'] = 'subrandr'
        records.append(row)
    ci.write_json(evidence / 'rust-actually-compiled.json', records)
    ci.write_json(evidence / 'rust-unused-candidates.json',
                  [{'name': i['name'], 'version': i['version'], 'sha256': i['archive_sha256']}
                   for key, i in locked.items()
                   if key not in {(packages[k]['name'], packages[k]['version']) for k in used}])


def link_inventory(lock, root, evidence, analysis):
    mapfile = evidence / 'libmpv.map'
    if not mapfile.is_file() or mapfile.stat().st_size == 0:
        raise ValueError('BLOCKED: linker map missing')
    origins = json.loads((evidence / 'installed-library-origins.json').read_text())
    origins.update(json.loads((evidence / 'sdk-library-origins.json').read_text()))
    candidates = {str(root / path): row for path, row in origins.items()}
    text = mapfile.read_text(errors='strict')
    libraries = sorted(set(re.findall(r'([^\s()]+\.(?:a|lib))(?:\(|\s|$)', text)))
    if not libraries:
        raise ValueError('BLOCKED: linker map has no resolvable archive inputs')
    records, unresolved = [], []
    for name in libraries:
        path = Path(name)
        matches = [(key, row) for key, row in candidates.items()
                   if (Path(key) == path if path.is_absolute() else Path(key).name == path.name)]
        if len(matches) != 1:
            unresolved.append(name); continue
        key, row = matches[0]
        if ci.digest(Path(key)) != row['sha256']:
            raise ValueError('BLOCKED: linked library hash differs')
        records.append({'path': key, **row})
    imports = sorted(set(re.findall(r'^\s*Name: ([^\r\n]+\.dll)\s*$', analysis, re.M | re.I)))
    system = {name.casefold() for name in lock.get('windows_system_imports', [])}
    closure = [{'name': name, 'status': 'WINDOWS_SYSTEM' if name.casefold() in system
                or name.casefold().startswith(('api-ms-win-', 'ext-ms-win-')) else 'UNRESOLVED_RUNTIME_SOURCE'}
               for name in imports]
    prohibited = sorted({r['component'] for r in records} & ci.DENIED)
    status = 'PASS' if records and not unresolved and not prohibited and closure and all(
        item['status'] == 'WINDOWS_SYSTEM' for item in closure) else 'BLOCKED'
    ci.write_json(evidence / 'link-inventory.json', {'status': status, 'libraries': records,
                  'components': sorted({r['component'] for r in records}), 'unresolved_libraries': unresolved,
                  'prohibited_components': prohibited, 'maps': [{'path': 'libmpv.map', 'sha256': ci.digest(mapfile)}],
                  'import_closure': closure, 'dynamic_load_runtime': 'WINDOWS_QA_REQUIRED'})

def pe_amd64(path):
    with path.open('rb') as f:
        if f.read(2) != b'MZ':
            raise ValueError('BLOCKED: not PE')
        f.seek(0x3c); offset = struct.unpack('<I', f.read(4))[0]
        f.seek(offset)
        if f.read(4) != b'PE\0\0' or struct.unpack('<H', f.read(2))[0] != 0x8664:
            raise ValueError('BLOCKED: not AMD64 PE')

def qualify(lock, root, evidence):
    tools, env = environment(lock, root)
    # Packaging copies are not independent DLL candidates. Qualify the exact
    # ExternalProject build output, whose path is locked before execution.
    dll = ci.confined(root, lock['dll_output'])
    pe_amd64(dll)
    analysis = run([tools['llvm-readobj'], '--file-headers', '--coff-exports', '--coff-imports', str(dll)],
                   root, evidence, 'dll-readobj', env)
    link_inventory(lock, root, evidence, analysis)
    exported = set(re.findall(r'^\s*Name: (mpv_\w+)\s*$', analysis, re.M))
    if not set(lock['required_exports']).issubset(exported):
        raise ValueError('BLOCKED: required exports missing')
    header = ci.confined(root, 'sources/mpv/include/mpv/client.h')
    version = re.search(r'#define\s+MPV_CLIENT_API_VERSION\s+MPV_MAKE_VERSION\((\d+),\s*(\d+)\)', header.read_text())
    if not version or tuple(map(int, version.groups())) < (1, 108):
        raise ValueError('BLOCKED: client API below 1.108')
    ff = ci.confined(root, lock['ffmpeg_config'])
    for option in ['GPL', 'NONFREE', 'CHROMAPRINT']:
        if not re.search(r'^#define CONFIG_' + option + r' 0$', ff.read_text(), re.M):
            raise ValueError('BLOCKED: prohibited feature not excluded ' + option)
    options = json.loads(ci.confined(root, lock['mpv_buildoptions']).read_text())
    values = {item['name']: item['value'] for item in options}
    if values.get('gpl') is not False or values.get('cplayer') is not False:
        raise ValueError('BLOCKED: generated mpv GPL/player configuration differs')
    linked = json.loads((evidence / 'link-inventory.json').read_text())
    if linked['status'] != 'PASS' or linked['prohibited_components'] != []:
        raise ValueError('BLOCKED: link receipt incomplete')
    # Import and dynamic-load closure requires reviewed recipe/linker evidence,
    # never merely a DLL-name string scan.
    allowed = set(lock['active']) | {'llvm-runtime', 'mingw-w64-runtime'}
    if set(linked['components']) - allowed or not linked['maps'] or not linked['import_closure']:
        raise ValueError('BLOCKED: actual link closure incomplete')
    (evidence / 'binary').mkdir(exist_ok=False)
    with dll.open('rb') as source, (evidence / 'binary/libmpv-2.dll').open('xb') as dest:
        shutil.copyfileobj(source, dest)
    inventory = []
    licenses = evidence / 'licenses'; licenses.mkdir(exist_ok=False)
    for n in lock['active']:
        for relative in lock['sources'][n]['license_paths']:
            src = ci.confined(root / 'sources' / n, relative)
            dest = licenses / n / relative; dest.parent.mkdir(parents=True, exist_ok=True)
            with src.open('rb') as source, dest.open('xb') as out:
                shutil.copyfileobj(source, out)
            inventory.append({'component': n, 'path': relative, 'sha256': ci.digest(dest)})
    if not inventory:
        raise ValueError('BLOCKED: licenses absent')
    ci.write_json(evidence / 'license-inventory.json', inventory)
    ci.write_json(evidence / 'dll-static-analysis.json', {'status': 'PASS',
                  'prohibited_components': [], 'exports': sorted(exported),
                  'api_header': list(map(int, version.groups())), 'DLL_SHA256': ci.digest(dll),
                  'runtime': 'NOT_TESTED'})
    with (evidence / 'reproduce.txt').open('x') as f:
        f.write('Use the included exact lock, Source snapshots, recipe and command records.\n'
                'Run prepare, compile and qualify in the locked container.\n'
                'This receipt does not establish byte-identical reproducibility or Windows Runtime PASS.\n')

if __name__ == '__main__':
    import sys
    phase = sys.argv[1]
    root = Path.cwd().resolve(); evidence = Path(os.environ['CI_EVIDENCE_DIR']).resolve()
    lock = json.loads((root / 'build-lock.json').read_text())
    ci.validate(lock, root, os.environ.get('ImageVersion'))
    {'prepare': prepare, 'compile': compile_, 'qualify': qualify}[phase](lock, root, evidence)
