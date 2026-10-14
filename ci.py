"""Fail-closed libmpv CI input, graph, execution and evidence gates.
No product source, deletion, adoption, signing or deployment operations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import shutil
import io
import urllib.request
import urllib.error

DENIED = {'fftw', 'fftw3', 'chromaprint', 'x264', 'x265', 'davs2',
          'libdvdcss', 'libdvdnav', 'libdvdread', 'rubberband', 'readline'}

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def confined(root, relative):
    p = Path(relative)
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise ValueError('BLOCKED: invalid relative path')
    root = root.resolve(strict=True)
    current = root
    for part in p.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('BLOCKED: symbolic link input')
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError('BLOCKED: path outside isolated root')
    return resolved

def closure(graph, target):
    seen = set()
    def visit(n):
        if n in seen:
            return
        if n not in graph or n in DENIED:
            raise ValueError('BLOCKED: missing or prohibited dependency ' + n)
        seen.add(n)
        for child in graph[n]:
            visit(child)
    visit(target)
    return seen

def validate(lock, root, image_version):
    if lock.get('status') != 'REVIEWED_LOCK_COMPLETE':
        raise ValueError('BLOCKED: incomplete reviewed lock')
    if lock.get('host_runner_policy') != 'STANDARD_HOST_RECORDED_BUILD_TOOLS_PINNED_CONTAINER':
        raise ValueError('BLOCKED: runner/container policy absent')
    if not re.fullmatch(r'[a-z0-9./:_-]+@sha256:[0-9a-f]{64}', lock.get('container_image', '')):
        raise ValueError('BLOCKED: unpinned container')
    policy = lock.get('artifact_policy', {})
    if policy.get('paid_usage_allowed') is not False or policy.get('source_omission_allowed') is not False:
        raise ValueError('BLOCKED: unsafe artifact policy')
    if not 1 <= policy.get('retention_days', 0) <= 1 or policy.get('maximum_bytes', 0) <= 0:
        raise ValueError('BLOCKED: missing artifact limits')
    active = closure(lock['graph'], 'mpv')
    if active != set(lock['active']) or not active:
        raise ValueError('BLOCKED: active graph differs')
    for n in active:
        s = lock['sources'][n]
        if not re.fullmatch(r'[0-9a-f]{64}', s.get('archive_sha256', '')):
            raise ValueError('BLOCKED: absent source hash')
        if not s.get('url', '').startswith('https://') or not s.get('license'):
            raise ValueError('BLOCKED: absent source/license')
        if s.get('revision') and not re.fullmatch(r'[0-9a-f]{40}', s['revision']):
            raise ValueError('BLOCKED: floating revision')
        selected = s['license'].get('selected', '')
        if not selected or re.search(r'(?<!L)GPL-|nonfree|LicenseRef-Unknown', selected, re.I):
            raise ValueError('BLOCKED: incompatible selected license ' + n)
        if lock['license_review'].get(n) != 'APPROVED_COMPATIBLE':
            raise ValueError('BLOCKED: license review incomplete')
    if not lock.get('toolchain') or not lock.get('files'):
        raise ValueError('BLOCKED: missing toolchain/file closure')
    for rel, expected in lock['files'].items():
        if not re.fullmatch(r'[0-9a-f]{64}', expected) or digest(confined(root, rel)) != expected:
            raise ValueError('BLOCKED: input hash mismatch ' + rel)
    for crate in lock['rust_crates']:
        if not crate.get('selected_license') or re.search(r'(?<!L)GPL-|nonfree|LicenseRef-Unknown', crate['selected_license'], re.I):
            raise ValueError('BLOCKED: prohibited Rust license')
    for name, tool in lock['toolchain'].items():
        if not tool.get('version') or not re.fullmatch(r'[0-9a-f]{64}', tool.get('sha256', '')):
            raise ValueError('BLOCKED: toolchain pin absent ' + name)
    return active

def write_json(path, value):
    with path.open('x', encoding='utf8') as f:
        json.dump(value, f, indent=2)

def snapshot(root, output, phase):
    root = root.resolve(strict=True)
    dest = output / phase
    dest.mkdir(exist_ok=False)
    inventory = []
    with (dest / 'source.tar.gz').open('xb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(root)
            if '.git' in relative.parts:
                continue
            if path.is_symlink():
                raise ValueError('BLOCKED: final source contains symlink; vendor before capture')
            if path.is_file():
                inventory.append({'path': str(relative), 'size': path.stat().st_size, 'sha256': digest(path)})
                archive.add(path, arcname=str(relative), recursive=False)
    write_json(dest / 'source-manifest.json', inventory)
    write_json(dest / 'source-sha256.json', {'source.tar.gz': digest(dest / 'source.tar.gz')})

def execute(lock, root, output, phase):
    # Only an exact reviewed local entrypoint is executed. No user command input.
    item = lock['entrypoints'][phase]
    script = confined(root, item['path'])
    if digest(script) != item['sha256'] or lock['files'].get(item['path']) != item['sha256']:
        raise ValueError('BLOCKED: unreviewed entrypoint')
    with (output / (phase + '.stdout')).open('xb') as out, (output / (phase + '.stderr')).open('xb') as err:
        subprocess.run(['/bin/bash', '-euo', 'pipefail', str(script)], cwd=root,
                       env={**os.environ, 'CI_EVIDENCE_DIR': str(output)},
                       stdout=out, stderr=err, timeout=7200, check=True)

def preserve_failure_evidence(root, output):
    logs = output / 'external-project-logs'
    logs.mkdir(exist_ok=False)
    build = root / 'build'
    if build.exists():
        for source in sorted(build.rglob('*')):
            if source.is_symlink():
                raise ValueError('BLOCKED: evidence log symlink')
            if source.is_file() and source.suffix in ('.log', '.cmake'):
                target = logs / source.relative_to(build)
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open('rb') as inp, target.open('xb') as out:
                    shutil.copyfileobj(inp, out)
    write_json(output / 'FINAL-SHA256.json',
               {str(p.relative_to(output)): digest(p) for p in output.rglob('*') if p.is_file()})


def save_corresponding_inputs(lock, root, output):
    destination = output / 'corresponding-inputs'
    destination.mkdir(exist_ok=False)
    inventory = []
    items = list(lock['sources'].values()) + lock['runtime_source_inputs'] + lock['rust_crates']
    items += [{**i, 'archive_sha256': i['sha256']} for i in lock['submodules']]
    items += [i for i in lock['tool_archives'] if i.get('name') == 'rust-src' or 'rust-src' in i['archive_path']]
    for item in items:
        path = root / item['archive_path']
        if not path.exists():
            inventory.append({'path': item['archive_path'], 'status': 'NOT_ACQUIRED'})
            continue
        path = confined(root, item['archive_path'])
        if digest(path) != item['archive_sha256']:
            inventory.append({'path': item['archive_path'], 'status': 'HASH_FAILURE_NOT_CORRESPONDING_SOURCE'})
            continue
        target = destination / item['archive_path']
        target.parent.mkdir(parents=True, exist_ok=True)
        with path.open('rb') as inp, target.open('xb') as out:
            shutil.copyfileobj(inp, out)
        inventory.append({'path': item['archive_path'], 'sha256': digest(target), 'status': 'PRESERVED'})
    for relative in lock['files']:
        path = confined(root, relative)
        target = destination / 'build-information' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with path.open('rb') as inp, target.open('xb') as out:
            shutil.copyfileobj(inp, out)
    write_json(destination / 'inputs.json', inventory)


def artifact_capacity(lock, output):
    policy = lock['artifact_policy']
    files = [p for p in output.rglob('*') if p.is_file()]
    payload = sum(p.stat().st_size for p in files)
    # Reserve ZIP headers, incompressible deflate overhead and final receipts.
    total = payload + (payload + 99) // 100 + len(files) * 4096 + 1024 * 1024
    receipt = {'required_bytes': total, 'maximum_bytes': policy['maximum_bytes'],
               'free_capacity_confirmed_bytes': policy['free_capacity_confirmed_bytes'],
               'retention_days': policy['retention_days'], 'omitted_source_files': 0,
               'status': 'PASS' if total <= min(policy['maximum_bytes'], policy['free_capacity_confirmed_bytes']) else 'BLOCKED'}
    write_json(output / 'ARTIFACT-CAPACITY.json', receipt)
    if receipt['status'] != 'PASS':
        raise ValueError('BLOCKED: full evidence exceeds approved free artifact capacity; no Source omitted')


def source_link_record(source, file):
    # Resolve one component at a time: never follow an unvalidated outside link.
    source = source.resolve(strict=True)
    relative = file.relative_to(source)
    pending = list(relative.parts)
    current = source
    seen = set()
    observed = []
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if current == source:
                raise ValueError('BLOCKED: Source link leaves component ' + str(relative))
            current = current.parent
            continue
        if part == '.git':
            raise ValueError('BLOCKED: Source link targets Git metadata ' + str(relative))
        current = current / part
        st = current.lstat()
        if current.is_symlink():
            if current in seen or len(seen) >= 64:
                raise ValueError('BLOCKED: cyclic Source link ' + str(relative))
            seen.add(current)
            target = os.readlink(current)
            if (not target or os.path.isabs(target) or '\\' in target
                    or ':' in target or '\x00' in target):
                raise ValueError('BLOCKED: invalid Source link ' + str(relative))
            target.encode('utf-8', errors='strict')
            observed.append((current, st, target))
            pending = list(Path(target).parts) + pending
            current = current.parent
        elif pending and not current.is_dir():
            raise ValueError('BLOCKED: Source link non-directory traversal ' + str(relative))
    if not (current.is_file() or current.is_dir()) or current.is_symlink():
        raise ValueError('BLOCKED: Source link target is not a regular file/directory ' + str(relative))
    if not current.resolve(strict=True).is_relative_to(source):
        raise ValueError('BLOCKED: Source link target escapes ' + str(relative))
    for path, before, target in observed:
        after = path.lstat()
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or os.readlink(path) != target):
            raise ValueError('BLOCKED: Source link changed during capture ' + str(relative))
    target = next(target for path, _, target in observed if path == file)
    return {'path': relative.as_posix(), 'type': 'symlink', 'target': target,
            'sha256': hashlib.sha256(target.encode('utf-8')).hexdigest(),
            'resolved_target': current.relative_to(source).as_posix()}, current


def save_final_source_state(lock, root, output):
    destination = output / 'final-source-state'
    destination.mkdir(exist_ok=False)
    inventory = []
    git = lock['toolchain']['git']['path']
    for name in lock['active']:
        source = root / 'sources' / name
        if source.is_symlink():
            raise ValueError('BLOCKED: Source root symlink ' + name)
        if not source.is_dir():
            continue
        additions = []
        for file in sorted(source.rglob('*')):
            if '.git' in file.relative_to(source).parts:
                continue
            if file.is_symlink():
                try:
                    record, target = source_link_record(source, file)
                    if target.is_file():
                        payload = target.read_bytes()
                        # Verify the path identity again after reading, before saving.
                        checked, checked_target = source_link_record(source, file)
                        if checked != record or checked_target != target or hashlib.sha256(payload).hexdigest() != digest(target):
                            raise ValueError('BLOCKED: Source link target changed during capture')
                        record['target_sha256'] = hashlib.sha256(payload).hexdigest()
                        copied = destination / 'link-targets' / name / record['resolved_target']
                        copied.parent.mkdir(parents=True, exist_ok=True)
                        if copied.exists():
                            if digest(copied) != record['target_sha256']:
                                raise ValueError('BLOCKED: Source link target capture collision')
                        else:
                            with copied.open('xb') as out:
                                out.write(payload)
                    inventory.append({'component': name, **record})
                    if (source / '.git').is_dir():
                        additions.append(str(file.relative_to(source)))
                except Exception as error:
                    write_json(destination / 'link-failure.json',
                               {'component': name, 'path': file.relative_to(source).as_posix(),
                                'reason': str(error), 'status': 'BLOCKED'})
                    raise
                continue
            if file.is_file() and file.suffix.lower() in ('.c', '.cc', '.cpp', '.h', '.hpp', '.rs', '.inc', '.s', '.asm'):
                inventory.append({'component': name, 'path': file.relative_to(source).as_posix(), 'sha256': digest(file)})
                if (source / '.git').is_dir():
                    additions.append(str(file.relative_to(source)))
        if (source / '.git').is_dir():
            for start in range(0, len(additions), 128):
                subprocess.run([git, 'add', '--intent-to-add', '--force', '--', *additions[start:start+128]],
                               cwd=source, check=True, stdout=subprocess.DEVNULL, timeout=120)
            with (destination / (name + '.diff')).open('xb') as out:
                subprocess.run([git, 'diff', '--binary', 'HEAD'], cwd=source, stdout=out, check=True, timeout=120)
    write_json(destination / 'source-manifest.json', inventory)


def reacquisition_pins(lock):
    items = list(lock['sources'].values()) + lock['runtime_source_inputs'] + lock['rust_crates']
    items += [{**i, 'archive_sha256': i['sha256'], 'archive_size': i['size']} for i in lock['submodules']]
    items += [i for i in lock['tool_archives'] if 'rust-src' in i['archive_path']]
    return {i['archive_sha256']: i for i in items}


def restore_handoff(lock, root, destination):
    import core
    manifest = json.loads((destination / 'ASSET-MANIFEST.json').read_text())
    if len(manifest['files']) != 1:
        raise ValueError('BLOCKED: unexpected handoff asset set')
    item = manifest['files'][0]
    archive = confined(destination, item['name'])
    if digest(archive) != item['sha256'] or archive.stat().st_size != item['size']:
        raise ValueError('BLOCKED: handoff archive differs')
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if len(members) > 100000 or sum(m.size for m in members) > lock['handoff_policy']['maximum_expanded_bytes']:
            raise ValueError('BLOCKED: handoff expanded size exceeds bound')
    restored = root / 'restored-evidence'
    core.unpack(archive, restored, strip_components=0)
    index = json.loads((restored / 'RECONSTRUCTION.json').read_text())
    if index['lock_sha256'] != digest(root / 'build-lock.json'):
        raise ValueError('BLOCKED: build and Release lock differ')
    pins = reacquisition_pins(lock)
    for row in index['files']:
        if row['sha256'] not in pins or row['size'] != pins[row['sha256']]['archive_size']:
            raise ValueError('BLOCKED: unlocked Source reconstruction')
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or '\\' in row['path']:
            raise ValueError('BLOCKED: reconstruction path escapes')
        target = restored / relative
        if target.exists() or target.is_symlink() or not target.parent.resolve().is_relative_to(restored.resolve()):
            raise ValueError('BLOCKED: reconstruction overwrite/escape')
        source = core.acquire(pins[row['sha256']], root)
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open('rb') as inp, target.open('xb') as out: shutil.copyfileobj(inp, out)
        if digest(target) != row['sha256']: raise ValueError('BLOCKED: reconstructed Source differs')
    pack_evidence(lock, restored, root / 'release-assets')


def pack_evidence(lock, output, destination, transfer=False):
    destination.mkdir(exist_ok=False)
    archive = destination / 'qualification-evidence.tar.gz'
    maximum = (lock['handoff_policy']['maximum_total_bytes'] if transfer else lock['artifact_policy']['maximum_bytes']) - 1024 * 1024
    excluded = {}
    if transfer:
        pins = reacquisition_pins(lock)
        for file in output.rglob('*'):
            if file.is_symlink(): raise ValueError('BLOCKED: Evidence symlink')
            if file.is_file():
                value = digest(file)
                if value in pins:
                    excluded[file.relative_to(output).as_posix()] = {'path': file.relative_to(output).as_posix(), 'sha256': value, 'size': file.stat().st_size}
        write_json(output / 'RECONSTRUCTION.json', {'lock_sha256': digest(Path('build-lock.json')), 'files': list(excluded.values()), 'policy': 'Exact archived bytes restored; no generated Evidence omitted'})
    class BoundedOutput:
        def __init__(self, stream): self.stream, self.count = stream, 0
        def write(self, data):
            if self.count + len(data) > maximum:
                raise ValueError('BLOCKED: complete Evidence exceeds 2GiB limit; no truncation approved')
            n = self.stream.write(data); self.count += n; return n
        def flush(self): self.stream.flush()
    with archive.open('xb') as stream:
        bounded = BoundedOutput(stream)
        with tarfile.open(fileobj=bounded, mode='w|gz') as tar:
            seen = {}
            for file in sorted(output.rglob('*')):
                if file.is_symlink(): raise ValueError('BLOCKED: Evidence symlink')
                if file.is_file():
                    name = file.relative_to(output).as_posix()
                    if name in excluded: continue
                    key = (file.stat().st_size, digest(file))
                    if key in seen:
                        info = tar.gettarinfo(str(file), arcname=name)
                        info.type = tarfile.LNKTYPE; info.linkname = seen[key]; info.size = 0
                        tar.addfile(info)
                    else:
                        tar.add(file, arcname=name, recursive=False); seen[key] = name
    write_json(destination / 'ASSET-MANIFEST.json',
               {'status': 'PACKED_NOT_PUBLISHED', 'files': [{'name': archive.name,
                'size': archive.stat().st_size, 'sha256': digest(archive)}],
                'classification': 'UNQUALIFIED_CI_EVIDENCE_NOT_COMMERCIAL_RELEASE'})


def publish_evidence(lock, destination):
    # Called only by the separately approved workflow publication step.
    if lock['artifact_policy'].get('storage_mode') != 'PUBLIC_GITHUB_RELEASE':
        raise ValueError('BLOCKED: publication mode not reviewed')
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    if repository != lock['publication']['repository']:
        raise ValueError('BLOCKED: publication repository differs')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    if event['repository']['private'] or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise ValueError('BLOCKED: publication requires public manual run')
    asset_manifest = json.loads((destination / 'ASSET-MANIFEST.json').read_text())
    for item in asset_manifest['files']:
        asset = confined(destination, item['name'])
        if asset.stat().st_size != item['size'] or digest(asset) != item['sha256']:
            raise ValueError('BLOCKED: transferred asset hash differs; no Release created')
    token = os.environ['GITHUB_TOKEN']
    def api(url, value=None):
        request = urllib.request.Request(url, data=json.dumps(value).encode() if value is not None else None,
                    headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                             'Content-Type': 'application/json', 'User-Agent': 'EF-Softworks-CI'})
        with urllib.request.urlopen(request, timeout=120) as response: return json.load(response)
    base = 'https://api.github.com/repos/' + repository
    repo = api(base)
    if repo.get('private') is not False or repo.get('full_name') != repository:
        raise ValueError('BLOCKED: Release destination is not exact public repository')
    tag = 'ci-evidence-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    try:
        api(base + '/releases/tags/' + tag)
    except urllib.error.HTTPError as error:
        if error.code != 404: raise
    else:
        raise ValueError('BLOCKED: release already exists; no overwrite or retry')
    release = api(base + '/releases', {'tag_name': tag, 'target_commitish': os.environ['GITHUB_SHA'],
                  'name': tag + ' — unqualified build evidence', 'prerelease': True,
                  'body': 'CI evidence only. Not approved for SimMedia commercial adoption. Complete Source, patches, notices and build information are included. Keep for at least three years and throughout downstream binary distribution.'})
    if not release['upload_url'].startswith('https://uploads.github.com/repos/' + repository + '/releases/'):
        raise ValueError('BLOCKED: unexpected authenticated upload host')
    manifest = json.loads((destination / 'ASSET-MANIFEST.json').read_text())
    rows = manifest['files'] + [{'name': 'ASSET-MANIFEST.json', 'size': (destination / 'ASSET-MANIFEST.json').stat().st_size,
                                'sha256': digest(destination / 'ASSET-MANIFEST.json')}]
    receipts = []
    for item in rows:
        file = confined(destination, item['name'])
        if digest(file) != item['sha256'] or file.stat().st_size != item['size']:
            raise ValueError('BLOCKED: publish asset differs')
        request = urllib.request.Request(release['upload_url'].split('{')[0] + '?name=' + item['name'],
                  data=file.read_bytes(), headers={'Authorization': 'Bearer ' + token,
                  'Content-Type': 'application/octet-stream', 'User-Agent': 'EF-Softworks-CI'}, method='POST')
        with urllib.request.urlopen(request, timeout=600) as response: result = json.load(response)
        if result['size'] != item['size']: raise ValueError('BLOCKED: uploaded asset size differs')
        h = hashlib.sha256(); count = 0
        # Public readback carries no token to any redirected asset host.
        with urllib.request.urlopen(result['browser_download_url'], timeout=120) as response:
            for data in iter(lambda: response.read(1024 * 1024), b''): h.update(data); count += len(data)
        if count != item['size'] or h.hexdigest() != item['sha256']:
            raise ValueError('BLOCKED: public asset readback hash differs')
        receipts.append({'url': result['browser_download_url'], **item})
    write_json(destination / 'PUBLICATION-RECEIPT.json', {'status': 'PUBLIC_EVIDENCE_HASH_VERIFIED',
               'url': release['html_url'], 'assets': receipts, 'commercial_adoption': 'NOT_APPROVED'})
    print(json.dumps({'evidence_url': release['html_url'], 'assets': receipts}))


def handoff_execution_gate(lock):
    policy = lock['handoff_policy']
    budget = policy.get('billing_evidence', {})
    if policy.get('paid_usage_blocked') is not True or budget.get('amount_usd') != 0 or budget.get('status') != 'Usage blocked' or budget.get('product') != 'Actions':
        raise ValueError('BLOCKED: zero-paid Actions stop evidence absent')
    if budget.get('account') != lock['publication']['repository'].split('/')[0]:
        raise ValueError('BLOCKED: budget evidence belongs to another account')
    if policy['maximum_total_bytes'] > 128 * 1024 * 1024 or policy['retention_days'] != 1:
        raise ValueError('BLOCKED: handoff exceeds reviewed limit')
    # Availability is not certified. GitHub may refuse execution/storage.
    # The account's reported active zero-dollar stop is the no-paid-use gate.
    # Failure is never permission to raise budgets, bypass limits, or retry.
    if policy.get('free_capacity_confirmed_bytes', 0) < policy['maximum_total_bytes'] and policy.get('unknown_capacity_policy') != 'SINGLE_ATTEMPT_PROVIDER_ENFORCED_ZERO_PAID_STOP':
        raise ValueError('BLOCKED: unconfirmed free capacity without reviewed stop policy')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['gate', 'build', 'pack', 'publish', 'restore'])
    p.add_argument('--lock', required=True)
    p.add_argument('--root', required=True)
    p.add_argument('--output')
    a = p.parse_args()
    lock = json.loads(Path(a.lock).read_text())
    root = Path(a.root).resolve(strict=True)
    validate(lock, root, os.environ.get('ImageVersion'))
    if a.mode == 'pack':
        pack_evidence(lock, Path(a.output), root / 'handoff-assets', transfer=True)
        return
    if a.mode == 'restore':
        restore_handoff(lock, root, root / 'handoff-assets')
        return
    if a.mode == 'publish':
        publish_evidence(lock, root / 'release-assets')
        return
    if a.mode == 'gate':
        handoff_execution_gate(lock)
        print(lock['container_image'])
        return
    if lock['artifact_policy'].get('storage_mode') != 'PUBLIC_GITHUB_RELEASE' and lock['artifact_policy']['free_capacity_confirmed_bytes'] < lock['artifact_policy']['maximum_bytes']:
        raise ValueError('BLOCKED: free Artifact storage not confirmed; build not started')
    handoff_execution_gate(lock)
    output = Path(a.output)
    output.mkdir(exist_ok=False)
    write_json(output / 'lock.json', lock)
    try:
        execute(lock, root, output, 'prepare')
        generated = json.loads((output / 'active-graph.json').read_text())
        if generated != lock['graph']:
            raise ValueError('BLOCKED: configured dependency graph differs')
        execute(lock, root, output, 'compile')
        execute(lock, root, output, 'qualify')
        required = ['patch-receipts.json', 'source-revisions.json', 'link-inventory.json',
                    'license-inventory.json', 'configure-records.json', 'toolchain-records.json',
                    'dll-static-analysis.json', 'binary/libmpv-2.dll', 'reproduce.txt',
                    'rust-actually-compiled.json', 'rust-unused-candidates.json']
        for rel in required:
            path = confined(output, rel)
            if not path.is_file() or path.stat().st_size == 0:
                raise ValueError('BLOCKED: missing evidence ' + rel)
        for rel in ['link-inventory.json', 'dll-static-analysis.json']:
            receipt = json.loads((output / rel).read_text())
            if receipt.get('status') != 'PASS' or receipt.get('prohibited_components') != []:
                raise ValueError('BLOCKED: binary/link qualification incomplete')
        write_json(output / 'SHA256.json', {str(f.relative_to(output)): digest(f)
                   for f in output.rglob('*') if f.is_file()})
        write_json(output / 'RESULTS.json', {'status': 'BUILD_EVIDENCE_COMPLETE',
                   'commercial_adoption': 'NOT_APPROVED', 'windows_runtime': 'NOT_TESTED'})
    except Exception as e:
        write_json(output / 'RESULTS.json', {'status': 'FAILED_OR_BLOCKED', 'reason': str(e)})
        raise
    finally:
        errors = []
        operations = [lambda: save_corresponding_inputs(lock, root, output),
                      lambda: save_final_source_state(lock, root, output) if (root / 'sources').is_dir() else None,
                      lambda: preserve_failure_evidence(root, output)]
        for operation in operations:
            try:
                operation()
            except Exception as error:
                errors.append(str(error))
        write_json(output / 'EVIDENCE-FINALIZATION.json', {'status': 'BLOCKED' if errors else 'PASS', 'errors': errors})
        if lock['artifact_policy'].get('storage_mode') != 'PUBLIC_GITHUB_RELEASE':
            artifact_capacity(lock, output)
        if errors:
            raise ValueError('BLOCKED: evidence finalization incomplete: ' + '; '.join(errors))

if __name__ == '__main__':
    main()
