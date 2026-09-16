#!/usr/bin/env python3
"""Regression tests for tools/apk_builder.py.

Two styles are used:

- Unit tests import the module directly (importlib) to exercise pure logic
  (Java .properties parsing, output-dir containment, derive_dart) without
  spawning subprocesses -- this is what makes the Windows dart.bat sibling
  selection testable on any host OS via os.name monkeypatching.
- Integration tests spawn the real CLI against a fake Flutter/Dart
  toolchain (clearly-labelled fakes -- never a real SDK, network, or
  upload) to exercise the end-to-end flow: progress output, gating,
  artifact publication, and failure handling.

Temporary test projects stay inside the project directory and are cleaned up.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile

TOOLS_DIR = Path(__file__).resolve().parent
BUILDER = TOOLS_DIR.with_name(TOOLS_DIR.name) / 'apk_builder.py'
PROJECT_ROOT = TOOLS_DIR.parent
# Keep fixtures local so tests don't rely on a shared temporary directory.
TEST_TMP_PARENT = str(PROJECT_ROOT)

_spec = importlib.util.spec_from_file_location('apk_builder_module', BUILDER)
apk_builder = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(apk_builder)


def _write_fake_apk(path: Path, *, manifest: bytes = b'FAKE-NOT-A-REAL-MANIFEST', dex: bytes = b'FAKE-NOT-REAL-DEX-BYTECODE') -> None:
    """A minimal, clearly-fake structural APK: real ZIP, fake Android bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('AndroidManifest.xml', manifest)
        archive.writestr('classes.dex', dex)
        archive.writestr('resources.arsc', b'FAKE-NOT-REAL-RESOURCES')


# --------------------------------------------------------------------------
# Pure-logic unit tests (no subprocess, OS-independent)
# --------------------------------------------------------------------------


class JavaPropertiesParsingTest(unittest.TestCase):
    def _load(self, text: str) -> dict:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            path = Path(tmp) / 'key.properties'
            path.write_bytes(text.encode('utf-8'))
            return apk_builder.load_java_properties(path)

    def test_plain_equals_and_colon_separators(self) -> None:
        values = self._load('alpha=one\nbeta:two\n')
        self.assertEqual(values, {'alpha': 'one', 'beta': 'two'})

    def test_whitespace_separator(self) -> None:
        values = self._load('alpha one\n')
        self.assertEqual(values, {'alpha': 'one'})

    def test_escaped_separator_and_space_in_key(self) -> None:
        values = self._load(r'store\:path\ file=C\:\\keys\\upload.jks' + '\n')
        self.assertEqual(values, {'store:path file': 'C:\\keys\\upload.jks'})

    def test_line_continuation(self) -> None:
        values = self._load('longValue=abc\\\n   def\n')
        self.assertEqual(values, {'longValue': 'abcdef'})

    def test_unicode_escape(self) -> None:
        values = self._load(r'alias=caf\u00e9' + '\n')
        self.assertEqual(values, {'alias': 'caf\u00e9'})

    def test_comment_lines_ignored(self) -> None:
        values = self._load('# comment\n! also comment\nkey=value\n')
        self.assertEqual(values, {'key': 'value'})

    def test_rejects_unsupported_escape(self) -> None:
        with self.assertRaises(apk_builder.BuildFailure):
            self._load('key=bad\\qvalue\n')

    def test_rejects_malformed_unicode_escape(self) -> None:
        with self.assertRaises(apk_builder.BuildFailure):
            self._load('key=bad\\u12zzvalue\n')

    def test_rejects_dangling_backslash(self) -> None:
        with self.assertRaises(apk_builder.BuildFailure):
            self._load('key=value\\')

    def test_rejects_unterminated_continuation(self) -> None:
        with self.assertRaises(apk_builder.BuildFailure):
            self._load('key=value\\')


class SafeOutputDirectoryTest(unittest.TestCase):
    def test_default_dist_allowed(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            resolved = apk_builder.safe_output_directory(root, 'dist')
            self.assertEqual(resolved, (root / 'dist').resolve())

    def test_nested_dist_allowed(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            resolved = apk_builder.safe_output_directory(root, 'dist/nested/out')
            self.assertEqual(resolved, (root / 'dist' / 'nested' / 'out').resolve())

    def test_absolute_path_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            with self.assertRaises(apk_builder.BuildFailure):
                apk_builder.safe_output_directory(root, '/etc')

    def test_dotdot_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            with self.assertRaises(apk_builder.BuildFailure):
                apk_builder.safe_output_directory(root, '../escape')

    def test_symlink_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp) / 'project'
            outside = Path(tmp) / 'outside'
            root.mkdir()
            outside.mkdir()
            try:
                (root / 'dist').symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f'symlinks unsupported on this filesystem: {error}')
            with self.assertRaises(apk_builder.BuildFailure):
                apk_builder.safe_output_directory(root, 'dist')

    def test_collision_with_protected_dir_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            for name in ('android', 'lib', 'test', 'tools', 'build'):
                with self.assertRaises(apk_builder.BuildFailure):
                    apk_builder.safe_output_directory(root, name)

    def test_collision_with_nested_protected_dir_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            with self.assertRaises(apk_builder.BuildFailure):
                apk_builder.safe_output_directory(root, 'android/app')

    def test_root_itself_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            with self.assertRaises(apk_builder.BuildFailure):
                apk_builder.safe_output_directory(root, '.')


class DeriveDartTest(unittest.TestCase):
    def test_posix_sibling_plain_dart(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            bin_dir = Path(tmp)
            flutter = bin_dir / 'flutter'
            dart = bin_dir / 'dart'
            flutter.write_text('#!/bin/sh\n')
            dart.write_text('#!/bin/sh\n')
            original_name = apk_builder.os.name
            apk_builder.os.name = 'posix'
            try:
                result = apk_builder.derive_dart(str(flutter), None, dry_run=True)
            finally:
                apk_builder.os.name = original_name
            self.assertEqual(Path(result), dart)

    def test_windows_prefers_dart_bat_sibling(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            bin_dir = Path(tmp)
            flutter_bat = bin_dir / 'flutter.bat'
            dart_bat = bin_dir / 'dart.bat'
            dart_exe = bin_dir / 'dart.exe'
            flutter_bat.write_text('rem fake\n')
            dart_bat.write_text('rem fake\n')
            dart_exe.write_text('fake\n')
            result = apk_builder.derive_dart(str(flutter_bat), None, dry_run=True, windows=True)
            self.assertEqual(Path(result), dart_bat)

    def test_windows_falls_back_to_dart_exe_when_no_bat(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            bin_dir = Path(tmp)
            flutter_bat = bin_dir / 'flutter.bat'
            dart_exe = bin_dir / 'dart.exe'
            flutter_bat.write_text('rem fake\n')
            dart_exe.write_text('fake\n')
            result = apk_builder.derive_dart(str(flutter_bat), None, dry_run=True, windows=True)
            self.assertEqual(Path(result), dart_exe)

    def test_explicit_dart_bin_overrides_sibling_search(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            bin_dir = Path(tmp)
            flutter = bin_dir / 'flutter'
            dart = bin_dir / 'dart'
            custom = bin_dir / 'custom_dart'
            flutter.write_text('#!/bin/sh\n')
            dart.write_text('#!/bin/sh\n')
            custom.write_text('#!/bin/sh\n')
            result = apk_builder.derive_dart(str(flutter), str(custom), dry_run=True)
            self.assertEqual(Path(result), custom)


class LaunchArgvTest(unittest.TestCase):
    def test_posix_passthrough(self) -> None:
        original_name = apk_builder.os.name
        apk_builder.os.name = 'posix'
        try:
            argv = apk_builder.build_launch_argv(['flutter', '--version'])
        finally:
            apk_builder.os.name = original_name
        self.assertEqual(argv, ['flutter', '--version'])

    def test_windows_bat_wrapped_with_comspec(self) -> None:
        original_name = apk_builder.os.name
        apk_builder.os.name = 'nt'
        try:
            argv = apk_builder.build_launch_argv(['C:/flutter/bin/flutter.bat', 'pub', 'get'])
        finally:
            apk_builder.os.name = original_name
        self.assertIsInstance(argv, str)
        self.assertIn(' /d /v:off /s /c ""C:/flutter/bin/flutter.bat" "pub" "get""', argv)


class ProjectLockTest(unittest.TestCase):
    def test_lock_blocks_second_acquire(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            first = apk_builder.ProjectLock(root)
            first.acquire()
            try:
                second = apk_builder.ProjectLock(root)
                with self.assertRaises(apk_builder.BuildFailure):
                    second.acquire()
            finally:
                first.release()
            self.assertFalse((root / '.apk_builder.lock').exists())

    def test_lock_released_and_reusable(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            lock = apk_builder.ProjectLock(root)
            lock.acquire()
            lock.release()
            lock.acquire()
            lock.release()


# --------------------------------------------------------------------------
# Integration tests: real CLI, fake toolchain
# --------------------------------------------------------------------------


@unittest.skipIf(os.name == 'nt', 'fake executable fixtures are POSIX-only (shebang scripts)')
class ApkBuilderIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT)
        self.root = Path(self.temp.name)
        (self.root / 'lib').mkdir()
        (self.root / 'test').mkdir()
        (self.root / 'tools').mkdir()
        (self.root / 'android').mkdir()
        (self.root / 'android' / 'app').mkdir()
        (self.root / 'pubspec.yaml').write_text(
            'name: demo\nversion: 1.0.0+1\n',
            encoding='utf-8',
        )
        (self.root / 'tools' / 'verify_fixes.py').write_text(
            'print("verifier ok")\n',
            encoding='utf-8',
        )
        self.built_apk_path = 'build/app/outputs/flutter-apk'
        self.flutter = self._write_fake_flutter('fake_flutter.py')
        self.dart = self._write_fake_dart('fake_dart.py')

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fake_flutter(self, name: str, *, build_behavior: str = 'write_valid_apk') -> Path:
        # `build_behavior` selects what `flutter build apk` does, to exercise
        # the structural-integrity and stale-artifact guards without a real
        # Android toolchain. This is a fake fixture, clearly labelled, never
        # a real Flutter SDK.
        script = self.root / name
        script.write_text(
            textwrap.dedent(
                f'''\
                #!{sys.executable}
                import json
                from pathlib import Path
                import sys
                import zipfile

                args = sys.argv[1:]
                if args == ['--version', '--machine']:
                    print(json.dumps({{'frameworkVersion': '3.41.0'}}))
                elif args[:2] == ['build', 'apk']:
                    mode = 'release' if '--release' in args else 'debug'
                    output = Path.cwd() / '{self.built_apk_path}' / f'app-{{mode}}.apk'
                    output.parent.mkdir(parents=True, exist_ok=True)
                    behavior = {build_behavior!r}
                    if behavior == 'write_valid_apk':
                        with zipfile.ZipFile(output, 'w') as archive:
                            archive.writestr('AndroidManifest.xml', b'FAKE-NOT-A-REAL-MANIFEST')
                            archive.writestr('classes.dex', b'FAKE-NOT-REAL-DEX-BYTECODE')
                    elif behavior == 'write_corrupt':
                        output.write_bytes(b'not-a-zip-file-at-all')
                    elif behavior == 'write_nothing':
                        pass
                sys.exit(0)
                ''',
            ),
            encoding='utf-8',
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        return script

    def _write_fake_dart(self, name: str) -> Path:
        script = self.root / name
        script.write_text(f'#!{sys.executable}\nraise SystemExit(0)\n', encoding='utf-8')
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        return script

    def run_builder(self, *arguments: str, flutter: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(BUILDER),
                '--project-root',
                str(self.root),
                '--flutter-bin',
                str(flutter or self.flutter),
                '--dart-bin',
                str(self.dart),
                *arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    # -- original behaviours, preserved -----------------------------------

    def test_debug_build_creates_apk_and_report_without_github(self) -> None:
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = self.root / 'dist' / 'demo-1.0.0+1-debug.apk'
        report_path = self.root / 'dist' / 'build-report-debug.json'
        with zipfile.ZipFile(artifact) as archive:
            self.assertIn('AndroidManifest.xml', archive.namelist())
            self.assertIn('classes.dex', archive.namelist())
        report = json.loads(report_path.read_text(encoding='utf-8'))
        self.assertEqual(report['status'], 'success')
        self.assertFalse(report['githubUsed'])
        self.assertFalse(report['sourceUpload'])
        self.assertEqual(report['artifact']['bytes'], artifact.stat().st_size)
        self.assertEqual(report['skippedChecks'], [])
        self.assertFalse((self.root / '.apk_builder.lock').exists())

    def test_release_fails_closed_without_signing_configuration(self) -> None:
        result = self.run_builder('--mode', 'release')
        self.assertEqual(result.returncode, 2)
        self.assertIn('android/key.properties', result.stderr)
        self.assertFalse((self.root / 'dist').exists())

    def test_dry_run_needs_no_sdk_and_writes_nothing(self) -> None:
        result = subprocess.run(
            [sys.executable, str(BUILDER), '--project-root', str(self.root), '--dry-run'],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Dry-run завершён', result.stdout)
        self.assertFalse((self.root / 'dist').exists())
        self.assertFalse((self.root / '.apk_builder.lock').exists())

    # -- progress / numbered steps -----------------------------------------

    def test_progress_shows_numbered_russian_steps_and_elapsed_time(self) -> None:
        result = self.run_builder('--skip-tests')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('[1/6] Проверка версии Flutter', result.stdout)
        self.assertIn('[6/6] Сборка APK', result.stdout)
        self.assertIn('Готово за', result.stdout)
        self.assertNotIn('%', result.stdout)
        report = json.loads((self.root / 'dist' / 'build-report-debug.json').read_text(encoding='utf-8'))
        self.assertEqual(report['skippedChecks'], ['test'])

    # -- skip-format must not resolve dart ----------------------------------

    def test_skip_format_does_not_require_or_resolve_dart(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(BUILDER),
                '--project-root',
                str(self.root),
                '--flutter-bin',
                str(self.flutter),
                '--skip-format',
                '--skip-analyze',
                '--skip-tests',
                '--skip-verifier',
            ],
            text=True,
            capture_output=True,
            check=False,
            env={},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('dart', result.stdout.lower().split('\n')[0])

    # -- structural APK integrity --------------------------------------------

    def test_corrupt_apk_output_is_rejected(self) -> None:
        flutter = self._write_fake_flutter('fake_flutter_corrupt.py', build_behavior='write_corrupt')
        result = self.run_builder(flutter=flutter)
        self.assertEqual(result.returncode, 2)
        self.assertIn('повреждён', result.stderr)
        self.assertFalse((self.root / 'dist').exists())

    # -- stale artifact guard ------------------------------------------------

    def test_stale_build_output_is_not_republished(self) -> None:
        built = self.root / self.built_apk_path / 'app-debug.apk'
        _write_fake_apk(built, manifest=b'STALE-MANIFEST', dex=b'STALE-DEX')
        stale_bytes = built.read_bytes()
        flutter = self._write_fake_flutter('fake_flutter_nooutput.py', build_behavior='write_nothing')
        result = self.run_builder(flutter=flutter)
        self.assertEqual(result.returncode, 2)
        self.assertIn('не создал ожидаемый файл', result.stderr)
        self.assertFalse((self.root / 'dist').exists())
        # The stale build/ output itself must have been discarded up front,
        # not silently left in place for a later run to accidentally publish.
        self.assertFalse(built.exists())
        self.assertNotEqual(stale_bytes, b'')  # sanity: fixture actually wrote bytes

    def test_stale_dist_artifact_preserved_on_gate_failure(self) -> None:
        # A previously published dist/ artifact must survive an unrelated
        # gate failure (e.g. missing release signing) untouched.
        dist_dir = self.root / 'dist'
        dist_dir.mkdir()
        existing = dist_dir / 'demo-1.0.0+1-release.apk'
        existing.write_bytes(b'PREVIOUSLY-PUBLISHED-REAL-BUILD')
        result = self.run_builder('--mode', 'release')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(existing.read_bytes(), b'PREVIOUSLY-PUBLISHED-REAL-BUILD')

    # -- release signing: escaping and strict relative resolution -----------

    def test_release_signing_accepts_escaped_properties_and_relative_app_path(self) -> None:
        keystore_dir = self.root / 'android' / 'app' / 'keys'
        keystore_dir.mkdir(parents=True)
        keystore = keystore_dir / 'up load.jks'
        keystore.write_bytes(b'FAKE-NOT-A-REAL-KEYSTORE')
        properties = self.root / 'android' / 'key.properties'
        properties.write_text(
            'storePassword=pa\\:ss\\=word\n'
            'keyPassword=secret two\n'
            'keyAlias=upload\n'
            r'storeFile=keys/up\ load.jks' + '\n',
            encoding='utf-8',
        )
        result = self.run_builder('--mode', 'release')
        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = self.root / 'dist' / 'demo-1.0.0+1-release.apk'
        self.assertTrue(artifact.is_file())
        # Secrets must never be printed.
        self.assertNotIn('pa:ss=word', result.stdout)
        self.assertNotIn('secret two', result.stdout)
        self.assertNotIn(str(keystore), result.stdout)

    def test_release_signing_rejects_relative_storeFile_outside_android_app(self) -> None:
        # Old behaviour used to also probe cwd and android/ as fallbacks;
        # the fixed resolver must match Gradle's file() exactly and only
        # look under android/app.
        keystore = self.root / 'android' / 'upload.jks'  # NOT under android/app
        keystore.write_bytes(b'FAKE-NOT-A-REAL-KEYSTORE')
        properties = self.root / 'android' / 'key.properties'
        properties.write_text(
            'storePassword=pw\nkeyPassword=pw\nkeyAlias=upload\nstoreFile=upload.jks\n',
            encoding='utf-8',
        )
        result = self.run_builder('--mode', 'release')
        self.assertEqual(result.returncode, 2)
        self.assertIn('keystore', result.stderr.lower())
        self.assertNotIn(str(keystore), result.stdout)
        self.assertNotIn(str(keystore), result.stderr)

    def test_release_signing_rejects_malformed_properties_without_leaking_secrets(self) -> None:
        properties = self.root / 'android' / 'key.properties'
        properties.write_text(
            'storePassword=top\\qsecret\nkeyPassword=pw\nkeyAlias=upload\nstoreFile=upload.jks\n',
            encoding='utf-8',
        )
        result = self.run_builder('--mode', 'release')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('top', result.stdout)
        self.assertNotIn('secret', result.stdout)

    # -- output containment via the real CLI --------------------------------

    def test_output_dir_collision_with_source_dir_rejected_via_cli(self) -> None:
        result = self.run_builder('--dry-run', '--output-dir', 'android')
        self.assertEqual(result.returncode, 2)
        self.assertIn('служебным каталогом', result.stderr)

    def test_output_dir_symlink_escape_rejected_via_cli(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as outside:
            try:
                (self.root / 'dist').symlink_to(Path(outside), target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f'symlinks unsupported on this filesystem: {error}')
            result = self.run_builder('--dry-run')
            self.assertEqual(result.returncode, 2)
            self.assertIn('symlink', result.stderr)

    # -- concurrency guard ----------------------------------------------------

    def test_concurrent_build_is_rejected_by_lock(self) -> None:
        lock_path = self.root / '.apk_builder.lock'
        lock_path.write_text('999999999', encoding='utf-8')
        result = self.run_builder()
        self.assertEqual(result.returncode, 2)
        self.assertIn('уже выполняется', result.stderr)
        # The pre-existing lock file was not ours to clean up.
        self.assertTrue(lock_path.exists())
        lock_path.unlink()

    # -- timeout + process cleanup -------------------------------------------

    def test_timeout_stops_hanging_command(self) -> None:
        hanging = self.root / 'fake_flutter_hang.py'
        hanging.write_text(
            textwrap.dedent(
                f'''\
                #!{sys.executable}
                import json
                import sys
                import time

                args = sys.argv[1:]
                if args == ['--version', '--machine']:
                    print(json.dumps({{'frameworkVersion': '3.41.0'}}))
                    sys.exit(0)
                if args == ['pub', 'get']:
                    time.sleep(120)
                    sys.exit(0)
                sys.exit(0)
                ''',
            ),
            encoding='utf-8',
        )
        hanging.chmod(hanging.stat().st_mode | stat.S_IEXEC)
        result = self.run_builder(
            '--skip-format',
            '--skip-analyze',
            '--skip-tests',
            '--skip-verifier',
            '--timeout',
            '2',
            flutter=hanging,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn('таймаут', result.stderr)
        self.assertFalse((self.root / 'dist').exists())


class AdditionalRegressionTest(unittest.TestCase):
    def test_timeout_rejects_nonfinite_values(self):
        import argparse
        for value in ('nan', 'inf', '-inf', '0', '-1'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                apk_builder.positive_seconds(value)

    def test_windows_space_path_uses_outer_quotes(self):
        from unittest.mock import patch
        with patch.object(apk_builder.os, 'name', 'nt'):
            command = apk_builder.build_launch_argv(['C:/Program Files/flutter/bin/flutter.bat', '--version'])
        self.assertIn('/c ""C:/Program Files/flutter/bin/flutter.bat" "--version""', command)

    def test_windows_expansion_rejected(self):
        from unittest.mock import patch
        for path in ('C:/%TEMP%/flutter.bat', 'C:/a&b/flutter.bat', 'C:/a!b/flutter.bat'):
            with patch.object(apk_builder.os, 'name', 'nt'), self.assertRaises(apk_builder.BuildFailure):
                apk_builder.build_launch_argv([path, '--version'])

    def test_java_inputstream_uses_latin1(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            path = Path(tmp) / 'key.properties'
            path.write_bytes(b'alias=caf\xe9\n')
            self.assertEqual(apk_builder.load_java_properties(path)['alias'], 'caf\u00e9')

    def test_nested_dex_and_empty_manifest_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            path = Path(tmp) / 'bad.apk'
            for manifest, dex_name in ((b'valid', 'assets/classes.dex'), (b'', 'classes.dex')):
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr('AndroidManifest.xml', manifest)
                    archive.writestr(dex_name, b'fake-dex')
                with self.assertRaises(apk_builder.BuildFailure):
                    apk_builder.validate_apk_structure(path)

    def test_atomic_copy_preserves_existing_on_replace_failure(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            source, destination = root / 'source.apk', root / 'destination.apk'
            source.write_bytes(b'new')
            destination.write_bytes(b'old')
            with patch.object(apk_builder.os, 'replace', side_effect=OSError('test failure')):
                with self.assertRaises(OSError):
                    apk_builder.atomic_copy(source, destination)
            self.assertEqual(destination.read_bytes(), b'old')
            self.assertEqual(list(root.glob('*.tmp')), [])

    def test_sdk_output_redacts_signing_secrets(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            runner = apk_builder.Runner(Path(tmp), dry_run=False, timeout=10, total_steps=1, secrets=['test-secret-value'])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.run([sys.executable, '-c', "print('test-secret-value')"], 'test')
            self.assertNotIn('test-secret-value', output.getvalue())
            self.assertIn('[скрыто]', output.getvalue())

    def test_dry_run_never_spawns_or_creates_lock(self):
        from unittest.mock import patch
        import contextlib
        import io
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = Path(tmp)
            (root / 'pubspec.yaml').write_text('name: demo\nversion: 1.0.0+1\n')
            before = sorted(p.name for p in root.iterdir())
            with patch.object(apk_builder.subprocess, 'Popen', side_effect=AssertionError('spawned')), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(apk_builder.build(['--project-root', str(root), '--dry-run']), 0)
            self.assertEqual(before, sorted(p.name for p in root.iterdir()))



if __name__ == '__main__':
    unittest.main()
