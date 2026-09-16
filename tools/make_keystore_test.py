#!/usr/bin/env python3
"""Регрессии для tools/make_keystore.py.

Проверяется два слоя:

- чистая логика (экранирование java .properties, выбор путей, отказ
  перезаписывать существующие секреты) — без запуска keytool;
- один сквозной прогон с настоящим keytool из JDK, если он доступен:
  созданный keystore и key.properties должны проходить проверку подписи
  из apk_builder.validate_release_signing.

Временные проекты создаются внутри каталога проекта и удаляются.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent
MAKE_KEYSTORE = TOOLS_DIR / "make_keystore.py"
APK_BUILDER = TOOLS_DIR / "apk_builder.py"
TEST_TMP_PARENT = str(PROJECT_ROOT)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


make_keystore = _load("make_keystore_module", MAKE_KEYSTORE)
apk_builder = _load("apk_builder_module_for_keystore", APK_BUILDER)


def _fake_project(directory: Path) -> Path:
    (directory / "android" / "app").mkdir(parents=True)
    (directory / "pubspec.yaml").write_text(
        "name: ai_workbench\nversion: 1.0.0+1\n", encoding="utf-8"
    )
    return directory


class PropertyEscapingTest(unittest.TestCase):
    def _round_trip(self, values: dict[str, str]) -> dict[str, str]:
        text = make_keystore.render_key_properties(
            store_password=values["storePassword"],
            key_password=values["keyPassword"],
            key_alias=values["keyAlias"],
            store_file=values["storeFile"],
        )
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            path = Path(tmp) / "key.properties"
            path.write_text(text, encoding="latin-1", newline="\n")
            return apk_builder.load_java_properties(path)

    def test_plain_values_round_trip(self) -> None:
        values = {
            "storePassword": "abcDEF123",
            "keyPassword": "abcDEF123",
            "keyAlias": "upload",
            "storeFile": "upload-keystore.jks",
        }
        self.assertEqual(self._round_trip(values), values)

    def test_windows_path_and_separators_round_trip(self) -> None:
        values = {
            "storePassword": "pa:ss=word#1!",
            "keyPassword": "pa:ss=word#1!",
            "keyAlias": "upload key",
            "storeFile": "C:\\Users\\me\\keys\\upload.jks",
        }
        self.assertEqual(self._round_trip(values), values)

    def test_non_latin1_path_round_trip(self) -> None:
        values = {
            "storePassword": "abc123",
            "keyPassword": "abc123",
            "keyAlias": "upload",
            "storeFile": "C:\\Пользователи\\ключ.jks",
        }
        self.assertEqual(self._round_trip(values), values)

    def test_generated_password_needs_no_escaping(self) -> None:
        password = make_keystore.generate_password()
        self.assertGreaterEqual(len(password), 20)
        self.assertTrue(password.isalnum())
        self.assertEqual(make_keystore.escape_property_value(password), password)


class KeystorePathTest(unittest.TestCase):
    def test_default_path_is_inside_android_app(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = _fake_project(Path(tmp))
            path, store_file = make_keystore.resolve_keystore_path(root, None)
            self.assertEqual(store_file, make_keystore.DEFAULT_KEYSTORE_NAME)
            self.assertEqual(path.parent, root / "android" / "app")

    def test_absolute_path_is_kept_verbatim(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = _fake_project(Path(tmp))
            absolute = Path(tmp) / "outside" / "my.jks"
            path, store_file = make_keystore.resolve_keystore_path(root, str(absolute))
            self.assertEqual(path, absolute)
            self.assertEqual(store_file, str(absolute))

    def test_relative_path_resolves_against_android_app(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = _fake_project(Path(tmp))
            path, store_file = make_keystore.resolve_keystore_path(root, "keys/my.jks")
            self.assertEqual(store_file, "keys/my.jks")
            self.assertEqual(path, (root / "android" / "app" / "keys" / "my.jks").resolve())


class CliGuardTest(unittest.TestCase):
    def _run_cli(self, root: Path, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(MAKE_KEYSTORE), "--project-root", str(root), *arguments],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    def test_dry_run_creates_nothing(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = _fake_project(Path(tmp))
            result = self._run_cli(root, "--dry-run")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Dry-run", result.stdout)
            self.assertFalse((root / "android" / "key.properties").exists())
            self.assertFalse(
                (root / "android" / "app" / make_keystore.DEFAULT_KEYSTORE_NAME).exists()
            )

    def test_existing_key_properties_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = _fake_project(Path(tmp))
            properties = root / "android" / "key.properties"
            properties.write_text("storePassword=keep-me\n", encoding="utf-8")
            result = self._run_cli(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(properties.read_text(encoding="utf-8"), "storePassword=keep-me\n")

    def test_orphan_keystore_stops_with_clear_error(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = _fake_project(Path(tmp))
            keystore = root / "android" / "app" / make_keystore.DEFAULT_KEYSTORE_NAME
            keystore.write_bytes(b"NOT-A-REAL-KEYSTORE")
            result = self._run_cli(root)
            self.assertEqual(result.returncode, 2)
            self.assertIn("keystore", (result.stdout + result.stderr).lower())
            self.assertEqual(keystore.read_bytes(), b"NOT-A-REAL-KEYSTORE")

    def test_missing_project_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            result = self._run_cli(Path(tmp))
            self.assertEqual(result.returncode, 2)
            self.assertIn("pubspec.yaml", result.stdout + result.stderr)


@unittest.skipUnless(shutil.which("keytool"), "keytool из JDK недоступен")
class RealKeytoolTest(unittest.TestCase):
    def test_generated_signing_passes_builder_validation(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = _fake_project(Path(tmp))
            result = subprocess.run(
                [sys.executable, str(MAKE_KEYSTORE), "--project-root", str(root)],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            properties = root / "android" / "key.properties"
            keystore = root / "android" / "app" / make_keystore.DEFAULT_KEYSTORE_NAME
            self.assertTrue(properties.is_file())
            self.assertTrue(keystore.is_file())
            values = apk_builder.load_java_properties(properties)
            self.assertEqual(values["keyAlias"], make_keystore.DEFAULT_ALIAS)
            self.assertEqual(values["storeFile"], make_keystore.DEFAULT_KEYSTORE_NAME)
            self.assertEqual(values["storePassword"], values["keyPassword"])
            self.assertNotIn(values["storePassword"], result.stdout + result.stderr)
            # Главная проверка: сборщик считает подпись корректной.
            apk_builder.validate_release_signing(root)
            if os.name != "nt":
                self.assertEqual(properties.stat().st_mode & 0o777, 0o600)

    def test_password_from_environment_is_used(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TMP_PARENT) as tmp:
            root = _fake_project(Path(tmp))
            environment = dict(os.environ, AI_WB_TEST_PASSWORD="test-only-password-1")
            result = subprocess.run(
                [
                    sys.executable,
                    str(MAKE_KEYSTORE),
                    "--project-root",
                    str(root),
                    "--password-env",
                    "AI_WB_TEST_PASSWORD",
                ],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            values = apk_builder.load_java_properties(root / "android" / "key.properties")
            self.assertEqual(values["storePassword"], "test-only-password-1")
            self.assertNotIn("test-only-password-1", result.stdout + result.stderr)
            apk_builder.validate_release_signing(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
