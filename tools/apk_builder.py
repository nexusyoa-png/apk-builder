#!/usr/bin/env python3
"""Local, no-GitHub APK builder for AI Workbench.

The script never downloads an SDK, prints signing secrets, or uploads sources.
A local Flutter/Android toolchain is still required because compiling Flutter on
an Android phone would require bundling the Flutter SDK, Android SDK, JDK and
Gradle toolchain inside the app.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import tempfile
import threading
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from typing import Sequence

MIN_FLUTTER = (3, 41, 0)
DEFAULT_TIMEOUT_SECONDS = 1800.0

# Directories that hold project sources or Flutter/Gradle build output. The
# output directory must never be the same as, nor contain, nor be contained
# by any of these -- colliding would let the builder read/write files that
# are not build artifacts, or corrupt the input tree.
PROTECTED_RELATIVE_DIRS = ("android", "lib", "test", "tools", "build", ".git")

STEP_LABELS = {
    "flutter_version": "Проверка версии Flutter",
    "pub_get": "Установка зависимостей (flutter pub get)",
    "format": "Проверка форматирования (dart format)",
    "analyze": "Статический анализ (flutter analyze)",
    "test": "Тесты Flutter (flutter test)",
    "offline_verifier": "Офлайн-проверка (verify_fixes.py)",
    "build_apk": "Сборка APK (flutter build apk)",
}


class BuildFailure(RuntimeError):
    """A safe, user-facing build failure."""


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value.strip())
    if not match:
        raise BuildFailure(f"Не удалось определить версию Flutter: {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def read_project_identity(root: Path) -> tuple[str, str]:
    pubspec = root / "pubspec.yaml"
    if not pubspec.is_file():
        raise BuildFailure(f"Не найден pubspec.yaml: {root}")
    source = pubspec.read_text(encoding="utf-8")
    name = re.search(r"(?m)^name:\s*([^\s#]+)", source)
    version = re.search(r"(?m)^version:\s*([^\s#]+)", source)
    if not name or not version:
        raise BuildFailure("В pubspec.yaml отсутствуют name или version.")
    return name.group(1), version.group(1)


def resolve_executable(requested: str | None, fallback: str, *, dry_run: bool) -> str:
    value = requested or fallback
    expanded = Path(value).expanduser()
    if expanded.is_file():
        return str(expanded.resolve())
    found = shutil.which(value)
    if found:
        return found
    if dry_run:
        return value
    raise BuildFailure(
        f"Не найден {fallback}. Установите Flutter 3.41+ и добавьте его bin в PATH."
    )


def _dart_sibling_names(*, windows: bool) -> tuple[str, ...]:
    # The Flutter SDK ships bin/dart.bat (a launcher script) on Windows and a
    # plain bin/dart executable elsewhere. dart.exe is not part of a normal
    # Flutter SDK layout but is accepted defensively if present.
    if windows:
        return ("dart.bat", "dart.exe", "dart")
    return ("dart",)


def derive_dart(
    flutter: str,
    requested: str | None,
    *,
    dry_run: bool,
    windows: bool | None = None,
) -> str:
    if requested:
        return resolve_executable(requested, "dart", dry_run=dry_run)
    is_windows = (os.name == "nt") if windows is None else windows
    flutter_path = Path(flutter)
    if flutter_path.is_file():
        for name in _dart_sibling_names(windows=is_windows):
            sibling = flutter_path.parent / name
            if sibling.is_file():
                return str(sibling)
    return resolve_executable(None, "dart", dry_run=dry_run)


# --------------------------------------------------------------------------
# Java .properties parsing (java.util.Properties compatible subset)
# --------------------------------------------------------------------------

_UNICODE_HEX_RE = re.compile(r"^[0-9a-fA-F]{4}$")
_ESCAPE_MAP = {
    "t": "\t",
    "n": "\n",
    "r": "\r",
    "f": "\f",
    "\\": "\\",
    " ": " ",
    ":": ":",
    "=": "=",
    "#": "#",
    "!": "!",
}


def _ends_with_odd_backslashes(value: str) -> bool:
    count = 0
    index = len(value) - 1
    while index >= 0 and value[index] == "\\":
        count += 1
        index -= 1
    return count % 2 == 1


def _iter_logical_lines(text: str):
    physical = text.split("\n")
    physical = [line[:-1] if line.endswith("\r") else line for line in physical]
    total = len(physical)
    index = 0
    while index < total:
        line_no = index + 1
        stripped_lead = physical[index].lstrip(" \t\f")
        if not stripped_lead or stripped_lead[0] in "#!":
            index += 1
            continue
        logical = stripped_lead
        start_line_no = line_no
        while _ends_with_odd_backslashes(logical):
            index += 1
            if index >= total:
                raise BuildFailure(
                    "key.properties: незавершённое продолжение строки после "
                    f"строки {start_line_no}."
                )
            logical = logical[:-1] + physical[index].lstrip(" \t\f")
        yield start_line_no, logical
        index += 1


def _unescape(value: str, *, line_no: int) -> str:
    result: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch != "\\":
            result.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            raise BuildFailure(
                f"key.properties: висячий обратный слеш в строке {line_no}."
            )
        nxt = value[i + 1]
        if nxt == "u":
            hex_digits = value[i + 2 : i + 6]
            if len(hex_digits) != 4 or not _UNICODE_HEX_RE.match(hex_digits):
                raise BuildFailure(
                    f"key.properties: некорректный \\u escape в строке {line_no}."
                )
            code_point = int(hex_digits, 16)
            if 0xD800 <= code_point <= 0xDFFF:
                raise BuildFailure(
                    "key.properties: одиночный unicode-суррогат не поддерживается "
                    f"(строка {line_no})."
                )
            result.append(chr(code_point))
            i += 6
            continue
        mapped = _ESCAPE_MAP.get(nxt)
        if mapped is None:
            raise BuildFailure(
                "key.properties: неподдерживаемая escape-последовательность "
                f"в строке {line_no}."
            )
        result.append(mapped)
        i += 2
    return "".join(result)


def _split_key_value(logical: str, line_no: int) -> tuple[str, str]:
    i = 0
    n = len(logical)
    key_chars: list[str] = []
    while i < n:
        ch = logical[i]
        if ch == "\\":
            if i + 1 >= n:
                raise BuildFailure(
                    f"key.properties: висячий обратный слеш в ключе строки {line_no}."
                )
            key_chars.append(ch)
            key_chars.append(logical[i + 1])
            i += 2
            continue
        if ch in "=: \t\f":
            break
        key_chars.append(ch)
        i += 1
    while i < n and logical[i] in " \t\f":
        i += 1
    if i < n and logical[i] in "=:":
        i += 1
        while i < n and logical[i] in " \t\f":
            i += 1
    key = _unescape("".join(key_chars), line_no=line_no)
    value = _unescape(logical[i:], line_no=line_no)
    return key, value


def load_java_properties(path: Path) -> dict[str, str]:
    try:
        raw_bytes = path.read_bytes()
    except OSError as error:
        raise BuildFailure("Не удалось прочитать android/key.properties.") from error
    # Gradle uses Properties.load(InputStream), whose byte encoding is ISO-8859-1.
    # Non-Latin characters should use Java unicode escapes for portability.
    text = raw_bytes.decode("latin-1")
    values: dict[str, str] = {}
    for line_no, logical in _iter_logical_lines(text):
        key, value = _split_key_value(logical, line_no)
        if not key:
            raise BuildFailure(f"key.properties: пустой ключ в строке {line_no}.")
        values[key] = value
    return values


REQUIRED_SIGNING_KEYS = ("storePassword", "keyPassword", "keyAlias", "storeFile")


def validate_release_signing(root: Path) -> None:
    properties_path = root / "android" / "key.properties"
    if not properties_path.is_file():
        raise BuildFailure(
            "Для release нужен android/key.properties. Скопируйте "
            "android/key.properties.example и заполните локально."
        )
    values = load_java_properties(properties_path)
    missing = sorted(
        key
        for key in REQUIRED_SIGNING_KEYS
        if not values.get(key) or values[key] == "CHANGE_ME"
    )
    if missing:
        raise BuildFailure(
            "В android/key.properties не заполнены поля: " + ", ".join(missing)
        )
    # Mirrors android/app/build.gradle.kts: `storeFile = ... .let { file(it) }`
    # evaluated inside the android/app Gradle project. Gradle's file()
    # resolves relative paths strictly against that project directory and
    # never expands `~` or falls back to the process cwd or android/.
    configured = Path(values["storeFile"])
    if configured.is_absolute():
        keystore_path = configured
    else:
        keystore_path = root / "android" / "app" / configured
    if not keystore_path.is_file():
        raise BuildFailure(
            "Файл keystore из android/key.properties не найден. "
            "Секретный путь намеренно не печатается."
        )


# --------------------------------------------------------------------------
# Safe process launching, bounded command duration and process-group cleanup
# --------------------------------------------------------------------------


def build_launch_argv(command: Sequence[str]) -> list[str] | str:
    parts = [str(part) for part in command]
    if os.name == "nt" and parts and parts[0].lower().endswith((".bat", ".cmd")):
        # cmd has different quoting rules from MSVCRT. Pass an explicit command
        # string with an outer quote pair; reject expansion/control characters.
        if any(any(c in part for c in '\"%!?^&|<>\r\n\x00') for part in parts):
            raise BuildFailure("Путь к Windows SDK содержит неподдерживаемые спецсимволы. Переместите SDK в простой путь, например C:/flutter.")
        comspec = os.environ.get("ComSpec") or "cmd.exe"
        quoted = " ".join('"' + part + '"' for part in parts)
        return subprocess.list2cmdline([comspec]) + ' /d /v:off /s /c "' + quoted + '"'
    return parts


def _process_group_kwargs() -> dict:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _terminate_process_tree(process: "subprocess.Popen[str]") -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True, check=False, timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.kill()
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return
    # start_new_session makes the leader's PID the process-group ID. Keep it
    # even if the leader has already exited while descendants retain stdout.
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except OSError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    # A terminated leader doesn't imply that its children terminated too.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass


def count_total_steps(options: argparse.Namespace) -> int:
    total = 2  # flutter_version + build_apk always run
    total += 1  # pub_get always runs
    if not options.skip_format:
        total += 1
    if not options.skip_analyze:
        total += 1
    if not options.skip_tests:
        total += 1
    if not options.skip_verifier:
        total += 1
    return total


class Runner:
    def __init__(self, root: Path, *, dry_run: bool, timeout: float, total_steps: int, secrets: Sequence[str] = ()) -> None:
        self.root = root
        self.dry_run = dry_run
        self.timeout = timeout
        self.total = total_steps
        self.index = 0
        self.steps: list[str] = []
        self.durations: dict[str, float] = {}
        self.secrets = sorted({part for value in secrets for part in (value, *value.splitlines()) if part}, key=len, reverse=True)

    def redact(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, "[скрыто]")
        return text

    def run(self, command: Sequence[str], step: str, *, capture: bool = False) -> str:
        self.index += 1
        label = STEP_LABELS.get(step, step)
        print(f"\n[{self.index}/{self.total}] {label}", flush=True)
        print(self.redact("$ " + shlex.join(str(part) for part in command)), flush=True)
        if self.dry_run:
            print("(dry-run: команда не выполняется)", flush=True)
            return ""
        start = time.monotonic()
        try:
            process = subprocess.Popen(
                build_launch_argv(command), cwd=self.root, text=True,
                encoding="utf-8", errors="replace", stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, **_process_group_kwargs(),
            )
        except OSError as error:
            raise BuildFailure(self.redact(f"Не удалось запустить команду: {error}")) from error
        captured: list[str] = []
        capture_size = 0
        reader_errors: list[Exception] = []

        def read_output() -> None:
            nonlocal capture_size
            try:
                assert process.stdout is not None
                for line in process.stdout:
                    # Never emit raw subprocess output when signing is configured.
                    print(self.redact(line), end="", flush=True)
                    if capture and capture_size < 1048576:
                        piece = line[:1048576 - capture_size]
                        captured.append(piece)
                        capture_size += len(piece)
            except Exception as error:
                reader_errors.append(error)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            process.wait(timeout=self.timeout)
            remaining = max(0.0, self.timeout - (time.monotonic() - start))
            reader.join(timeout=remaining)
            if reader.is_alive():
                raise subprocess.TimeoutExpired(command, self.timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process)
            reader.join(timeout=5)
            raise BuildFailure(f"Шаг {step} превысил таймаут {self.timeout:g} c и был остановлен.") from None
        except BaseException:
            _terminate_process_tree(process)
            reader.join(timeout=5)
            raise
        finally:
            if not reader.is_alive() and process.stdout is not None:
                process.stdout.close()
        if reader_errors:
            raise BuildFailure("Не удалось прочитать вывод команды.")
        if process.returncode != 0:
            raise BuildFailure(f"Шаг {step} завершился с кодом {process.returncode}. APK не опубликован.")
        if capture and capture_size >= 1048576:
            raise BuildFailure("Слишком большой служебный ответ SDK.")
        elapsed = time.monotonic() - start
        self.steps.append(step)
        self.durations[step] = round(elapsed, 3)
        print(f"Готово за {elapsed:.1f} с", flush=True)
        return "".join(captured).strip() if capture else ""


# --------------------------------------------------------------------------
# Output containment, artifact hygiene and integrity
# --------------------------------------------------------------------------


def _is_within(path: Path, ancestor: Path) -> bool:
    try:
        path.relative_to(ancestor)
        return True
    except ValueError:
        return False


def safe_output_directory(root: Path, raw: str) -> Path:
    if not raw or not raw.strip():
        raise BuildFailure("Каталог результата не может быть пустым.")
    candidate = Path(raw)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise BuildFailure("Каталог результата должен находиться внутри проекта.")
    root_real = root.resolve()
    # resolve(strict=False) follows any existing symlink prefix, so a `dist`
    # that is (or contains) a symlink pointing outside the project is caught
    # by the containment check below rather than silently followed.
    resolved = (root_real / candidate).resolve()
    if not _is_within(resolved, root_real):
        raise BuildFailure(
            "Каталог результата выходит за пределы проекта (symlink или обход пути)."
        )
    if resolved == root_real:
        raise BuildFailure("Каталог результата не может совпадать с корнем проекта.")
    for name in PROTECTED_RELATIVE_DIRS:
        protected = (root_real / name).resolve()
        if resolved == protected or _is_within(resolved, protected) or _is_within(protected, resolved):
            raise BuildFailure(
                f"Каталог результата конфликтует со служебным каталогом '{name}'."
            )
    return resolved


def _silent_unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".apk-", suffix=".tmp", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as target, source.open("rb") as origin:
            shutil.copyfileobj(origin, target, length=1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
    finally:
        _silent_unlink(temporary)


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".report-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            target.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        _silent_unlink(temporary)


def discard_stale_build_output(built: Path) -> None:
    """Remove a pre-existing Flutter build output before invoking the build.

    Flutter/Gradle build outputs are disposable, regenerated artifacts (not
    project sources), so the safe guard against stale-APK reuse is simply to
    make sure nothing is present at that path before the build runs: a
    successful subprocess that produces no new file then correctly fails the
    subsequent existence check instead of letting an old file be published.
    """
    if not built.exists():
        return
    try:
        built.unlink()
    except OSError as error:
        raise BuildFailure(
            f"Не удалось удалить устаревший файл сборки {built.name}: {error}"
        ) from error


_DEX_RE = re.compile(r"^classes\d*\.dex$")


def validate_apk_structure(path: Path) -> None:
    """Structural-only sanity check: valid ZIP with the entries an APK needs.

    This does NOT verify the APK signature or its cryptographic validity --
    only that Flutter produced a well-formed archive with the files an APK
    must contain, catching truncated or corrupted build output.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 100000 or sum(i.file_size for i in entries) > 4 * 1024**3:
                raise BuildFailure("APK превышает лимит структурной проверки (4 ГБ / 100000 записей).")
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                raise BuildFailure("В APK обнаружены повторяющиеся имена файлов.")
            if archive.testzip() is not None:
                raise BuildFailure("APK повреждён: не совпадает CRC записи в архиве.")
            if "AndroidManifest.xml" not in names or archive.getinfo("AndroidManifest.xml").file_size == 0:
                raise BuildFailure("В APK отсутствует непустой AndroidManifest.xml (структурная проверка).")
            if not any(_DEX_RE.fullmatch(i.filename) and i.file_size > 0 for i in entries):
                raise BuildFailure("В APK отсутствуют непустые classes*.dex в корне (структурная проверка).")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise BuildFailure("Flutter создал повреждённый или неподдерживаемый APK ZIP.") from error


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Concurrency guard
# --------------------------------------------------------------------------


class ProjectLock:
    """Exclusive, project-local build lock.

    Uses O_CREAT|O_EXCL on a fixed path inside the project (not a predictable
    shared temp filename), which is atomic against races between concurrent
    builds of the same project.
    """

    def __init__(self, root: Path) -> None:
        self.path = root / ".apk_builder.lock"
        self._acquired = False

    def acquire(self) -> None:
        try:
            fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise BuildFailure(
                "Другая сборка уже выполняется в этом проекте "
                f"(lock-файл {self.path.name}). Дождитесь её завершения "
                "или удалите файл, если предыдущий процесс аварийно завершился."
            ) from None
        with os.fdopen(fd, "w") as handle:
            handle.write(str(os.getpid()))
        self._acquired = True

    def release(self) -> None:
        if self._acquired:
            _silent_unlink(self.path)
            self._acquired = False

    def __enter__(self) -> "ProjectLock":
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def positive_seconds(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("--timeout должен быть числом секунд") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("--timeout должен быть конечным положительным числом секунд")
    return parsed


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Локальная сборка APK без GitHub и загрузки исходников.",
    )
    parser.add_argument("--mode", choices=("debug", "release"), default="debug")
    parser.add_argument("--flutter-bin", help="Путь к flutter/flutter.bat")
    parser.add_argument("--dart-bin", help="Путь к dart/dart.bat/dart.exe")
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--skip-format", action="store_true")
    parser.add_argument("--skip-analyze", action="store_true")
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--skip-verifier", action="store_true")
    parser.add_argument(
        "--timeout",
        type=positive_seconds,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Таймаут на каждую команду в секундах (по умолчанию 1800).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Показать шаги без SDK, команд и изменения файлов.",
    )
    parser.add_argument(
        "--project-root",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def build(argv: Sequence[str]) -> int:
    options = parse_args(argv)
    default_root = Path(__file__).resolve().parents[1]
    root = Path(options.project_root).resolve() if options.project_root else default_root
    project_name, project_version = read_project_identity(root)
    output_dir = safe_output_directory(root, options.output_dir)
    flutter = resolve_executable(
        options.flutter_bin or os.environ.get("FLUTTER_BIN"),
        "flutter",
        dry_run=options.dry_run,
    )
    dart: str | None = None
    if not options.skip_format:
        dart = derive_dart(flutter, options.dart_bin, dry_run=options.dry_run)

    lock = ProjectLock(root) if not options.dry_run else None
    if lock is not None:
        lock.acquire()
    try:
        signing_secrets: list[str] = []
        if not options.dry_run:
            if options.mode == "release":
                validate_release_signing(root)
            signing_file = root / "android" / "key.properties"
            if signing_file.is_file():
                signing_values = load_java_properties(signing_file)
                signing_secrets.extend(signing_values.get(key, "") for key in REQUIRED_SIGNING_KEYS)
                configured = signing_values.get("storeFile", "")
                if configured:
                    secret_path = Path(configured)
                    if not secret_path.is_absolute():
                        secret_path = root / "android" / "app" / secret_path
                    signing_secrets.extend((str(secret_path), str(secret_path.resolve())))
        runner = Runner(
            root,
            dry_run=options.dry_run,
            timeout=options.timeout,
            total_steps=count_total_steps(options),
            secrets=signing_secrets,
        )

        print(f"AI Workbench APK Builder · {project_version} · {options.mode}")
        print("Исходники остаются на этом компьютере. GitHub не используется.")

        flutter_version = "dry-run"
        if options.dry_run:
            runner.run([flutter, "--version", "--machine"], "flutter_version")
        else:
            raw_version = runner.run(
                [flutter, "--version", "--machine"],
                "flutter_version",
                capture=True,
            )
            try:
                machine = json.loads(raw_version)
                flutter_version = str(machine["frameworkVersion"])
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                raise BuildFailure("Flutter вернул неожиданный --machine JSON.") from error
            if version_tuple(flutter_version) < MIN_FLUTTER:
                raise BuildFailure(f"Нужен Flutter 3.41.0+, найден {flutter_version}.")


        runner.run([flutter, "pub", "get"], "pub_get")
        if not options.skip_format:
            assert dart is not None
            runner.run(
                [dart, "format", "--output=none", "--set-exit-if-changed", "lib", "test"],
                "format",
            )
        if not options.skip_analyze:
            runner.run([flutter, "analyze"], "analyze")
        if not options.skip_tests:
            runner.run([flutter, "test", "--reporter", "expanded"], "test")
        if not options.skip_verifier:
            runner.run([sys.executable, "tools/verify_fixes.py"], "offline_verifier")

        built = root / "build" / "app" / "outputs" / "flutter-apk" / f"app-{options.mode}.apk"
        if not _is_within(built.resolve(), root):
            raise BuildFailure("Каталог сборки APK выходит за пределы проекта.")
        if not options.dry_run:
            discard_stale_build_output(built)
        runner.run([flutter, "build", "apk", f"--{options.mode}"], "build_apk")

        if options.dry_run:
            print("\nDry-run завершён: команды не запускались, файлы не изменялись.")
            return 0

        if not built.is_file() or built.stat().st_size == 0:
            raise BuildFailure(f"Flutter не создал ожидаемый файл: {built}")
        validate_apk_structure(built)

        safe_name = re.sub(r"[^A-Za-z0-9._+-]+", "-", project_name).strip("-")
        safe_version = re.sub(r"[^A-Za-z0-9._+-]+", "-", project_version).strip("-")
        destination = output_dir / f"{safe_name}-{safe_version}-{options.mode}.apk"
        atomic_copy(built, destination)
        digest = sha256_file(destination)
        skipped = [
            name
            for name, skipped_value in (
                ("format", options.skip_format),
                ("analyze", options.skip_analyze),
                ("test", options.skip_tests),
                ("offline_verifier", options.skip_verifier),
            )
            if skipped_value
        ]
        report = {
            "schema": 1,
            "status": "success",
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "project": project_name,
            "version": project_version,
            "mode": options.mode,
            "flutterVersion": flutter_version,
            "completedSteps": runner.steps,
            "stepDurationsSeconds": runner.durations,
            "timeoutSeconds": options.timeout,
            "validation": "zip-crc-manifest-dex; signature-not-verified",
            "skippedChecks": skipped,
            "artifact": {
                "file": destination.name,
                "bytes": destination.stat().st_size,
                "sha256": digest,
            },
            "sourceUpload": False,
            "githubUsed": False,
        }
        report_path = output_dir / f"build-report-{options.mode}.json"
        try:
            atomic_json(report_path, report)
        except OSError as error:
            raise BuildFailure("APK скопирован, но JSON-отчёт записать не удалось. Сборка не подтверждена; проверьте права и свободное место.") from error

        print("\nAPK готов:")
        print(destination)
        print(f"SHA-256: {digest}")
        print(f"Отчёт: {report_path}")
        if skipped:
            print("Внимание: пропущены проверки: " + ", ".join(skipped))
        return 0
    finally:
        if lock is not None:
            lock.release()


def main() -> int:
    try:
        return build(sys.argv[1:])
    except BuildFailure as error:
        print(f"\nСборка остановлена: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nСборка отменена пользователем.", file=sys.stderr)
        return 130
    except (OSError, ValueError) as error:
        print(f"\nСборка остановлена: ошибка файловой системы или конфигурации ({type(error).__name__}). Проверьте пути, права и свободное место.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
