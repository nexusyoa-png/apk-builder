# APK Builder

Local helper scripts for building a Flutter project into an Android APK.

This repository contains only the APK builder. It does not contain the mobile app source code.

## Requirements

- Flutter 3.41 or newer
- Android SDK
- Python 3
- JDK 17 or newer for release signing

Copy these files into the root of your Flutter project, or run them from a project root that contains `pubspec.yaml` and `lib/`.

## Debug APK

```sh
sh build_apk.sh --mode debug
```

On Windows:

```bat
build_apk.bat --mode debug
```

The APK and a JSON report are written to `dist/`.

## Release APK

```sh
python3 tools/make_keystore.py
sh build_apk.sh --mode release
```

Never commit `android/key.properties` or a keystore. The repository includes only the safe example template.

## Tests

```sh
python3 -m unittest tools/apk_builder_test.py tools/make_keystore_test.py
```
