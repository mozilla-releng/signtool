# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [3.1.4] - 2017-08-04
### Added
- added widevine support

## [3.1.3] - 2017-07-13
### Changed
- stop using pefile; verify windows signatures more efficiently

## [3.1.2] - 2017-07-13
### Fixed
- accept the `sha2signcodestub` and `mar_sha384` signing format.
- Fix the missing readme section on the pypi page.

## [3.1.1] - 2017-07-13
- Bad release: It should have contain the patch in 3.1.1

## [3.1.0] - 2017-06-02
### Fixed
- accept the `macapp` signing format, and translate it to `dmg` for the signing servers.

## [3.0.0] - 2017-03-23
### Changed
- changed the `dmg` signing format to accept and return tarballs.
- changed `unpackfile` to accept `.tgz` and `.tar.gz` suffixes for tarballs.

### Removed
- removed the `dmgv2` signing format.

## [2.0.3] - 2016-08-19
### Fixed

- fixed `remote_signfile` exception logging.

## [2.0.2] - 2016-08-08
### Changed

- moved source repo to [mozilla-releng/signtool](https://github.com/mozilla-releng/signtool)
- changed required pefile version to `>=2016.3.28` because we need [this fix](https://github.com/erocarrera/pefile/commit/ac410dcf7fff6840a06bc50e374f4b4db33e0c0e) for py3.

### Removed

- removed py26 support

## [2.0.1] - 2016-07-08
### Changed

- fixed packaging to remove tests

## [2.0.0] - 2016-07-08
### Added
- more unittests; 65% coverage

### Changed

- switch to `requests` instead of `poster`+`urllib`
- refactor to be more clean architecture oriented
- switch to `pytest` from `nosetests`

### Fixed

- py3 signtool working again

## [1.0.8] - 2016-06-21
### Added

- py3 support
- standalone signtool support

### Changed

- Copied signtool source files from [build-tools](https://github.com/escapewindow/build-tools/commit/2c797a5623efc391cd09304d314571638b596e8c)

## [1.0.7] - 2016-06-21 [YANKED]
## [1.0.6] - 2016-06-21 [YANKED]
