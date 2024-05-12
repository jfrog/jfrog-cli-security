#### Builds
```
✅ build-name (build-number)
❌ build-name (build-number): Found 3 Secrets (2 High, 1 Low)
```
#### Binaries
```
❌ /binary-name: Found 3 Secrets (2 High, 1 Low)
✅ other-root/dir/binary-name2
```
#### Modules
```
❌ /application1: Found 14 vulnerabilities
├── 1 SAST vulnerabilities (1 Low)
├── 5 IAC vulnerabilities (5 Medium)
└── 8 SCA vulnerabilities
    ├── 3 Critical (2 Not Applicable)
    ├── 4 High (1 Applicable, 1 Not Applicable)
    └── 1 Low
❌ /application2: Found 1 SCA vulnerabilities
    └── 1 High (1 Not Applicable)
✅ /dir/application3
```