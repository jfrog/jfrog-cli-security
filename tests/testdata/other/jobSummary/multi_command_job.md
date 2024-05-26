#### Builds
| Status | Id | Details |
|--------|----|---------|
| ✅ | build-name (build-number) |  |
| ❌ | build-name (build-number) | <pre>3 violations found<br>└── 3 SCA 🔴 <span style="color:red">2 High</span><br>          🟡 <span style="color:yellow">1 Low</span></pre> |
#### Artifacts
| Status | Id | Details |
|--------|----|---------|
| ❌ | /binary-name | <pre>3 unique vulnerabilities found<br>└── 3 Secrets 🔴 <span style="color:red">2 High</span><br>              🟡 <span style="color:yellow">1 Low</span></pre> |
| ✅ | other-root/dir/binary-name2 |  |
#### Modules
| Status | Id | Details |
|--------|----|---------|
| ❌ | /application1 | <pre>14 unique vulnerabilities found<br>├── 1 SAST 🟡 <span style="color:yellow">1 Low</span><br>├── 5 IAC 🟠 <span style="color:orange">5 Medium</span><br>└── 8 SCA ❗️ <span style="color:red">3 Critical</span> (2 Not Applicable)<br>          🔴 <span style="color:red">4 High</span> (1 Applicable, 1 Not Applicable)<br>          🟡 <span style="color:yellow">1 Low</span></pre> |
| ❌ | /application2 | <pre>1 violations found, 1 unique vulnerabilities<br>└── 2 SCA 🔴 <span style="color:red">2 High</span> (1 Not Applicable)</pre> |
| ✅ | /dir/application3 |  |