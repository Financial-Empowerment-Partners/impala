# JavaCard Libraries

Local `*.jar` dependencies repository.

## Vendored tooling (provenance)

The two build-tool jars referenced by `applet/build.xml` are vendored here,
pinned by version in the filename (the upstream release assets are
unversioned). When updating, download from the release URL, rename with the
version, record the new SHA-256 below, and update the `deps.*.jar` properties
in `build.xml`.

| File | Source | SHA-256 |
|------|--------|---------|
| `ant-javacard-v26.05.15.jar` | <https://github.com/martinpaljak/ant-javacard/releases/download/v26.05.15/ant-javacard.jar> | `14f5e25c07b184e4ec02ee148892c2ea7ad5d7e9db8b91109524df8f7d000589` |
| `gp-v25.10.20.jar` | <https://github.com/martinpaljak/GlobalPlatformPro/releases/download/v25.10.20/gp.jar> | `c88e0c5093032ec4571571f5397b6174e56bf632667950fa5bb716338534b122` |

Verify after download:

```bash
sha256sum --check <<'EOF'
14f5e25c07b184e4ec02ee148892c2ea7ad5d7e9db8b91109524df8f7d000589  ant-javacard-v26.05.15.jar
c88e0c5093032ec4571571f5397b6174e56bf632667950fa5bb716338534b122  gp-v25.10.20.jar
EOF
```

Note: ant-javacard v26.x requires Java 17+ to run; `gp.jar` (GlobalPlatformPro)
is only exercised against physical cards (`:applet:install` / `list` / `info`),
not in CI.

You can add here local dependencies if there are not available on the 
Maven central repository or you are not willing to use those.

If there is a `test.jar` file you can add it as a dependency
by adding the following line to the `dependencies {}` block.

```gradle
compile name: 'test'
```

This works only for JAR files placed right in the `/libs` directory (flat hierarchy).
The artifact group is ignored, artifact is searched just by the name.
 
For subdirectories you have to use the `files()` or `fileTree` as demonstrated below.

Java 8+ is required.

## Custom JCardSim

If you want to use custom JCardSim version place your jar in the `libs` directory, e.g., as
`libs/jcardsim-3.0.6.jar`

Then modify project gradle file `build.gradle`, in particular section `dependencies` as follows:

```gradle
dependencies {
    testCompile 'org.testng:testng:6.1.1'
    testCompile group: 'com.klinec', name: 'javacard-tools', version: '0.0.1', transitive: false
    
    // Previously, the jcardsim record:
    // jcardsim 'com.licel:jcardsim:3.0.5'
            
    // Now using custom version.
    jcardsim ':jcardsim:3.0.6'
        
    // Or you can include jcardsim directly:
    // jcardsim files(libs + '/jcardsim-3.0.5.jar')
}

```


## `globalplatform-2_1_1`

Globalplatform libraries

```gradle
compile fileTree(dir: rootDir.absolutePath + '/libs/globalplatform-2_1_1', include: '*.jar')
```

Or if you use predefined gradle file with `libs` variable:

```gradle
compile fileTree(dir: libs + '/globalplatform-2_1_1', include: '*.jar')
```

License: no idea

## `visa_openplatform`

```gradle
compile fileTree(dir: rootDir.absolutePath + '/libs/visa_openplatform-2_0', include: '*.jar')
```

License: no idea

