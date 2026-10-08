# Build environment

The build and tests were verified on the machine and versions below. Anything newer within
the same major versions is expected to work.

| Component | Version |
|-----------|---------|
| OS | macOS 15.8.1, Apple M3 (arm64) |
| JDK | OpenJDK 17.0.20.1 (Homebrew `openjdk@17`) |
| Maven | 3.10.0, via Maven Wrapper 3.3.4 (`./mvnw`, only-script mode) |
| Spring Boot | 3.3.5 (Spring Framework 6.1.14) |
| Hibernate ORM | 6.5.3.Final |
| H2 | 2.2.224 (in-memory) |
| JUnit Jupiter | 5.10.5 |
| AssertJ | 3.25.3 |

## Commands

```bash
./mvnw test        # unit + Spring context tests
./mvnw verify      # what CI runs
```

## Last verified

2026-10-09: `./mvnw test` passes, 5 tests (`SeedDataTest`), 0 failures.

## Notes

- `JAVA_HOME` must point at a JDK 17+, e.g.
  `export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home`.
- The wrapper downloads Maven into `~/.m2/wrapper` on first use; no global Maven is needed.
