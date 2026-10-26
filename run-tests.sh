#!/bin/bash
# Run the jcardsim unit tests in-JVM (no pcscd, no hardware).
# Usage: ./run-tests.sh [--quiet]
set -e
cd "$(dirname "$0")"

JC=jcardsim-2.2.2-unsigned.jar
JUNIT=junit-platform-console-standalone-1.10.2.jar
SIM=${SIM_LIB:-$HOME/.m2/repository/com/licel/jcardsim/2.2.2/$JC}
if [ ! -f "$SIM" ]; then
  echo "jcardsim not found at $SIM — install via maven or set SIM_LIB" >&2
  exit 1
fi
if [ ! -f "$JUNIT" ]; then
  curl -sL -o "$JUNIT" https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.10.2/$JUNIT
fi

rm -rf build/test-classes
mkdir -p build/test-classes
javac --release 17 -cp "$SIM" -d build/test-classes $(find src/main/java -name "*.java")
javac --release 17 -cp "$SIM:build/test-classes:$JUNIT" -d build/test-classes $(find src/test/java -name "*.java")
cp src/test/resources/* build/test-classes/ 2>/dev/null || true
cp test/vectors/*.json build/test-classes/ 2>/dev/null || true
java -jar "$JUNIT" execute -cp "$SIM:build/test-classes" --scan-classpath --details=tree \
  --reports-dir=build/test-reports 2>&1 | tee build/test-output.log | tail -40
