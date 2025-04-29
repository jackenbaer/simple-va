#!/usr/bin/env python3
import subprocess
import sys
import yaml

# 1) Get the version from your Go binary
try:
    raw = subprocess.check_output(
        ["simple-va", "--version"], stderr=subprocess.STDOUT
    ).decode("utf-8").strip()
    version = raw.split(",")[-1]
except subprocess.CalledProcessError as e:
    print("Failed to run ../simple-va --version:", e.output.decode())
    sys.exit(1)

print("Code ApiVersion:", version)

# 2) Parse the OpenAPI/Swagger YAML
with open("docs/swagger.yaml") as f:
    spec = yaml.safe_load(f)

# 3) Extract the prefix
prefix = None
if spec.get("servers"):
    prefix = spec["servers"][0]["url"].lstrip("/").strip()
elif spec.get("basePath"):
    prefix = spec["basePath"].lstrip("/").strip()
elif spec.get("swagger") == "2.0":
    # infer from first path
    paths = spec.get("paths", {})
    if paths:
        first = next(iter(paths.keys()))
        prefix = first.strip("/").split("/")[0]

if not prefix:
    print("Could not determine API version prefix in swagger.yaml")
    sys.exit(1)

print("Spec prefix:     ", prefix)

# 4) Compare version vs. prefix
if version != prefix:
    print(f"Version mismatch: code={version}  spec={prefix}")
    sys.exit(1)

# 5) Ensure every endpoint path starts with the prefix
for path in spec.get("paths", {}):
    if not path.startswith(f"/{prefix}/"):
        print(f"Endpoint '{path}' does not start with '/{prefix}/'")
        sys.exit(1)

print("All endpoints start with the prefix and versions match")
