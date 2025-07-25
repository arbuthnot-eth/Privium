#!/bin/bash

# Check if a version argument is provided
PACKAGE_JSON_FILE="package.json"
CONFIG_FILE="src/config.ts"

# Read the current version from package.json
CURRENT_VERSION=$(grep '"version":' "$PACKAGE_JSON_FILE" | head -1 | awk -F: '{ print $2 }' | sed 's/[", ]//g')

# Extract major, minor, and patch versions
MAJOR=$(echo "$CURRENT_VERSION" | cut -d'.' -f1)
MINOR=$(echo "$CURRENT_VERSION" | cut -d'.' -f2)
PATCH=$(echo "$CURRENT_VERSION" | cut -d'.' -f3)

# If a version argument is provided, use it as the new patch version
if [ -n "$1" ]; then
  NEW_PATCH="$1"
else
  # If no argument, increment the patch version
  NEW_PATCH=$((PATCH + 1))
fi

NEW_VERSION="${MAJOR}.${MINOR}.${NEW_PATCH}"

# Update the version in package.json
# The regex 'VERSION: "[0-9]*\.[0-9]*\.\([0-9]*\)"' captures the patch version in group 1.
# The replacement uses '\1' to refer to the captured group.
sed -i "s/\(VERSION: \"[0-9]*\.[0-9]*\.\)[0-9]*\"/\1$NEW_PATCH\"/" "$CONFIG_FILE"
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" "$PACKAGE_JSON_FILE"
echo "Updated $PACKAGE_JSON_FILE and $CONFIG_FILE to version $NEW_VERSION"