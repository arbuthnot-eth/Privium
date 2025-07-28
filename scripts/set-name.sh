#!/bin/bash

PACKAGE_JSON_FILE="package.json"
CONFIG_FILE="src/config.ts"
FRONTEND_CONFIG_FILE="frontend/vite.config.ts"

# Read the current name from package.json
CURRENT_NAME=$(grep '"name":' "$PACKAGE_JSON_FILE" | head -1 | awk -F: '{ print $2 }' | sed 's/[", ]//g')

# If a name argument is provided, use it as the new name
if [ -n "$1" ]; then
  NEW_NAME="$1"
else
  # If no argument, default to the current name from package.json
  NEW_NAME="$CURRENT_NAME"
fi

# Use sed to update the SERVER_NAME in frontend/vite.config.ts
sed -i "s/SERVER_NAME: JSON.stringify(\"[^\"]*\")/SERVER_NAME: JSON.stringify(\"$NEW_NAME\")/" "$FRONTEND_CONFIG_FILE"
sed -i "s/NAME: \"[^\"]*\"/NAME: \"$NEW_NAME\"/" "$CONFIG_FILE"
echo "Updated $FRONTEND_CONFIG_FILE and $CONFIG_FILE to name $NEW_NAME"

# Use sed to update the title in frontend/index.html
sed -i "s/<title>[^<]*<\/title>/<title>$NEW_NAME<\/title>/" "frontend/index.html"
echo "Updated frontend/index.html to title $NEW_NAME"