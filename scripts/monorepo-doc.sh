#!/bin/bash

# Generate codebase documentation excluding certain directories and files
# This script creates a comprehensive overview of the project structure and contents

# Define output file in a way that won't conflict with the search
OUTPUT_FILE="./Docs/zodebase.txt"

echo "Generating codebase documentation..."

# Create the documentation
(
  echo "File Structure:"
  echo "."
  find . -not -path '*/node_modules/*' -not -path '*/.wrangler/*' -not -path '*/.git/*' -not -path '*/dist/*' -not -path '*/Docs/*' -not -name 'index3.ts' -not -name 'zodebase.txt' -not -name 'codebase.txt' -print | sort | awk -F'/' '{ if ($0 != ".") { indent = ""; for (i=2; i<NF; i++) indent = indent " "; printf "%s|-- %s\n", indent, $NF } }'
  echo -e "\n\n--- Codebase Contents ---\n"
  find . -type f -not -path '*/node_modules/*' -not -path '*/.wrangler/*' -not -path '*/.git/*' -not -path '*/Docs/*' -not -path '*/dist/*' -not -name 'package-lock.json' -not -name 'zodebase.txt' -not -name 'worker-configuration.d.ts' -not -name '.env' -not -name '.dev.vars' -not -name '.gitignore' -not -name '.gitconfig' -not -name 'README.md' -not -name '*.svg' -not -name 'index3.ts' -not -name 'codebase.txt' -exec sh -c 'printf "\n\n======== File: %s ========\n\n" "$0"; cat "$0"' {} \;
) > "$OUTPUT_FILE"

echo "Codebase documentation generated successfully at $OUTPUT_FILE"