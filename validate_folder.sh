#!/bin/bash


if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <folder> [<folder2> ...]"
    exit 1
fi

for FOLDER in "$@"; do
    if [ ! -d "$FOLDER" ]; then
        echo "Error: $FOLDER is not a directory"
        continue
    fi

    for file in "$FOLDER"/*.h2g; do
        if [ -f "$file" ]; then
            echo "Validating $file..."
            python3 h2g_validate.py "$file" > "${file}_validation.log"
            if [ $? -eq 0 ]; then
                            echo "  ✓ Success: $file is valid"
                        else
                            echo "  ✗ Failed: $file validation failed"
                        fi
        fi
    done
done

exit 0
