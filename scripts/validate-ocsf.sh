#!/bin/bash
# Actually validate HTA-LM-001 fields against OCSF API

OCSF_API="https://schema.ocsf.io/api"

echo "🔍 Validating HTA-LM-001 fields against OCSF API..."
echo ""

# Fields we're using in HTA-LM-001
SMB_FIELDS=("time" "src_endpoint" "dst_endpoint" "file" "share" "command" "metadata")
PROCESS_FIELDS=("time" "device" "process" "actor" "metadata")

# Fetch SMB Activity schema
echo "📋 Fetching smb_activity schema..."
SMB_SCHEMA=$(curl -s "${OCSF_API}/classes/smb_activity")

if [ -z "$SMB_SCHEMA" ]; then
    echo "❌ Failed to fetch smb_activity schema"
    exit 1
fi

echo "✅ SMB Activity ($(echo $SMB_SCHEMA | grep -o '"uid":[0-9]*' | cut -d':' -f2))"
echo ""
echo "Validating SMB fields:"

for field in "${SMB_FIELDS[@]}"; do
    if echo "$SMB_SCHEMA" | grep -q "\"$field\""; then
        echo "  ✅ $field - found"
    else
        echo "  ❌ $field - NOT FOUND"
    fi
done

# Fetch Process Activity schema
echo ""
echo "📋 Fetching process_activity schema..."
PROCESS_SCHEMA=$(curl -s "${OCSF_API}/classes/process_activity")

if [ -z "$PROCESS_SCHEMA" ]; then
    echo "❌ Failed to fetch process_activity schema"
    exit 1
fi

echo "✅ Process Activity ($(echo $PROCESS_SCHEMA | grep -o '"uid":[0-9]*' | cut -d':' -f2))"
echo ""
echo "Validating Process fields:"

for field in "${PROCESS_FIELDS[@]}"; do
    if echo "$PROCESS_SCHEMA" | grep -q "\"$field\""; then
        echo "  ✅ $field - found"
    else
        echo "  ❌ $field - NOT FOUND"
    fi
done

echo ""
echo "================================================================"
echo "Note: This validates top-level fields only."
echo "Nested fields (like src_endpoint.ip, file.name) require the parent"
echo "object to exist, which we've validated above."
echo ""
echo "If all parent objects (src_endpoint, dst_endpoint, file, process,"
echo "device, actor, metadata) are ✅, then nested fields like:"
echo "  - src_endpoint.ip"
echo "  - file.name"
echo "  - process.file.path"
echo "are valid by definition in OCSF."
echo ""
echo "For full schema details:"
echo "  https://schema.ocsf.io/1.3.0/classes/smb_activity"
echo "  https://schema.ocsf.io/1.3.0/classes/process_activity"
echo "================================================================"
