#!/bin/zsh

# Release script that publishes ReachabilityDashboard as a GitHub release
# This script:
# 1. Checks the working tree is clean and main is pushed
# 2. Builds the .app bundle with bundle.sh
# 3. Zips it and creates release v1.0.<build number> with gh

set -e

SCRIPT_DIR="${0:A:h}"
cd "$SCRIPT_DIR"

APP_NAME="ReachabilityDashboard"
BUILD_NUMBER="$(git rev-list --count HEAD)"
TAG="v1.0.$BUILD_NUMBER"
ZIP=".build/$APP_NAME.zip"

if [[ -n "$(git status --porcelain)" ]]; then
    echo "❌ Uncommitted changes, commit or stash them first."
    exit 1
fi
git fetch -q origin main
if [[ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]]; then
    echo "❌ HEAD isn't origin/main, push (or pull) first."
    exit 1
fi
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "❌ Release $TAG already exists, commit something new first."
    exit 1
fi

./bundle.sh

echo "🗜  Zipping..."
rm -f "$ZIP"
ditto -c -k --keepParent ".build/$APP_NAME.app" "$ZIP"

echo "🚀 Creating release $TAG..."
gh release create "$TAG" "$ZIP" --target "$(git rev-parse HEAD)" --title "$APP_NAME ${TAG#v}" --notes-file - <<'EOF'
Menu bar app that monitors ICMP, DNS, and HTTPS probe latency, with a live neon graph dashboard, sparklines in the popover, and an editable target list.

## Install
1. Download `ReachabilityDashboard.zip`, unzip it, and move `ReachabilityDashboard.app` to Applications.
2. The app is ad-hoc signed, not notarized, so macOS blocks it the first time. Open it once, then choose **Open Anyway** in System Settings › Privacy & Security. Or run:
   ```sh
   xattr -dr com.apple.quarantine /Applications/ReachabilityDashboard.app
   ```

Requires macOS 13 or later. Universal binary (Apple silicon and Intel).
EOF
