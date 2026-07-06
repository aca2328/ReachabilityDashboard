#!/bin/zsh

# Build and run script for ReachabilityDashboard
# This script:
# 1. Pulls the latest changes from the current branch
# 2. Cleans the build directory completely
# 3. Builds the project in release mode
# 4. Runs the application

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔄 Pulling latest changes..."
git pull origin HEAD

echo "🧹 Cleaning build directory..."
rm -rf .build

echo "🔨 Building in release mode..."
swift build --configuration release

echo "▶️  Running application..."
open .build/arm64-apple-macosx/release/ReachabilityDashboard

echo "✅ Application started. Check your Dock."
