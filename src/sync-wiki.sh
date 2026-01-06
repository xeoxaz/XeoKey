#!/bin/bash
# Bash script to sync wiki/ files to GitHub wiki
# GitHub wikis are separate repositories that need to be cloned and updated manually

echo "=== XeoKey Wiki Sync Script ==="
echo ""

# Check if we're in the right directory
if [ ! -f "wiki/Home.md" ]; then
    echo "Error: wiki/Home.md not found. Please run this script from the XeoKey root directory."
    exit 1
fi

# Wiki repository URL
WIKI_REPO="https://github.com/xeoxaz/XeoKey.wiki.git"
WIKI_DIR="XeoKey.wiki"

echo "Step 1: Cloning GitHub wiki repository..."
if [ -d "$WIKI_DIR" ]; then
    echo "Wiki directory already exists. Removing old clone..."
    rm -rf "$WIKI_DIR"
fi

git clone "$WIKI_REPO" "$WIKI_DIR"
if [ $? -ne 0 ]; then
    echo "Error: Failed to clone wiki repository. Make sure:"
    echo "  1. The wiki feature is enabled in your GitHub repository settings"
    echo "  2. You have at least one wiki page created (even if empty)"
    echo "  3. You have push access to the repository"
    exit 1
fi

echo ""
echo "Step 2: Copying wiki files..."

# Copy all markdown files from wiki/ to the wiki repo
for file in wiki/*.md; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        cp "$file" "$WIKI_DIR/$filename"
        echo "  Copied: $filename"
    fi
done

echo ""
echo "Step 3: Committing changes..."

cd "$WIKI_DIR"

# Configure git identity if not set (use parent repo config or defaults)
GIT_NAME=$(git config user.name 2>/dev/null)
GIT_EMAIL=$(git config user.email 2>/dev/null)

if [ -z "$GIT_NAME" ]; then
    # Try to get from parent repo
    PARENT_NAME=$(git -C .. config user.name 2>/dev/null)
    if [ -n "$PARENT_NAME" ]; then
        git config user.name "$PARENT_NAME"
        GIT_NAME="$PARENT_NAME"
    else
        git config user.name "XeoKey Developer"
        GIT_NAME="XeoKey Developer"
    fi
fi

if [ -z "$GIT_EMAIL" ]; then
    # Try to get from parent repo
    PARENT_EMAIL=$(git -C .. config user.email 2>/dev/null)
    if [ -n "$PARENT_EMAIL" ]; then
        git config user.email "$PARENT_EMAIL"
        GIT_EMAIL="$PARENT_EMAIL"
    else
        git config user.email "xeokey@example.com"
        GIT_EMAIL="xeokey@example.com"
    fi
fi

echo "  Using git identity: $GIT_NAME <$GIT_EMAIL>"

# Check if there are changes
if [ -z "$(git status --porcelain)" ]; then
    echo "No changes to commit. Wiki is already up to date."
    cd ..
    rm -rf "$WIKI_DIR"
    exit 0
fi

git add -A
git commit -m "Update wiki documentation from wiki/"
if [ $? -ne 0 ]; then
    echo "Error: Failed to commit changes."
    cd ..
    exit 1
fi

echo ""
echo "Step 4: Pushing to GitHub..."
git push origin master
if [ $? -ne 0 ]; then
    echo "Error: Failed to push to GitHub. You may need to:"
    echo "  1. Set up authentication (SSH key or personal access token)"
    echo "  2. Check your GitHub permissions"
    cd ..
    exit 1
fi

cd ..

echo ""
echo "=== Wiki sync completed successfully! ==="
echo "Your wiki is now available at: https://github.com/xeoxaz/XeoKey/wiki"
echo ""
echo "Cleaning up temporary wiki directory..."
rm -rf "$WIKI_DIR"

echo "Done!"

