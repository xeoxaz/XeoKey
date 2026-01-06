# PowerShell script to sync wiki/ files to GitHub wiki
# GitHub wikis are separate repositories that need to be cloned and updated manually

Write-Host "=== XeoKey Wiki Sync Script ===" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the right directory
if (-not (Test-Path "wiki/Home.md")) {
    Write-Host "Error: wiki/Home.md not found. Please run this script from the XeoKey root directory." -ForegroundColor Red
    exit 1
}

# Wiki repository URL
$WIKI_REPO = "https://github.com/xeoxaz/XeoKey.wiki.git"
$WIKI_DIR = "XeoKey.wiki"

Write-Host "Step 1: Cloning GitHub wiki repository..." -ForegroundColor Yellow
if (Test-Path $WIKI_DIR) {
    Write-Host "Wiki directory already exists. Removing old clone..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $WIKI_DIR
}

git clone $WIKI_REPO $WIKI_DIR
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to clone wiki repository. Make sure:" -ForegroundColor Red
    Write-Host "  1. The wiki feature is enabled in your GitHub repository settings" -ForegroundColor Red
    Write-Host "  2. You have at least one wiki page created (even if empty)" -ForegroundColor Red
    Write-Host "  3. You have push access to the repository" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Step 2: Copying wiki files..." -ForegroundColor Yellow

# Copy all markdown files from wiki/ to the wiki repo
$files = Get-ChildItem -Path "wiki" -Filter "*.md"
foreach ($file in $files) {
    $dest = Join-Path $WIKI_DIR $file.Name
    Copy-Item -Path $file.FullName -Destination $dest -Force
    Write-Host "  Copied: $($file.Name)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Step 3: Committing changes..." -ForegroundColor Yellow

Push-Location $WIKI_DIR

# Configure git identity if not set (use local repo config or defaults)
$gitName = git config user.name 2>$null
$gitEmail = git config user.email 2>$null

if ([string]::IsNullOrWhiteSpace($gitName)) {
    # Try to get from parent repo
    $parentName = git -C .. config user.name 2>$null
    if ($parentName) {
        git config user.name $parentName
        $gitName = $parentName
    } else {
        git config user.name "XeoKey Developer"
        $gitName = "XeoKey Developer"
    }
}

if ([string]::IsNullOrWhiteSpace($gitEmail)) {
    # Try to get from parent repo
    $parentEmail = git -C .. config user.email 2>$null
    if ($parentEmail) {
        git config user.email $parentEmail
        $gitEmail = $parentEmail
    } else {
        git config user.email "xeokey@example.com"
        $gitEmail = "xeokey@example.com"
    }
}

Write-Host "  Using git identity: $gitName <$gitEmail>" -ForegroundColor Gray

# Check if there are changes
$status = git status --porcelain
if ([string]::IsNullOrWhiteSpace($status)) {
    Write-Host "No changes to commit. Wiki is already up to date." -ForegroundColor Green
    Pop-Location
    Remove-Item -Recurse -Force $WIKI_DIR
    exit 0
}

git add -A
git commit -m "Update wiki documentation from wiki/"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to commit changes." -ForegroundColor Red
    Pop-Location
    exit 1
}

Write-Host ""
Write-Host "Step 4: Pushing to GitHub..." -ForegroundColor Yellow
git push origin master
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to push to GitHub. You may need to:" -ForegroundColor Red
    Write-Host "  1. Set up authentication (SSH key or personal access token)" -ForegroundColor Red
    Write-Host "  2. Check your GitHub permissions" -ForegroundColor Red
    Pop-Location
    exit 1
}

Pop-Location

Write-Host ""
Write-Host "=== Wiki sync completed successfully! ===" -ForegroundColor Green
Write-Host "Your wiki is now available at: https://github.com/xeoxaz/XeoKey/wiki" -ForegroundColor Cyan
Write-Host ""
Write-Host "Cleaning up temporary wiki directory..." -ForegroundColor Yellow
Remove-Item -Recurse -Force $WIKI_DIR

Write-Host "Done!" -ForegroundColor Green

