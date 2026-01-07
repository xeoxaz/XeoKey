#!/bin/bash
# Restart script for XeoKey server
# This script pulls updates and restarts the server

echo "[$(date)] Restarting XeoKey server..."

# Change to the script directory
cd "$(dirname "$0")"

# Pull latest changes
echo "Pulling latest changes from GitHub..."
git pull origin master
if [ $? -ne 0 ]; then
    echo "ERROR: Git pull failed!"
    exit 1
fi

echo "Git pull successful!"

# Wait a moment for any file system sync
sleep 2

# Start the new server instance in background
echo "Starting new server instance..."
nohup bun start > /dev/null 2>&1 &

# Wait a moment for the new server to start
sleep 3

# Exit this process (the old server process will end)
echo "Old server process will exit now..."
exit 0

