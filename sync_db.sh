#!/bin/bash

# Configuration
REPO_DIR="/home/ubuntu/psb-cyber-26"
DB_FILE="rakshak/rakshak.db"
GIT_BRANCH="main"

# Navigate to the repository
cd "$REPO_DIR" || exit

# Check if there are changes to the database file
if git status --short "$DB_FILE" | grep -q "."; then
    echo "$(date): Changes detected in $DB_FILE. Committing and pushing..."
    
    # Add, commit, and push
    git add "$DB_FILE"
    git commit -m "chore: automated database backup $(date '+%Y-%m-%d %H:%M:%S')"
    git push origin "$GIT_BRANCH"
    
    if [ $? -eq 0 ]; then
        echo "$(date): Successfully pushed to GitHub."
    else
        echo "$(date): Error pushing to GitHub."
    fi
else
    echo "$(date): No changes in $DB_FILE. Skipping push."
fi
