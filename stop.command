#!/bin/bash
# Double-click this file in Finder to stop SSO Watcher.
sudo lsof -ti :8765 2>/dev/null | xargs sudo kill -9 2>/dev/null
echo "SSO Watcher stopped."
sleep 1
