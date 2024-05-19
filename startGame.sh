#!/bin/bash

# Get the directory of the current script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Open terminal for the server
gnome-terminal --title="Server" -- bash -c "python3 \"$DIR/server.py\"; exec bash"

# Open terminal for Player 1
gnome-terminal --title="Player 1" -- bash -c "python3 \"$DIR/client.py\"; exec bash"

# Open terminal for Player 2
gnome-terminal --title="Player 2" -- bash -c "python3 \"$DIR/client.py\"; exec bash"


chmod +x startGame.sh
