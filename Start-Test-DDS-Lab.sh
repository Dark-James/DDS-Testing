#!/bin/bash

# Function to open a gnome-terminal and execute a command
open_terminal() {
    gnome-terminal --title="$1" -- bash -c "$2; exec bash"
}

# Open the terminals
open_terminal "Publisher" "python Publisher.py"
open_terminal "Subscriber 1" "python Subcriber-1.py"
open_terminal "Subscriber 2" "python Subscriber-2.py"
open_terminal "Subscriber 3" "python Subscriber-3.py .py"

# Delay of 5 seconds before opening the last terminal
sleep 5

open_terminal "List" "cyclonedds ls"

# Wait a moment to ensure all terminals are open
sleep 2

# Use wmctrl to tile the windows
wmctrl -r ":ACTIVE:" -b add,maximized_vert,maximized_horz
wmctrl -r "Publisher" -e 0,0,0,640,480
wmctrl -r "Subscriber 1" -e 0,640,0,640,480
wmctrl -r "Subscriber 2" -e 0,0,480,640,480
wmctrl -r "Subscriber 3" -e 0,640,480,640,480
wmctrl -r "List" -e 0,1280,240,640,480
