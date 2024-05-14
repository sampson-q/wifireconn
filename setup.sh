#!/bin/bash
#Author: SAMPSON QUARMY, SOKPOLI (Hash 👽)

current_dir=$(pwd)

# Create wifireconn file in the /usr/bin directory
sudo touch /usr/bin/wifireconn
sudo echo "#!/usr/bin/python3

from $current_dir import __main__
__main__.entry_point()" > /usr/bin/wifireconn

# Make wifireconn file executable
sudo chmod +x /usr/bin/wifireconn

# Change wifireconn ownership to the current user
sudo chown $USER /usr/bin/wifireconn