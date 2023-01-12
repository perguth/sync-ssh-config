# Sync SSH Config

> Syncs your SSH config

This script:

- **Watches** your `~/.ssh/config` for changes
- Automatically **syncs** changes **with** the **group**

This script does not work for the `root` user.

## Install

```bash
# Install NodeJS
# https://nodejs.org/en/download/package-manager/

# Install the systemd service
bash -c "$(curl -fsSL https://raw.githubusercontent.com/perguth/sync-ssh-config/master/setup.sh)"

# Set/copy the `sharedSecret` of the group
# and set `userName` to your username
sudo nano /etc/opt/sync-ssh-config/swarm.json

# Restart the service
sudo service sync-ssh-config restart
```
