# Rootless Outline Server

This is the modified version of the [Official Install Script](https://github.com/Jigsaw-Code/outline-server/blob/master/src/server_manager/install_scripts/install_server.sh) for running outline vpn server with rootless container using podman.

## Prerequisites
- [Podman](https://podman.io)

## Install

As this is for rootless installation, run this as normal user.
```
bash outline.sh
```
You can specify flags to customize the installation. For example, to use hostname `myserver.com` and the port 2000 for access keys and the port 3000 for api key, you can run:
```
bash outline.sh --hostname myserver.com --keys-port 2000 --api-port 3000
```

## Remove

To remove and clean up, run this:
```
bash outline.sh --remove
```

## Notes
- As this is running in rootless container, the ports less than 1024 cannot be used.
- If you run outline.sh with sudo or with root user, the installation will also be successful. But the container will be rootful and also be able to use ports less than 1024.
- But if you want to use ports less than 1024 with rootless container, This command will allow rootless Podman containers to bind to ports >= 80.
  ```
  echo "net.ipv4.ip_unprivileged_port_start=80" | sudo tee -a /etc/sysctl.conf
  sudo sysctl --system
  ```
