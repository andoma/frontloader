# Frontloader

Frontloader keeps docker containers running and automatically upgraded from dockerhub (or any docker repo really).

Frontloader is shipped as a complete Linux system based on Builroot.

## Building

From commandline (For required deps, see beginning of Dockerfile)

```
./build.sh
```

Docker:

```
./build.sh docker
```

## Meta configuration

The meta configuration specifies how Frontloder obtains its primary config.

Meta configuration cannot be reloaded once started.

There are a number of ways frontloader will get its meta config.

#### Loading meta config from ec2

If `FL_ENV` environment variable is set to `ec2` it will load meta config
from http://169.254.169.254/latest/user-data

This is the default for the frontloader AMI image.

#### Loading meta config from URL in environment

The environment variable `FL_META_CONFIG` can be set to a URL which will
download meta config from that URL

#### URL override

If the environment variable `FL_URL` is set, or command line option `-c`
is given, it will use this URL to load the primary config.
Ie, it overrides whatever the meta config specifies

### Meta configuration syntax

Meta configuration doesn't contain much as it it's only supposed to
point out the primary configuration.

#### Plain meta

This just points out a URL to the primary configuration.

```
{
  "type": "plain",  // Plain is also the default
  "url": "<url to config>" // http:// or https:// or a local file path
}
```

#### Amazon Secret Manager

This allows storing the full primary configuration as an AWS Secret.

The machineRole needs to have sufficient access to read the secret and
needs to be assigned to the machine. If machineRole is not specified in
the meta configuration, frontloader will try with all of the machineRoles
assigned to the machine.

Example:

```
{
  "type": "aws-sm",
  "secretId": "<nameofsecret>",
  "region": "eu-west-1",
  "machineRole": "<iamrole>", // optional
}
```

## Primary Configuration

Frontloader is configured from a JSON file.

```
{
  // Contains a dockerhub username and password for private repos
  // If these are not given, only public repos will be available
  "docker": {
    "username": "someuser",
    "password": "very-secret-password",
  },

  // Kernel to run
  "kernel": {
    "manifest": "https://registry.hub.docker.com/v2/myorg/frontloader-image/manifests/52e12365f0"
  },

  // Volumes
  // Two filesystems are supported, XFS and NFSv4
  // For XFS Frontloader will automatically grow the filesystem if the
  // underlying block device expands in size.
  "volumes": [{
    "path": "/some_xfs_volume",
    "device": "/dev/nvme1n1",
    "fstype": "xfs",
    "uid": 1000,
    "gid": 1000,
  },{
    "path": "/some_nfs_volume",
    "device": "nfs.example.com:/exports",
    "fstype": "nfs4",
    "options": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
    "uid": 1000,
    "gid": 1000,
  }],

  // Then comes the container to run
  "container": {
    // URL to the manifest on dockerhub
    "manifest": "https://registry.hub.docker.com/v2/myorg/myproject/manifests/latest",

     // Command to execute in the container,
     // Currently Frontloader doesn't care about the CMD from Dockerfile
    "command": "/usr/local/bin/myproject",

    // UID/GID this should run as
    "uid": 1000,
    "gid": 1000,

    // Capabilites given to the daemon when running as non-root
    "capabilities": [
      "NET_BIND_SERVICE",
      "SYS_NICE"
    ],

    // Mounts to bind into the contianer "INSIDE":"OUTSIDE"
    "mounts": {
      "/dev/log": "/dev/log",
      "/myproject": "/myproject"
    },

    // Dictionary of environment variable to pass to the command
    // String values will be passed as it,
    // Object or List values will be serialized to JSON first
    "environment": {
      "ENV": "production",

      "CONFIG": {
         "foo": "bar"
      }
    }


```

## Container runtime

Each image is installed in a tmpfs mounted at `/tmp/frontloader.rootfs.XXXXXX`.

Once the container has started the tmpfs is unmounted from the root mount namespace.

The tmpfs (root file system) is mounted read-only inside the container. If you want to change something, do it somewhere else :-)

When a new image version of a container is loaded the old instance will be sent the TERM signal but it's never forced to stop (via the KILL signal, etc). This allows the container to shutdown gracefully and take its time.

If Frontloader dies for some reason all containers will be sent the TERM signal (by virtue of the PDEATHSIG Linux kernel feature).

## Creating an AMI

Note: Creating a new AMI is only requried to bootstrap Frontloader installations from scartch and is not needed to perform regular upgrades.

This is, unfortunately, very contrived when it comes to AWS / EC2. You pretty much need two instances. One staging machine and another machine (can be any type, your current dev machine, etc). They should be in the same AWS region and zone though.

For the staging machine:

- Create a new EC2 intance, Choose Ubuntu 18.04
- Choose t3.nano
- Just click thru
- "Select no key-pair"
- Wait for it to boot, then stop it.
- Detach its root volume and delete it.

On your dev machine, download `disk.img` artifact from the circle-ci build you want to use as AMI image.

Create a new 2GB volume.

Attach it to your dev machine:

`aws ec2 attach-volume --volume-id vol-xxx --instance-id i-yyy --device /dev/sdf`

Check `dmesg` or similar to see which device it actually ended up as (Not necessarily `/dev/sdf` unforunately, can also be `/dev/nvmeXnY`)

Now, write out the disk to this volume `sudo dd if=disk.img of=/dev/<something> bs=1M`. Take care to **not** overwrite anything else. Overwriting incorrect volume is irreversible and data will be lost.

Then detach the volume:

`aws ec2 detach-volume --volume-id vol-xxx`

Attach it on the stage machine:

`aws ec2 attach-volume --volume-id vol-yyy --instance-id i-zzz --device /dev/sda1`

Finally, create an AMI:

`aws ec2 create-image --instance-id i-zzz --name "Frontloader-<githash>"`

This AMI can be copied to all regions where it's needed.

# License

MIT (see LICENSE.txt)
