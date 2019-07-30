# Part 1: Orientation and setup

## `Docker` 概念

### What is docker?

Docker is a platform for developers and sysadmins to **develop, deploy, and run** applications with containers. The use of Linux containers to deploy applications is called *containerization*. 

Containerization is increasingly popular because containers are:

- Flexible, Lightweight, Interchangeable, Portable, Scalable, Stackable

### Images and Containers

- **Image**：包含所有运行一个程序所需环境的可执行包。比如：其中的代码，库文件，环境变量，配置文件等等。一个 `container` 通过运行一个 `image` 启动。

- **containers**：运行一个 `image` 的实例，或者说一个拥有状态和用户进程的 `image`。你可以使用以下的命令查看正在运行的实例：

  ```bash
  $ docker ps
  ```

### Containers and Virtual machines

- A **container** runs *natively* on Linux and shares the kernel of the host machine with other containers. It runs a discrete process, taking no more memory than any other executable, making it lightweight.

- By contrast, a **virtual machine** (VM) runs a full-blown “guest” operating system with *virtual* access to host resources through a hypervisor. In general, VMs provide an environment with more resources than most applications need.

## 测试 `Docker` 的版本

通过以下的命令查看 `docker` 的版本：

```bash
$ docker --version
Docker version 17.12.1-ce, build 7390fc6

# view even more details about your docker installation with following command:
$ docker info
Containers: 0
 Running: 0
 Paused: 0
 Stopped: 0
Images: 0
...
```

## 测试 `Docker` 的安装

以下的命令会自动运行一个测试 `image`，若未安装，该命令会自动下载镜像：

```bash
$ docker run hello-world
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
d1725b59e92d: Pull complete 
Digest: sha256:0add3ace90ecb4adbf7777e9aacf18357296e799f81cabc9fde470971e499788
Status: Downloaded newer image for hello-world:latest
...
```

通过之前的查看命令，可以看到 `hello-world` 这个 `image` 已经被安装到了机器上：

```bash
$ docker image ls
```

List the `hello-world` container (spawned by the image) which exits after displaying its message. If it were still running, you would not need the `--all` option:

```bash
$ docker container ls --all
```

## 命令总结

```bash
## List Docker CLI commands
docker
docker container --help

## Display Docker version and info
docker --version
docker version
docker info

## Execute Docker image
docker run hello-world

## List Docker images
docker image ls

## List Docker containers (running, all, all in quiet mode)
docker container ls
docker container ls --all
docker container ls -aq
```

