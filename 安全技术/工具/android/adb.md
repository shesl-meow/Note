# Android Debug Bridge(ADB)

Android Debug Bridge (adb) is a versatile command-line tool that lets you communicate with a device.

 It is a client-server program that includes three components:

- **A client**, which sends commands. The client runs on your development machine. You can invoke a client from a command-line terminal by issuing an `adb`command.
- **A daemon (`adbd`)**, which runs commands on a device. The daemon runs as a background process on each device.
- **A server**, which manages communication between the client and the daemon. The server runs as a background process on your development machine.

## How does adb works

客户端：

- 启动一个 adb 客户端时，此客户端首先检查是否有已运行的 adb 服务器进程。
- 如果没有，它将启动服务器进程。当服务器启动时，它与本地 TCP 端口 5037 绑定，并侦听从 adb 客户端发送的命令—所有 adb 客户端均使用端口 5037 与 adb 服务器通信。

服务端：

- 它通过扫描 5555 到 5585 之间（模拟器/设备使用的范围）的奇数号端口查找模拟器/设备实例。服务器一旦发现 adb 后台程序，它将设置与该端口的连接。

- 请注意，每个模拟器/设备实例将获取一对端口——用于控制台连接的偶数号端口、用于 adb 连接的奇数号端口。例如：

  ```
  Emulator 1, console: 5554
  Emulator 1, adb: 5555
  Emulator 2, console: 5556
  Emulator 2, adb: 5557
  and so on...
  ```

当服务器已设置与所有模拟器实例的连接后，您可以使用 adb 命令访问这些实例。

## Enable `adb` debugging on your device

To use adb with a device connected over USB, you must enable **USB debugging** in the device system settings, under **Developer options**.

You can now connect your device with USB. You can verify that your device is connected by executing `adb devices` from the `android_sdk/platform-tools/`directory. If connected, you'll see the device name listed as a "device."

```bash
# see list of connected devices
$ adb devices
```

For more information about connecting to a device over USB, read [Run Apps on a Hardware Device](https://developer.android.com/studio/run/device.html).

## Connect to a device over WiFi

暂时不需要

## Query for devices

You can generate a list of attached devices using the`devices` command.

```bash
$ adb devices -l
```

In response, adb prints this status information for each device:

- Serial number: A string created by adb to uniquely identify the device by its port number. Here's an example serial number: `emulator-5554`
- State: The connection state of the device can be one of the following:
  - `offline`: The device is not connected to adb or is not responding.
  - `device`: The device is now connected to the adb server. Note that this state does not imply that the Android system is fully booted and operational because the device connects to adb while the system is still booting. However, after boot-up, this is the normal operational state of an device.
  - `no device`: There is no device connected.
- Description: If you include the `-l` option, the `devices` command tells you what the device is. This information is helpful when you have multiple devices connected so that you can tell them apart.

### Emulator not listed

his happens when *all* of the following conditions are true:

1. The adb server is not running, and
2. You use the `emulator` command with the `-port` or `-ports` option with an odd-numbered port value between 5554 and 5584, and
3. The odd-numbered port you chose is not busy so the port connection can be made at the specified port number, or if it is busy, the emulator switches to another port that meets the requirements in 2, and
4. You start the adb server after you start the emulator.

One way to avoid this situation is to let the emulator choose its own ports, and don't run more than 16 emulators at once.

Example:

```bash
$ adb kill-server
$ emulator -avd Nexus_6_API_25 -port 5555
$ adb devices

List of devices attached
* daemon not running. starting it now on port 5037 *
* daemon started successfully *
```

## Send commands to a specific device

如果多个模拟器/设备实例正在运行，在发出 adb 命令时您必须指定一个目标实例。为此，请在命令中使用 `-s` 选项。以下是 `-s` 选项的用法：

```bash
$ adb -s <serial_number> <command>
```

如上所示，您使用由 adb 分配的序列号为命令指定目标实例。您可使用 `devices`命令获取正在运行的模拟器/设备实例的序列号。例如：

```bash
$ adb -s emulator-5556 install helloWorld.apk
```

注意，如果在多个设备可用时您未指定目标模拟器/设备实例就发出命令，那么 adb 将生成一个错误。

另外：

- 如果您有多个设备可用（硬件或模拟设备），但只有一个设备是模拟器，则使用 `-e`选项将命令发送至该模拟器。
- 同样，如果有多个设备，但只连接了一个硬件设备，则使用 `-d` 选项将命令发送至该硬件设备。

## Install an app

You can use adb to install an APK on an emulator or connected device with the `install` command:

```bash
$ adb install path_to_apk
```

You must use the `-t` option with the `install` command when you install a test APK. For more information, see [`-t`](https://developer.android.com/studio/command-line/adb#-t-option).

## Set up port forwarding

You can use the `forward` command to set up arbitrary port forwarding, which forwards requests on a specific host port to a different port on a device. The following example sets up forwarding of host port 6100 to device port 7100:

```bash
$ adb forward tcp:6100 tcp:7100
```

## Copy files to/from a device

Use the `pull` and `push` commands to copy files to and from an device. Unlike the `install` command, which only copies an APK file to a specific location, the `pull`and `push` commands let you copy arbitrary directories and files to any location in a device.

To copy a file or directory and its sub-directories *from* the device, do the following:

```bash
$ adb pull remote local
```

To copy a file or directory and its sub-directories *to* the device, do the following:

```bash
$ adb push local remote
```

Replace `local` and `remote` with the paths to the target files/directory on your development machine (local) and on the device (remote). For example:

```bash
$ adb push foo.txt /sdcard/foo.txt
```

## Stop the adb server

In some cases, you might need to terminate the adb server process and then restart it to resolve the problem (e.g., if adb does not respond to a command).

To stop the adb server, use the `adb kill-server` command. You can then restart the server by issuing any other adb command.

```bash
$ adb kill-server
```

# `adb` commands reference

see: https://developer.android.com/studio/command-line/adb