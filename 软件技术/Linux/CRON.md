> 学习网址：
>
> - https://www.marksanborn.net/linux/learning-cron-by-example/
> - http://www.unixgeeks.org/security/newbie/unix/cron-1.html

# CRON

If you are using a Linux system and want to schedule a task to run in the future you will probably need to know cron. Cron is much like Window’s Scheduled Tasks. The only difference is that cron is conifgured by a simple text file. 

Now obviously cron is very dependent and sensitive to the time. If you want accurate results from cron you are going to want to setup your computer to sync its clock via NTP. 

```bash
$ sudo ntpdate pool.ntp.org
```

## Editing Cron

There are more than one way to edit the cron config files; however many of them require you to restart the service.

Here is a method to add a task to `cron` without having to restart  the deamon:

```bash
$ crontab -e
```

Here is the basic structure for `cron`:

```cron
m h dom mon dow command
```

where

- `m` - minutes
- `h` - hours (24 hours)
- `dom` - day of month
- `mon` - month
- `dow` - day of the  week
- `command` - the command you want to run. This can contain spaces or point to a bash script.

## Examples

`*`’s represent wildcards or any:

```cron
10 * * * * echo “This command is run at 10 min past every hour”

22 7 * * * echo “This command is run daily at 7:22 am”

00 4 * * 0 echo “This command is run at 4 am every Sunday”
```

*PostScript*: In `dow`, 0 and 7 are both represent Sunday.



Using the `-` allows us to specify ranges of days (Execute at 5 pm only in weekdays):

```cron
* 17 * * 1-5 /path/to/your/code
```



Using the `,` allows us to specify intervals without having to have multiple entries in cron: (This would execute the ask on the 1st, the 10th, the 20th and on the 30th of each month, at 17:59 PM.)

```cron
59 17 1,10,20,30 * * /home/username/backupsite
```



Using the `/` allows us to divide the day into chunks: (Here, the tasks is executed every 4 hours (24⁄6 =4).)

```cron
59 */6 * * * /home/username/backupsite
```



## Start

Cron is a daemon, which means that it only needs to be started once, and will  lay dormant until it is required. 

The `cron` daemon, or `crond`, stays dormant  until a time specified in one of the config files, or `crontabs`.