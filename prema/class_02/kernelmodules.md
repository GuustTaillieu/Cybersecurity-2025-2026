# Userspace vs Kernelspace

## Hello world

In this exercise we will write, compile and run some C(++) programs. We will start with a normal program. This lab has been tested on a Linux, Debian, virtual machine. 

Install and or verify the following tools:

```bash
sudo apt install gcc gdb g++ make strace -y
uname -r # should shows something like 6.1.0-35-amd64
apt search linux-headers # look at the first lines, a package that resembles linux-headers-6.1.0-35-amd64 should be there, install it
# Note if you would have issues of the current kernel not matching what is in the package manager upgrade to the correct version with
#
# sudo apt install linux-image-6.xx.x-xx linux-headers-6.xx.x-xx
# sudo update-gru
# sudo reboot
# 
sudo apt install linux-headers-6.1.0-35-amd64
```

Create a seperate directory for this first test called `helloworld`. Create a new file `hello.c` and paste the code below in that file:

```c
#include <stdio.h>

int main(){
    printf("Hello World!");
    return 0;
}
```

Let's compile and be lazy. We can use `make hello` in order to create the executable.

**Questions**

- What command was actually ran when typing make? (Tip: it was printed)

  ​	cc hello.c -o hello

- What does the `file` command tell you about the executable? Is it 32-bit, 64-bit? 

  ​	ELF 64-bit LSB pie executable -> 64-bit

- Test out your first C program by running it.

  ​	

- Did we forget something in the source code to make the program a little bit "better" or "less ugly" when running it? 

  ​	Yes a new line signature (\n)


## A program that crashes

Create a new directory on the same level as helloworld called `testcrash`. Let's once again create a new .c file called testcrash.c. Paste the following code.

```c
#include <stdio.h>

int main(){

        int *p = 0;
        printf("%d\n", *p);
        return 0;
}

```

This code does something that is not a good idea. Don't worry if you do not completely understand this code right now, there are seperate exercises on pointers. All you need to know is that we do something ("low level") and we messed up. 

**Questions**

- Compile and run this program. What is the output?

  ​	Segmentation fault

- What is the exit code (echo $?)? Does this mean the program exited succesfully or not?

  ​	It didn't; exit code 139 shows it crashed


This in fact can be considered a crash of the program. Something illegal happened, and the operating system protected the system to not have any negative side effects. This is typically what happens when a program crashes in user space. All programs, thanks the operating system are somewhat shielded from each other to a certain degree. Also the operating system is not behaving worse because of a crash in user space. Typically all pieces of software, software engineers write are programs running in user space. Only dedicated programs, such as drivers, firmware, very low level programming, operating system development are running in kernelspace. Having issues and crashes in kernelspace is therefore way more dangerous. On Windows this typically leads to the legendary blue screen of death (bsod). Let's test this out on Linux as well.

## Writing a kernel module

In order to test out code running in kernel mode, we will create our own kernel module and load it into Linux. Let's first do this without breaking stuff. 

Go back a level and create a new directory called `hellokernel`.

Once again, we will make our live easier in terms of building and linking and compiling with the help of `make`. We do need some custom things though. In a file called `Makefile` we can configure these specifications. Create the file and copy paste the following contents.

```
obj-m+=hellokernel.o
all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
```

Now let's create the actual `hellokernel.c` file:

```c
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("Dual BSD/GPL");

static int hello_init(void)
{
        printk(KERN_ALERT "Loading hellokernel module...\n");
        printk(KERN_ALERT "Hello world\n");
        return 0;
}

static void hello_exit(void)
{
        printk(KERN_INFO "Goodbye hellokernel module!\n");
}

module_init(hello_init);
module_exit(hello_exit);

```

**Questions**

Type `make` in the terminal and if everything is setup correctly new files should be created. Don't worry if you see something like "Skipping BTF generation". You can ignore that. When it's done perform `ls -l` and search for a file called `hellokernel.ko`. Perform the `file` command to it. What does it say?
	ELF 64-bit LSB relocatable

We will not be able to "run" this file like we are used to. Go ahead and try (even with chmod +x), you should receive an error. What error?
	Exec format error

Let's **load the kernel module**. Make sure you have a second terminal open as we will look at the kernel messages (as our program only prints something). You can do this using `sudo dmesg -w`. This will watch and monitor all messages. In another terminal window perform `sudo insmod hellokernel.ko`. As soon as you pressed enter the message should appear in the dmesg output. You can verify that the kernel module is loaded with `lsmod` and remove with `rmmod`. Also have a look at the bottom of the journal by typing `sudo journalctl` followed by 'shift+g' to go to the bottom. 

Good job, you have written and loaded your first Linux kernel module! 


### Crashing a kernel module

Let's once again create a new folder, one lever higher, called `crashkernel`. You can copy paste the makefile from before, but don't forget to change the object file name to be crashkernel.o instead of hellokernel.o. For `crashkernel.c` use the following code:

```c
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("Dual BSD/GPL");

static int hello_init(void)
{
        printk(KERN_ALERT "Loading crashkernel module...\n");
        printk(KERN_ALERT "Hello world\n");
        int *p = 0;
        printk(*p);
        return 0;
}

static void hello_exit(void)
{
        printk(KERN_INFO "Goodbye crashkernel module!\n");
}

module_init(hello_init);
module_exit(hello_exit);

```

Again, use make to create the kernel object file. You will notice a lot of warnings as we are once again doing this that we shouldn't do. Don't forget to open dmesg if you would have closed it and try to load the new kernel module again and see what happens. 

**Questions**

- Did we crash the program?
- Did we crash the computer (Linux)?
- What output do we see in dmesg as soon as the module gets loaded?
- Try to perform lsmod, do you see crashkernel?
- Try to remove it with rmmod, is this possible?


As you can see the Linux kernel is already smart enough to protect the system against developer mistakes. This is not always the case obviously.


Let's finish this lab by really crashing the kernel directly using a system call. For one last time, create a new folder called `kernelpanic` and perform the same copy and change actions for the Makefile. Create `kernelpanic.c` with the following contents:

```c
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("Dual BSD/GPL");

static int hello_init(void)
{
        printk(KERN_ALERT "Loading kernelpanic module...\n");
        printk(KERN_ALERT "Hello crash\n");

        panic("Down we go, panic called!");

        return 0;
}

static void hello_exit(void)
{
        printk(KERN_INFO "Goodbye kernelpanic module!\n");
}

module_init(hello_init);
module_exit(hello_exit);

```

Load the kernel module. What happens?


Yes you will have the poweroff/reboot the machine yourself. Best not to mess with kernel space right? 