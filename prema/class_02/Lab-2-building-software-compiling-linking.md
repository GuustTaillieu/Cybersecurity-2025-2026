# Compiling software

# Recap

Remember the difference between a binary (or also called an executable) and a process:

- A binary/executable: A file stored on disk 
    - Containing machine code, data, metadata
    - Maybe human-readable strings (ascii, Unicode) 
    - On Linux: Usually ELF format
    - On Windows: Usually PE format
- A process: A running instance of a program (binary/executable). The operating system loads the binary into memory, 
  
  assigns resources and manages execution
      - In memory!
      - Managed by operating system
      - The CPU typically follows the fetch-decode-execute cycle

## Building software 

Building software is inherently complex. In today’s world, we often talk about packaging and shipping software using
methodologies like DevOps—or even DevSecOps. Cloud infrastructure has become central to this process, and tools
like Docker and Kubernetes have grown increasingly important. For most modern software engineers, these tools and 
workflows (such as Continuous Integration for example), are essential for turning source code into a finished, 
deliverable product.

In this course, we will look at the internals, the fundamentals and the foundations. And once again, at the end of the
day, everything is a process and a file on a device.

Depending on the programming environment and language you use, there are different approaches to how the end result, in this case a running process, actually comes to be.

Let’s begin by looking at web servers, as they’re everywhere these days. When dealing with HTML, CSS, and JavaScript, 
it’s primarily about working with files and placing them on a web server. The software developer writes the source code,
and those exact files are then placed in a specific directory on the server (for example: `/var/www/html`). At that
point, the developer’s job is essentially done.

However, one crucial step remains: setting up and configuring the web server itself. Software like Nginx or Apache 
consists of files which, once launched, become processes responsible for serving the static content.

From a security point of view, HTML/CSS/JS are relatively easy to inspect/investigate, as everything on the client side
is human-readable—even in a standard browser. While some **obfuscation** may be applied, it's still possible to read
and analyze the code.

Still on the web, there are many more languages. Python, Ruby, Go, RUST, and others can of course be used to create 
websites. Before tackling those languages, let’s briefly discuss server-side JavaScript (Node.js) and PHP. In those 
cases you need access to the actual source files to investigate the code, because server-side sources aren’t exposed to
the client (the browser). When you do have the source files, they’re typically plain text, which makes them
straightforward to review from a security perspective.


If we look at the other programming languages we typically can divide them into 2 categories 
(or a combination of the 2). These are languages that get **interpreted** and languages that are **compiled**. Another
often used set of terms is **managed** and **unmanaged** code.

Take Python and Ruby, for example. These are languages that use an interpreter, and are therefore called interpreted
languages. Python files are executed line by line at runtime, meaning no significant optimization is done ahead of time.
As a result, these languages are typically slower compared to compiled languages like C, C++, or RUST.

Java and C# use a combination of both interpreted and compiled approaches. One of their key selling points is
cross-platform compatibility, which they achieve by compiling the source code (e.g., .java files) into an intermediate
language. This intermediate code is then executed by a separate piece of software known as a virtual machine. This 
virtual machine is not the same as a full system VM like VMware Workstation Pro or VirtualBox. Instead, it's a runtime
environment designed specifically to execute the intermediate code—the
JVM (Java Virtual Machine) for Java and the .NET runtime for C#.

Because of this setup, both Java and C# applications can often be **decompiled** relatively easily, allowing access to
source code that is quite close to the original.

In contrast, compiled languages that **translate directly to CPU instructions**,like C(++) and RUST are much more
difficult to reverse-engineer or analyze. Let’s take a closer look at C and C++ as examples.


## Building software in c(++)

So program code is written in .c or .cpp files. These are the source code files. This is actually not needed but a 
standard and best practice. In C and C++ we also have .h files called header files. Not important for us but typically
both are needed for a C(++) developer. 

In C and C++, program code is typically written in .c or .cpp files—these are the source code files. While these file
extensions are not strictly required by the compiler, it's a well-established standard and best practice. Paired with 
these  C and C++ also use .h files, known as header files. These aren't particularly important for our purposes here,
but they are commonly used alongside source files and are essential in typical C/C++ development workflows.

C++ programs are compiled into binary executable files that are run directly by the CPU—unlike Java, which runs on a
virtual machine, or Python, which is executed by an interpreter. Be very mindful of this distinction!

This approach typically results in faster execution, but often comes at the cost of lower-level programming, where the 
developer must handle more complex tasks such as manual memory management and system-specific behavior.

To compile C or C++ code, you need a compiler. The three most commonly used compilers are **gcc, Clang, and Visual 
Studio.** If you are working on Windows, you can use Visual Studio (not VS Code) to compile and run your C programs.
On Linux, you can use either gcc or Clang. We will use gcc. Check if it is installed on your system, and if it 
isn’t, install it.


### C(++) compilation process

Steps in the build pipeline:


1.	Preprocessing (gcc -E): This handles #include, #define, #if macros and will output pure C code. You can
think of this a  big "find and replace tool"
2.	Compilation (gcc -S): Translates preprocessed C into assembly.
3.	Assembly (as or gcc -c): Converts assembly into object code (.o / .obj).
4.	Linking (gcc): Combines object files and libraries --> final executable.

This means that a compiler error and a linker error are 2 completely different problems that require 2 different
approaches.


## Hands-on exercises

Note: all exercises have been tested on a debian virtual machine. Do these on a linux based VM! 

### Exercise 1: Hello World Build Pipeline

Create a source file called "hello.c" which has the following content:

```c
#include <stdio.h>

int main() {
    printf("Hello, world!\n");
    return 0;
}
```

Now use the gcc compiler to convert then c code into an executable file. Execute the following commands in order, for each end result inspect the created file using the **file** and the **cat** command.

 Ask yourself the following 
**questions**:

- What does the linux `file` command says about each file, what is the type? 
- Which are human-readable?
- Can you tell what each result represents?


**Commands**:
```bash
gcc -E hello.c -o hello.i       # Preprocessing
gcc -S hello.i -o hello.s       # Compilation -> assembly
gcc -c hello.s -o hello.o       # Assembly -> object code
gcc hello.o -o hello            # Linking -> executable
./hello                         # Run process
```

hello -> not human readable

hello.i -> human readable

hello.o -> not human readable

hello.c -> human readable



### Exercise 2: 32 bit + inspect assembly

First install the following packages to enable 32 bit support. 
```bash
sudo apt install gcc-multilib g++-multilib
```
Then test this by doing the following:

```bash
gcc -m32 hello.c -o hello32
gcc -S -m32 hello.c -o hello32.s

```

We will not dive into  assembly details just yet, but do compare the 2 assembly files, ask yourself the following 
questions. 

- Which one has the most lines?

  The 32 bit one
- Can you spot the "hello world" string in both files?

​	Yes!



### Exercise 3: multiple files and linking
Create the following files, add.c and main.c. Make sure they are located in the same folder

add.c contains the following code:
```c
int add(int a, int b) {
    return a + b;
}
```

main.c contains the following code:
```c
#include <stdio.h>

int add(int, int);

int main() {
    printf("%d\n", add(2, 3));
    return 0;
}
```

Now do the following command again. 
```bash
gcc -c -m32 add.c -o add.o
gcc -c -m32 main.c -o main.o
gcc -m32 add.o main.o -o program
./program
```

Congrats you just build and compiled your first 32-bit program all by yourselves! Let's play around with this for a bit.
Try and answer the following questions **before** executing each command. Try and understand why something works or 
doesn't work. 

**Questions**

- Remove the final `./program` file. And perform the last command again but remove "add.o". In other words we will use 
  code from an object file, but in our linking stage we forget to include it. What error do you receive? What executable 
  is actually causing the error? Is it gcc? The program should be printed in the error message.

  ​	I would guess you'd get add is not defined by the program executable

  ​	> It was /usr/bin/ld  (what I'd guess stands for Linker Deamon -> I was right :) ) 


If You can also directly use the linker instead of `gcc -m32 add.o main.o -o program` an example could be:

```bash
ld -m elf_i386 \
  /usr/lib32/crt1.o /usr/lib32/crti.o add.o main.o /usr/lib32/crtn.o \
  -L/usr/lib32 -lc \
  -dynamic-linker /lib/ld-linux.so.2 \
  -o program
```

Let's appreciate gcc for doing all the hard work for us (gcc knows where the right libraries are installed)

- Next, run all 3 commands again but drop the -m32 option for one of the commands. What error do you get and why? 

​	`architecture of input file main.o' is incompatible with i386 output`

-> Because all files must be in the same architecture



### Exercise 4: object inspection

Even if you don't have the source code, machine instructions can be read, as this is the binary data the program 
actually holds. It's **"how it works"**. We will come back to these things in a later lecture when we will be talking 
about Assembly code but for now let's try this out.


```bash
objdump -d -M intel program
```

**Questions**

- Take a look at the output. The first "column" is again an offset in the file, next we see instructions formatted as
hexadecimal values and finally on the right side the actual Assembly instructions they represent. You should have
a bit of flashbacks to xxd with the magic bytes!
- Can you spot something about the add function?
	Yes! <add> will be the function
  
- Can you spot something related to printf? 
	Yes also the function: <printf@plt>



### Exercise 5: Comparing to Python

Python is a language that gets interpreted by the Python interpreter. Analysing Python programs is therefore actually
pretty simple as all you have to do is open the Python files. It is however possible to compile Python! In that case it
works similar to Java.

hello.py

```python
print("Hello, world!")
```

Steps:
```bash
python3 -m py_compile hello.py
ls __pycache__/
python3 __pycache__/hello.cPython-311.pyc # or another name if you have another version installed
```

**Questions**

- What does `file` tell you about the .pyc file?

  ​	It's a compiled Python module

- Do we still have the expected output? In other words does the Python compiled code properly runs when using Python?

  ​	Yes!

- Is the .pyc human-readable? Is it still Python code?

  ​	No it's compiled code

- Are you able to use the `objdump` command from before on this .pyc file?

  ​	No, file format not recognized

**Important to remember:** The Python bytecode (the .pyc file) does not directly run on the CPU. It uses a runtime environment (the Python virtual machine) to execute the Python bytecode! 

