/*  Bypass frida detection in memory, default file locations and running processes
    Created by Koen Koreman
*/

const libc = Process.getModuleByName('libc.so');

function hookLibcFunction(funcName) {
    const funcPtr = libc.getExportByName(funcName);
    Interceptor.attach(funcPtr, {
        onEnter(args) {
            this.funcName = funcName;
            if (funcName === 'read') {
                this.buf = args[0];
                try {
                    const str = Memory.readUtf8String(this.buf);
                    console.log(`Memory value: $(str)`);
                    if (str.search('frida') !== -1) {
                        this.frida = true;
                    }
                } catch (e) {
                    this.frida = false;
                }
            } else if (funcName === 'strstr') {
                this.haystack = args[0].readUtf8String() ?? "";
                this.needle = args[1].readUtf8String() ?? "";
                if (this.haystack.search("frida") !== -1 || this.needle.search("frida") !== -1 || this.haystack.search("su") !== -1 || this.needle.search("su") !== -1) {
                    this.frida = true;
                }
            
            } else if (funcName === 'stat' || funcName === 'access') {
                    this.haystack = args[0].readUtf8String() ?? "";
                    this.needle = args[1].readUtf8String() ?? "";
               if (this.haystack.search("frida") !== -1 || this.needle.search("frida") !== -1 || this.haystack.search("su") !== -1 || this.needle.search("su") !== -1) {
                    this.frida = true;
                }
            }
        },
        onLeave(retval) {
            if (this.funcName === 'read' && this.frida) {
                retval.replace(0);
            }
        }
    });
}

['read', 'stat', 'access', 'strstr'].forEach(hookLibcFunction);

Java.perform(function() {
    var BufferedReader = Java.use('java.io.BufferedReader');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    var InputStream = Java.use('java.io.InputStream');
    var Scanner = Java.use('java.util.Scanner');

    ProcessBuilder.start.implementation = function() {
        var p = this.start();
        return p;
    };
    
    BufferedReader.readLine.overload().implementation = function() {
        var line = this.readLine();
        if (line !== null && line.search("frida") !== -1) {
            return "";
        }
        return line;
    };

    InputStream.read.overload('[B', 'int', 'int').implementation = function(bArr, off, len) {
        var bytesRead = this.read(bArr, off, len);
        if (bytesRead > 0) {
            try {
                //var buf = Java.array('byte', bArr);
                var raw = Java.use('java.lang.String').$new(bArr, off, bytesRead);
                if (raw.search('frida') !== -1) {
                    return 0; 
                }
            } catch (e) {
            }
        }
        return bytesRead;
    };

    Scanner.nextLine.implementation = function() {
        var line = this.nextLine();
        if (line.search('frida') !== -1) {
            return "";
        }
        return line;
    };    
});