================================================
[ultimet] - The ultimate meterpreter executable.
================================================
  ...your one stop shop for all your
              meterpreter executable needs...

Usage, examples and faq http://eldeeb.net/wrdprs/?p=176

---------------
1. Introduction
---------------
  - Stand-alone meterpreter executables that are created using (msfpayload/msfvenom) are not flexible in selecting the LHOST, LPORT or even the transport after being created ... i.e. once you create the exe, you cannot change any of the settings you specified during the creation of the executable.

  - Meterpreter by design is a "staged" payload, it consists of a "stager" and a "stage"; when msfpayload|msfvenom create an exe, that's the "stager" part of meterpreter, which has only one purpose: When executed, connect back to the exploit/multi/handler, make room for the stager, copy the "stage" from handler, then execute the "stage" ... that "stage" is nothing but a patched version of "metsrv.dll" that you find in metasploit directory ... this scenario presents a challenge in highly secure environments(!) where incoming files from the internet are checked for viruses `:)` ...  example: someone created a meterpreter/reverse_http exe using msfvenom, then he manages to bypass AV somehow and successfully executed this exe on one machine inside the target environment, if there's some kind of virus checking of downloaded files at the gateway/proxy level ... the "stage" gets flagged, not downloaded, not executed, and you're doomed.

-------------------
2. What is ultimet?
-------------------
  - ultimet is a flexible "meterpreter" exe that takes LPORT, LHOST, TRANSPORT and many other options as command line arguments.
  - It supports multiple options to include the "stage" with the exe, turning it into a single stage "inline" meterpreter.
  - It is NOT a payload "i.e. you can't use it as a shellcode for an exploit", it's a stand-alone exe.

------------------------------------------------
3. What are the supported transports (payloads)? 
------------------------------------------------
- It supports "reverse_tcp", "bind_tcp", "reverse_http", "reverse_https" and "bint_metsvc & reverse_metsvc <- when stage included". 

---------------------------------------
4. How exactly is the stage "included"? 
---------------------------------------
- The "stage" can be loaded using any of the following options:
  - From a resource, or an encrypted resource that is included in the exe itself.
  - From a file (metsrv.dll), or an encrypted file.
  - ... if stage is not available, stage gets loaded over the network, which is basically falling back into "stager-mode".

------------------
5. inmet & ultimet 
------------------
The zip file contains two exe, inmet & ultimet:
- inmet is (ultimet + stage as a resource) that is the (exe) that has the (stage as a resource).
- ultimet is (inmet - stage as resource) that is JUST THE EXE.
- so, if you used any PE resource editor to crack open inmet.exe, you'll find a resource called "BINARY" and ID "101", if you deleted that resource, it will still work, but as a stager only.
- ... if you took that "stripped-down" exe again, opened it, and imported metsrv.dll (or the encrypted version of it)  into that exe, called the resource "BINARY" and set the ID to "101" ... it will become an inline exe again.
- inmet and ultimet are SAME EXECUTABLE that detects when it's just a mere stager, or the inline version of the executable.
- Got it? ... if not just download both and try to figure out the difference on your own ...

---------------
6. Encryption?! 
---------------
- ultimet will load metsrv.dll if it is plain (the one in your computer) or encrypted using the following scheme:
    - XOR every byte % a random 16-bytes key (position = i % 16; metsrv[i] ^=  key[position])
    - PREPEND the whole encrypted metsrv.dll with the 16 bytes random key :)
- FIPS compliant, strong and unbreakable encryption, I know, thank you ... but it gets the job done pretty well "AV sig change".
- A tool is included that does this automatically (ultimet_xor.exe) ... just drag metsrv.dll over it and you'll get a file called "encrypted.rsc" ... import that into ultimet.exe, they'll know how to play nice with each other.

---------------
7. Known issues 
---------------
- Currently the ReflectiveDLL bootstrap has the RVA_to_file offset of the ReflectiveLoader  hardcoded, so, you cannot use your own metsrv.dll if that offset is different without changing the offset in "constants.h" ... working on it.
- If your linker complained about not finding "encrypted.rsc" ... open "inmet.rc" using a text editor, and hard code the path there "or just put it on the root of your "e:\" drive ... to lazy to fix that and VS can be a **** sometimes.

----------------
8. Bug reporting 
----------------
- Github
- ultimet@eldeeb.net

---------
9. Author 
---------
- Sherif Eldeeb
- http://eldeeb.net
- @SheriefEldeeb
- archeldeeb@gmail.com
Made in Egypt.

... P.S: I am not a developer ;)

-------------------
10. Contributors:
-------------------
- Anwar Mohamed "@anwarelmakrahy"
  Added support for metsvc_bind_tcp & bind_tcp.
  
-------------------
11. Acknowledgments
-------------------
- All the extremely helpful people at #metasploit, and the mailing list:
hdm, corelanc0d3r, mihi, egypt, kernelsmith, tillo.
- Stephen Fewer for helping with ReflectiveDll stuff.
- @lnxg33k, @anwarelmakrahy & Yehia Mamdouh: for testing and bug reporting.




