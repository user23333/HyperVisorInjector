# HyperVisor-Injector
- Tested on Windows 10 20h2 : OS Build 19042.1586
# LEAVE A STAR IF IT WORKED FOR YOU ( 200 star for new injector release )
# last Updated 12/01/2023


# If you are interested purchasing my private sources or want your own developed you can contact me via discord : 0x254#0940
- this is perfect if you are starting up a p2c 



# before using you must do this
Please enable hyper-v in "turn windows features on or off". Then run launch.bat as admin, this will mount the EFI partition and move some files around then reboot you. Voyager is designed to recover from a crash. The first thing Voyager will do when executed is restore bootmgfw on disk. If any complications occur during boot you can simply reboot.

<img src="https://imgur.com/uOpcCp7.png">


public version supports 64bit games only

       
# active updates + changes to keep this undetected and safe to use !
# version 4.0
- Easy Anti Cheat Status : 🟢
- EAC Eos Status : 🟢
- Battleye Status : 🟢
- Vanguard Status : 🟢
- BattleEye Status : 🟢
- Riochet Status : 🟢


## [ How To Use Injector ? ] 

make sure your dll is in the same folder 
**re-name** your dll to **test.dll** if not it wont inject
**the dll must be in the same folder as the injector**
- **have your game open** 
-  **Open the injector -> then type out your game ( if this doesnt work type the window class name ) **
-  **hit enter key after you have typed it out then wait for it to inject**

[![Video Of Injection]](https://streamable.com/gyqihv)


# having issues on Windows 11 ?
- type this as admin in cmd
- reg add HKLM\SYSTEM\CurrentControlSet\CI\Config /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d 0 /f
- reg add HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity/v "Enabled" /t REG_DWORD /d 0 /f

To apply the changes, you will need to reboot the system.


## How to find the class to inject into ?
- head over to https://www.nirsoft.net/utils/winlister.html and download winlister x64 or x32
- open it up look for your process for my example i will use notepad
- double click on the process that you are wanting to inject into 
- then find Class: and copy that and paste it into the injector 
<img src="https://i.ibb.co/BL79h5h/tempsnip.png">




## Supports Intel + Amd Cpu's


## Multiple Injection methods To Choose
- Manual Map
- load libary
- x86 / x64 support
- APC Injection
- SetWindowsHook ( uses window class name to inject )
- RWX Injection


## Injection - > extra information
- CreateRemoteThread
- NtCreateThreadEx
- RtlCreateUserThread
- Delayed Injection ( choose how long you want to delay it for in )
- Changes Started Thread's Start Address
- Create Threads + Detours can be used within your dll
- Clears Loaded Module's PE Headers
- Changes Started Thread's Start Address



# other stuff
- Simple Display Of Imports Found From File
- Information Displayed: RVA, Original First Thunk, Name Of Module, Name Of Imported Function ( Remember that this is being parsed through file, not through running process )

# process 
- Simple Table For Processes
- Info Displayed: PID, EXE Name, Window Name, Ram Used and Full Path
- Allows You To Switch To NtQueryVirtualMemory For Checking Loaded Modules


## Requirements
- C++ Redistributables 2015, 2017, 2019, and 2022 
- download at https://www.microsoft.com/en-gb/download/details.aspx?id=48145

# Remote code execution
- Execute functions in remote process
- Assemble own code and execute it remotely
- Support for cdecl/stdcall/thiscall/fastcall conventions
- Support for arguments passed by value, pointer or reference, including structures
- FPU types are supported
- Execute code in new thread or any existing one



##  WHAT IS THE BENIFITS THAT COME WITH BUYING PRIVATE SOURCE CODE?
- It is fully private source code and you will be given a complete Hypervisor with instructions + help and support needed to get everything set up and working

- UI Mode ( imgui mode of the injector )
- you can use detours + minhook
- decrypt offsets ( rainbow 6, warzone )
- choose what injection format you want x86 / x64
- IAT dumper
- cheat engine support + other debuggers
- offset dumper
- inject without any detections
- have a full private source code ( fully undetected + Secure source code )
- can hold hundred of users at one time
- custome builds 
- panel api + loader for the hypervisor ( if you are wanting to have a secure loader for p2c and secure method of loading )


## Questions ?
- Q: does it work for all games | A: yes this does works for all games 
- Q: can i create threads in my dll? | A: Yes since we emulate anticheats with this injector you can create threads
- Q: Is there a risk of me using this ? | A: Of course there is as anything public can become detected 
- Q: If i purchase do i get the same source as the public version | A: No you get a completly private source code that only you will have

