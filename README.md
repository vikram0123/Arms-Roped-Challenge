# Arms-Roped-Challenge
The ARMS ROPED challenge is a binary exploitation challenge that involves bypassing the stack canary, address randomization (ASLR), and non-executable stack to achieve code execution by utilizing the Return-Oriented Programming (ROP) technique.

The first series includes analysis at the binary level: participation in binary examination by the
use of Ghidra tools to understand the architecture and functionalities of the
"arms-roped" binary file. Analysis was conducted at both static and dynamic levels to identify
any vulnerability that might arise.
Tools and Techniques Used:
Ghidra: Utilized for comprehensive binary analysis to understand
its functionalities.
2. Static and Dynamic Analysis Techniques: Applied to identify potential
vulnerabilities within the binary code.
Ppt
1. Dynamic Analysis with GDB: Using GDB, a debugging tool, the program is examined more closely while it's running. This helps in identifying exactly how data is handled in memory and to confirm if a buffer overflow can indeed be triggered.
Dynamic analysis using GDB (GNU Debugger) in the ARMS ROPED challenge involves a detailed process of examining how a binary program behaves during execution, particularly focusing on exploiting vulnerabilities. Here's a brief overview of the dynamic analysis steps described in the challenge:
**Setup**: The analysis uses a combination of GDB with qemu and gdb-multiarch to handle the ARM architecture binary. This setup allows running the ARM binary on non-ARM hardware and provides a way to debug it interactively.
2. **Attaching to GDB**: The binary is run under qemu, and gdb-multiarch is connected to it. This is done by setting the appropriate library paths and port bindings to ensure gdb can control the execution of the qemu session running the binary.
3. **Analyzing the Program**: 
   - **Setting a Breakpoint**: After identifying that the binary is vulnerable to a buffer overflow (from the static analysis phase), a breakpoint is set just after the `memcpy` operation in the `string_storer` function. This operation is where the overflow vulnerability can potentially be triggered.
   - **Triggering the Buffer Overflow**: Input is provided to the program through qemu to reach the breakpoint and potentially overflow the buffer.
4. **Investigating the Stack**: Once the breakpoint is hit, the state of the stack is examined. This includes:
   - Observing the canary (a security measure to detect buffer overflows) and its position relative to other elements like the return address.
   - Looking for any anomalies that might indicate successful buffer manipulation, such as unexpected values or addresses that should not logically be in the stack at that point.
5. **Leaking Information**: By carefully manipulating the input to overflow specific parts of the buffer, it is possible to leak sensitive information such as the canary value or memory addresses (like libc addresses). This information is critical for bypassing further security measures and achieving a successful exploit.
6. **Verification**: To confirm that the overflow and information leakage are functioning as intended, additional data is sent to overwrite the canary. If the program crashes (indicating a "stack smash"), it confirms that the canary was successfully overwritten.

This dynamic analysis approach is critical for understanding exactly how data is handled in memory and for validating the theoretical exploits identified during static analysis. This practical, hands-on investigation helps to refine the exploit techniques needed to take control of the program's execution.
