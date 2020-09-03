set -x
objcopy -O elf32-i386 ./out/Release/node node.elf32
scp ./node.elf32 10.255.15.3:/var/lib/tftpboot/ebbrt.elf32
ssh kznbmi hil node power cycle neu-5-9
