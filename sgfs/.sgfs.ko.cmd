cmd_fs/sgfs//sgfs.ko := ld -r -m elf_x86_64 -T ./scripts/module-common.lds --build-id  -o fs/sgfs//sgfs.ko fs/sgfs//sgfs.o fs/sgfs//sgfs.mod.o
