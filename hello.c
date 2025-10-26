#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <elf.h>

// #define MAYBE_MAP_FLAG(x,from,to)    (((x) & (from)) ? (to) : 0)
// #define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
//                                       MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
//                                       MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

#define PAGE_SIZE 4096
#define IMAGE_BASE 0x80000000
char *image_buf = NULL;

unsigned len;
unsigned char *tmp;
unsigned char *pbase;
unsigned char *extra_base;
unsigned extra_len;
unsigned total_sz = 0;


int main(int argc, char** argv){
    FILE *fp = fopen("/data/user/myls", "rb");
    image_buf = malloc(0x1000);
    fread(image_buf, sizeof(Elf32_Ehdr), 1, fp);
    Elf32_Ehdr *elf_hd = (Elf32_Ehdr *)image_buf;

    printf("e_phoff:%08x\n", elf_hd->e_phoff);
    fseek(fp, 0, SEEK_SET);
    fread(image_buf, elf_hd->e_phoff + sizeof(Elf32_Phdr)*elf_hd->e_phnum, 1, fp);
    Elf32_Phdr *phdr = (Elf32_Phdr *)(elf_hd->e_phoff + image_buf);
    //elf file mapped to memory by the mmap fun
    //only loaded segment which p_type is PT_LOAD (1) , its include all file (section data is not include)
    for (int i = 0; i < elf_hd->e_phnum; i++,phdr++)
    {
        if (phdr->p_type == PT_LOAD) {
            tmp = (unsigned char *)IMAGE_BASE + (phdr->p_vaddr & (~0xfff));
            len = phdr->p_filesz + (phdr->p_vaddr & 0xfff);
            pbase = mmap((void *)tmp, len, 
                        PROT_EXEC | PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_FIXED, fileno(fp),
                        phdr->p_offset & (~0xfff));

            /* If 'len' didn't end on page boundary, and it's a writable
             * segment, zero-fill the rest. */
            if ((len & 0xfff) && (phdr->p_flags & PF_W)){
                memset((void *)(pbase + len), 0, PAGE_SIZE - (len & 0xfff));
            }

            total_sz = (unsigned)((((unsigned)IMAGE_BASE + phdr->p_vaddr + phdr->p_memsz +
                    PAGE_SIZE - 1) & (~0xfff)) - (unsigned)pbase);
            printf("mapped addr: 0x%08x, loaded segment size: 0x%08x, file size: 0x%08x\n", (unsigned)pbase, total_sz, phdr->p_filesz);

            
            tmp = (unsigned char *)(((unsigned)pbase + len + PAGE_SIZE - 1) & (~0xfff));
            if (tmp < ((unsigned char *)IMAGE_BASE + phdr->p_vaddr + phdr->p_memsz))
            {
                extra_len = (unsigned char *)IMAGE_BASE + phdr->p_vaddr + phdr->p_memsz - tmp;
                extra_base = mmap((void *)tmp, extra_len,
                                  PROT_EXEC | PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                                  -1, 0);
                printf("last loaded segement exists extern addr: 0x%08x, extern len: 0x%08x\n", (unsigned)extra_base, extra_len);
            }
            printf("the no.%0x segment mapped ok\n", i+1);
        }
    }
    //关闭文件，释放buf,
    // 文件映射内存完成
    fclose(fp);
    free(image_buf);
    // DT_SYMTAB = 6
    // DT_STRTAB = 5
    // DT_REL = 17
//    DT_REL 

    printf("mapped ok!\n");
    // getchar();
    phdr = (Elf32_Phdr *)(IMAGE_BASE + elf_hd->e_phoff);
    //dynamic segment  !!! this is important !!!
    uint32_t *dyn_entry, *p;
    for (int i = 0; i < elf_hd->e_phnum; i++, phdr++)
    {
        if (phdr->p_type == PT_DYNAMIC)
        {
            dyn_entry = (uint32_t *)(IMAGE_BASE + phdr->p_vaddr);
            printf("Dyn_entry: %p\n", dyn_entry);
            break;
        }
        
    }
    //字符串表 类型：DT_STRTAB
    char *str_tab;
    p = dyn_entry;
    while (*p)
    {
        if (p[0] == DT_STRTAB)
        {
            str_tab = (char *)(IMAGE_BASE + p[1]);
            printf("Str_tab: %p\n", str_tab);
            break;
        }
        p += 2; 
    }
    //导入库表 类型：DT_NEEDED
    printf("============needed libs============\n");
    p = dyn_entry;
    char *needed_so;
    void *needed_so_addr[256];
    int needed_so_index = 0;
    while (*p)
    {
        if (p[0] == DT_NEEDED)
        {
            needed_so = str_tab + p[1];
            needed_so_addr[needed_so_index] = dlopen(needed_so, RTLD_NOW);
            printf("%s, location: %p\n", needed_so, needed_so_addr[needed_so_index]);
            needed_so_index++;
        }
        p += 2; 
    }
    
    //符号表 DT_SYMTAB
     printf("============符号表============\n");
    // getchar();
    p = dyn_entry;
    Elf32_Sym *sym_tab;
    while (*p)
    {
        if (p[0] == DT_SYMTAB)
        {
            sym_tab = (Elf32_Sym *)(IMAGE_BASE + p[1]);
            printf("sym_tab: %p\n", sym_tab);
            break;
        }
        p += 2; 
    }
    // DT_GNU_HASH

    // //导入表 DT_JMPREL
    printf("============导入表============\n");
    p = dyn_entry;
    uint32_t *plt_rel;
    uint32_t plt_rel_sz;
    while (*p)
    {
        if (p[0] == DT_PLTRELSZ)
        {
            plt_rel_sz = p[1]/8;
        }
        if (p[0] == DT_JMPREL)
        {

            plt_rel = (uint32_t *)(IMAGE_BASE + p[1]);
            
        }
        p += 2; 
    }
    printf("plt_rel_tab: %p\n, size: %d", plt_rel, plt_rel_sz);
    p = plt_rel;
    uint32_t type;
    char *str;
    uint32_t addr_ptr;
    void *addr;
    void *org_addr;

    for (int i = 0; i < plt_rel_sz; i++)
    {
        type = p[1] & 0xff;
        addr_ptr = p[0] + IMAGE_BASE;
        str = str_tab + sym_tab[p[1]>>8].st_name;
        org_addr = (void *)(*(uint32_t *)(addr_ptr));
        // printf("type: 0x%x, var_str: %s, addr_ptr: %p, fixed_value: %p\n", type, str, (void *)addr_ptr);
        
        //模拟导出表链接导入表的过程，填写导入表中外部库函数及变量的地址
        if (type == 0x16)
        {
            // printf("type: 0x%x, str: %s, addr_ptr: %p\n", type, str, (void *)addr_ptr);
            for (int i = 0; i < needed_so_index; i++)
            {
               addr =  dlsym(needed_so_addr[i], str);
               if (addr)
               {
                    //在导入库表的列表中第一个找到导入函数后就不再继续查找
                    *(uint32_t *)(addr_ptr) = (uint32_t)addr;
                    break;
               }
               
            }
                        
        }
        printf("type: 0x%x, var_str: %s, addr_ptr: %p, org_value:%p, fixed_addr: %p\n", type, str, (void *)addr_ptr, org_addr, addr);
        
        p += 2;
    }
    
    // //重定位表 DT_REL 等价 与导入表的linker处理逻辑一致
    printf("============重定位表============\n");
    p = dyn_entry;
    Elf32_Rel *rel_tab;
    uint32_t rel_sz = 0x1;
    while (*p)
    {   
        if (p[0] == DT_RELSZ)
        {
            rel_sz = p[1]/8;
        }
        if (p[0] == DT_REL)
        {

            rel_tab = (Elf32_Rel *)(IMAGE_BASE + p[1]);
        }
        p += 2; 
    }
    printf("plt_rel_tab: %p, size:%d\n", rel_tab, rel_sz);
    uint32_t rel_type;
    char *rel_str;
    uint32_t rel_addr_ptr;
    void *rel_addr;
    void *org_value;
    for (int i = 0; i < rel_sz; i++)
    {
        rel_type = rel_tab->r_info & 0xff;
        rel_addr_ptr = (uint32_t)(rel_tab->r_offset + IMAGE_BASE);
        org_value = (void *)(*(uint32_t *)(rel_addr_ptr));
        if (rel_tab->r_info >> 8)
        {
            rel_str = str_tab + sym_tab[rel_tab->r_info >> 8].st_name;
        }
        //模拟导出表链接导入表的过程，填写导入表中外部库函数及变量的地址
        // printf("type: 0x%x, str: %s, addr_ptr: %p\n", rel_type, rel_str, (void *)rel_addr_ptr);
        if (rel_type == R_ARM_GLOB_DAT || rel_type == R_ARM_JUMP_SLOT || rel_type == R_ARM_ABS32) 
        {
            for (int i = 0; i < needed_so_index; i++)
            {
               rel_addr =  dlsym(needed_so_addr[i], rel_str);
               // && and
               if (rel_addr && rel_type != R_ARM_ABS32)
               {
                    *(uint32_t *)(rel_addr_ptr) = (uint32_t)rel_addr;
               }
               else
               {
                    *(uint32_t *)(rel_addr_ptr) += (uint32_t)rel_addr;
               }
            }
            printf("type:0x%x, var_str:%s, addr_ptr: 0x%x, org_value: %p, fixed_addr: %p\n", rel_type, rel_str, rel_addr_ptr, org_value, rel_addr);
            
        }
        else if (rel_type == R_ARM_RELATIVE)
        {
            *(uint32_t *)(rel_addr_ptr) += IMAGE_BASE;
            printf("type:0x%x, var_str:%s, addr_ptr: 0x%x, org_addr: %p, fixed_addr: %p\n", rel_type, rel_str, rel_addr_ptr, (void *)(*(uint32_t *)(rel_addr_ptr)-IMAGE_BASE), (void *)(*(uint32_t *)(rel_addr_ptr)));
        }       
        rel_tab++;
    }
    // R_ARM_GLOB_DAT
    // R_ARM_ABS32
    // R_ARM_RELATIVE
    //导出表
    // DT_GNU_HASH
    printf("============导出表============\n");
    p = dyn_entry;
    uint32_t nbucket;
    uint32_t *bucket;
    uint32_t *chain;
    while (*p)
    {   
        if (p[0] == DT_GNU_HASH)
        {
            nbucket = *(uint32_t *)(p[1] + IMAGE_BASE);
            bucket = (uint32_t *)(p[1] + IMAGE_BASE + 0x10 + ((uint32_t *)(p[1] + IMAGE_BASE))[2]*4);
            chain = bucket + nbucket - ((uint32_t *)(p[1] + IMAGE_BASE))[1];
        }
        p += 2; 
    }
    printf("nbucket: %x, bucket: %p, chain: %p\n", nbucket, bucket, chain);
    for (int i = 0; i < nbucket; i++)
    {
        uint32_t n = bucket[i];
        if (n)
        {
            printf("name: %s, addr: %p\n", str_tab + sym_tab[n].st_name, (void *)(sym_tab[n].st_value + IMAGE_BASE));
        }
        //与运算
        while ((chain[n] & 0x1) == 0)
        {
            n++;
            printf("name: %s, addr: %p\n", str_tab + sym_tab[n].st_name, (void *)(sym_tab[n].st_value + IMAGE_BASE));
        }
        
    }
    //程序入口 e_entry_START_ADDRESS , entry_point
    // "ls ps acpi等字符串都是【toybox】的elf程序的第一个参数的值，包含多个参数则用空格分隔"
    /*
    acpi base64 basename blkid blockdev bunzip2 bzcat cal cat chattr chcon
    chgrp chmod chown chroot cksum clear cmp comm cp cpio cut date dd
    df dirname dmesg dos2unix du echo egrep env expand expr fallocate
    false fgrep find flock free freeramdisk fsfreeze getenforce getprop
    grep groups head help hostname hwclock id ifconfig inotifyd insmod
    install ionice iorenice kill killall ln load_policy logname losetup
    ls lsattr lsmod lsof lsusb makedevs md5sum mkdir mkfifo mknod mkswap
    mktemp modinfo more mount mountpoint mv nbd-client nc netcat netstat
    nice nl nohup od partprobe paste patch pgrep pidof pivot_root pkill
    pmap printenv printf ps pwd pwdx readlink realpath renice restorecon
    rev rfkill rm rmdir rmmod route runcon sed seq setenforce setprop
    setsid sha1sum sleep sort split stat strings swapoff swapon switch_root
    sync sysctl tac tail tar taskset tee time timeout top touch tr traceroute
    traceroute6 true truncate tty ulimit umount uname uniq unix2dos uptime
    usleep vconfig vmstat wc which whoami xargs xxd yes
    */
    typedef int (*ENTRY_POINT)(int a, int b, int c, int d, int argc, char *argv, ...);
    ENTRY_POINT fun = (ENTRY_POINT)(0x6890 + IMAGE_BASE);
    char *para_str1 = "...//which";
    char *para_str2 = "which";
    // getchar();
    fun(0, 0, 0, 0, 2, para_str1, para_str2, 0, 0);
    getchar();
    return 0;
}
