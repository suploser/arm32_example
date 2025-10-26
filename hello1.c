#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <dlfcn.h>

/*
栈

$-64
$-60
$-5C
$-58
$-54      cpsr    <---sp nakeFun
$-50      r0
$-4C      r1
$-48      r2  
$-44      r3
$-40      r4
$-3C      r5
$-38      r6
$-34      r7
$-30      r8  
$-2C      r9 
$-28      r10  
$-24      r11  
$-20      r12  
$-1C      lr  
$-18      pc  
$-14      r0        <---sp fopen
$-10      r1  
$-C       r4 
$-8       r5
$-4       r6  
$==>      lr        <---fopen in
$+4       
$+8       
$+C        
$+10      
$+14       
$+18         
$+1C     
$+20            
$+24
$+28
$+2C
$+30
$+34
$+38
$+3C
$+40
$+44
$+48
$+4C
$+50
$+54
$+58
$+5C
$+60
$+64


*/
uint32_t ret_addr;
uint32_t arg0;
uint32_t arg1;
// hook fopen
void __attribute__((naked)) nakeFun()
{
     asm("STMFD sp!, {R0,R1,R4-R6,LR}");  //fopen --> PUSH  {R0,R1,R4-R6,LR}
     asm("STMFD sp!, {R0-R12,LR,PC}");
     asm("mrs r0, cpsr");
     asm("STMFD sp!, {R0}");

     asm("ldr r4,[sp,#4]");
     asm("str r4, %0":"=m"(arg0));  //写全局变量
                                    // LDR             R0, =(arg0_ptr - 0x630)
                                    // LDR             R0, [PC,R0] ; arg0
                                    // STR             R4, [R0]
     asm("ldr r4,[sp,#8]");
     asm("str r4, %0":"=m"(arg1)); 
                                    // LDR             R0, =(arg1_ptr - 0x640)
                                    // LDR             R0, [PC,R0] ; arg1
                                    // STR             R4, [R0]
     //fopen -->mov r6, r0
     asm("ldr r0, [sp,#4]");
     asm("str r0, [sp,#0x1c]");
     //fopen -->mov r0,r1
     asm("ldr r0, [sp,#8]");
     asm("str r0, [sp,#4]"); 
     //fopen -->add r1, sp, #4
     asm("mov r0, sp");
     asm("add r0, r0, #0x44");  //sp = sp fopen
     asm("str r0, [sp,#8]");

     // return fopen
     asm("ldr r0, %0"::"m"(ret_addr));    //读全局变量
                                          // LDR             R0, =(ret_addr_ptr - 0x668)
                                          // LDR             R0, [PC,R0] ; ret_addr
                                          // LDR             R0, [R0]
     asm("str r0,[sp,#0x3c]");
    
     asm("LDMFD sp!, {R0}");
     asm("msr cpsr, R0");
     asm("LDMFD sp!, {R0-R12,LR,PC}");
}

int main()
{
     void *hand = dlopen("libc.so", RTLD_NOW);
     void *hook_addr = dlsym(hand, "fopen");
     mprotect((void*)((uint32_t)hook_addr & 0xfffff000), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
    printf("%p\n", hook_addr);  
    
    *(uint32_t *)((uint32_t)(hook_addr)-1) = 0xf000f8df ; // LDR PC,[PC]
    *(uint32_t *)((uint32_t)(hook_addr)-1 + 4) = (uint32_t)nakeFun;
    
     ret_addr = (uint32_t)hook_addr - 1 + 8 + 1; //arm -> thumb 返回地址
     
     getchar();

     FILE *fp = fopen("/data/user/android_server", "rb");
     uint32_t data;
     fread(&data, 4, 1, fp);
     fclose(fp);
     printf("data:%08x\n", data);
     printf("arg0:%s\n", arg0);
     printf("arg1:%s\n", arg1);
     return 0;
}
/*
uint32_t x = 0x1234;

int fun(int a, int b, int c, int d, int e, int f){
     int n = d + e;
     printf("%d\n", a);
     return n;
} 

int main(){
     int n = 10;
     fun(1, 2, 3, 4, 5, 6);


     // while(1){
     // printf("hello");
     // getchar();
     // }
     getchar();
     return 0;    
}
*/
// r11 栈帧指针
// r12 导入表寻址
// r0-r3 函数前四个参数，其余的参数通过栈传递 易变寄存器
// r4-r11 非易变寄存器
// 函数返回值存放在r0寄存器中

/*
栈

$-64
$-60
$-5C
$-58
$-54
$-50
$-4C
$-48
$-44
$-40
$-3C
$-38
$-34
$-30        ret_printf(r0)           <-- sp fun 
$-2C        5(e)
$-28        6(f)
$-24        n=d+e
$-20        R3(d)                   寄存器传参在栈复制一份
$-1C        R2(c)
$-18        R1(b)
$-14        R0(a)
$-10        R4
$-C         R10
$-8         R11        <-- R11
$-4         LR
$==>        5(e)       <-- fun in   
$+4         6(f)
$+8         ret_getchar
$+C         ret_fun(n=d+e)
$+10        10(n) 
$+14        0
$+18        R11    <-- R11
$+1C        LR
$+20               <-- main in
$+24
$+28
$+2C
$+30
$+34
$+38
$+3C
$+40
$+44
$+48
$+4C
$+50
$+54
$+58
$+5C
$+60
$+64


*/