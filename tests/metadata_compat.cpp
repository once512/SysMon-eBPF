// SPDX-License-Identifier: MIT
// A libc-free i386 requester: exercises the actual compat syscall/LSM path
// without requiring 32-bit libc development packages on the x86_64 host.
static int syscall3(int number, int a, int b, int c)
{
    int result;
    asm volatile("int $0x80" : "=a"(result) : "0"(number), "b"(a), "c"(b), "d"(c) : "memory", "cc");
    return result;
}
static void emit(int number)
{
    char digits[16]; unsigned length = 0;
    do { digits[length++] = '0' + number % 10; number /= 10; } while (number);
    for (unsigned i = 0; i < length / 2; ++i) {
        const char old = digits[i]; digits[i] = digits[length - i - 1]; digits[length - i - 1] = old;
    }
    digits[length++] = '\n'; syscall3(4, 1, reinterpret_cast<int>(digits), length);
}
extern "C" int compat_main(int argc, char **argv)
{
    if (argc != 3) return 22;
    const int target = syscall3(5, reinterpret_cast<int>(argv[1]), 2, 0);
    const int victim = syscall3(5, reinterpret_cast<int>(argv[2]), 2, 0);
    if (target < 0 || victim < 0) return 1;
    const char ready[] = "ready\n"; syscall3(4, 1, reinterpret_cast<int>(ready), 6);
    char op = 0, byte;
    while (syscall3(3, 0, reinterpret_cast<int>(&byte), 1) == 1) {
        if (byte != '\n') { if (!op) op = byte; continue; }
        if (op == 'q') break;
        int result = -22; int flags = 0;
        if (op == 'g' || op == 'i') {
            result = syscall3(54, target, 0x80046601U, reinterpret_cast<int>(&flags));
            if (!result && op == 'i') {
                flags ^= 0x40;
                result = syscall3(54, target, 0x40046602U, reinterpret_cast<int>(&flags));
            }
        } else if (op == 'w' || op == 'v') {
            const char content = 'W';
            result = syscall3(4, op == 'w' ? target : victim, reinterpret_cast<int>(&content), 1);
        } else if (op == 'u') result = syscall3(54, target, 0xdeadbeefU, 0);
        emit(result < 0 ? -result : 0); op = 0;
    }
    return 0;
}
asm(".global _start\n.type _start,@function\n_start:\n"
    "xorl %ebp,%ebp\n popl %eax\n movl %esp,%edx\n"
    "andl $-16,%esp\n subl $8,%esp\n pushl %edx\n pushl %eax\n"
    "call compat_main\n movl %eax,%ebx\n movl $1,%eax\n int $0x80\n");
