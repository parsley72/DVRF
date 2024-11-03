/* common.h  -  Common functions */

/* Written 1993 by Werner Almesberger */


#ifndef _COMMON_H
#define _COMMON_H

void die(char *msg,...) __attribute((noreturn));

/* Displays a prinf-style message and terminates the program. */

void pdie(char *msg,...) __attribute((noreturn));

/* Like die, but appends an error message according to the state of errno. */

void *alloc(int size);

/* mallocs SIZE bytes and returns a pointer to the data. Terminates the program
   if malloc fails. */

void *qalloc(void **root,int size);

/* Like alloc, but registers the data area in a list described by ROOT. */

void qfree(void **root);

/* Deallocates all qalloc'ed data areas described by ROOT. */

int min(int a,int b);

/* Returns the smaller integer value of a and b. */

char get_key(char *valid,char *prompt);

/* Displays PROMPT and waits for user input. Only characters in VALID are
   accepted. Terminates the program on EOF. Returns the character. */

extern int filter_printf(const char *format, ...);
/*John@2010.03.05*/
#define _syscall5(type,name,atype,a,btype,b,ctype,c,dtype,d,etype,e) \
type name(atype a, btype b, ctype c, dtype d, etype e) \
{ \
        register unsigned long __a0 asm("$4") = (unsigned long) a; \
        register unsigned long __a1 asm("$5") = (unsigned long) b; \
        register unsigned long __a2 asm("$6") = (unsigned long) c; \
        register unsigned long __a3 asm("$7") = (unsigned long) d; \
        unsigned long __v0; \
        \
        __asm__ volatile ( \
        ".set\tnoreorder\n\t" \
        "lw\t$2, %6\n\t" \
        "subu\t$29, 32\n\t" \
        "sw\t$2, 16($29)\n\t" \
        "li\t$2, %5\t\t\t# " #name "\n\t" \
        "syscall\n\t" \
        "move\t%0, $2\n\t" \
        "addiu\t$29, 32\n\t" \
        ".set\treorder" \
        : "=&r" (__v0), "+r" (__a3) \
        : "r" (__a0), "r" (__a1), "r" (__a2), "i" (__NR_##name), \
          "m" ((unsigned long)e) \
        : "$2", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", \
          "memory"); \
        \
        if (__a3 == 0) \
                return (type) __v0; \
        errno = __v0; \
        return (type) -1; \
}
#define printf filter_printf

#endif
