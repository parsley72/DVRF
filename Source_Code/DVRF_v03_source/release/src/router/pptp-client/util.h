/* util.h ....... error message utilities.
 *                C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * $Id: util.h,v 1.2 2007/11/20 06:06:12 jack Exp $
 */

#ifndef INC_UTIL_H
#define INC_UTIL_H

void _log(char *func, char *file, int line, char *format, ...)
     __attribute__ ((format (printf, 4, 5)));
void _warn(char *func, char *file, int line, char *format, ...)
     __attribute__ ((format (printf, 4, 5)));
void _fatal(char *func, char *file, int line, char *format, ...)
     __attribute__ ((format (printf, 4, 5))) __attribute__ ((noreturn));

#undef DEBUGP

#ifndef DEBUGP
    #define cprintf(fmt, args...)
#else
    #ifdef linux 
    /* Print directly to the console */
	#define cprintf(fmt, args...) do { \
		FILE *fp = fopen("/dev/console", "w"); \
		if (fp) { \
			fprintf(fp, fmt, ## args); \
			fclose(fp); \
		} \
	} while (0)
    #endif
#endif

#define log(format, args...) \
	_log(__FUNCTION__,__FILE__,__LINE__, format , ## args)
#define warn(format, args...) \
	_warn(__FUNCTION__,__FILE__,__LINE__, format , ## args)
#define fatal(format, args...) \
	_fatal(__FUNCTION__,__FILE__,__LINE__, format , ## args)

#endif /* INC_UTIL_H */
