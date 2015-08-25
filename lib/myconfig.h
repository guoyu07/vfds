#ifndef _MYCONFIG_H_
#define _MYCONFIG_H_

extern int myconfig_init(int argc, char **argv);
extern void myconfig_reload();
extern int myconfig_put_value(const char *prefix, const char *key, const char *val);
extern int myconfig_get_intval(const char *key, int def);
extern unsigned long myconfig_get_size(const char *key, int def);
extern double myconfig_get_decimal(const char *key);
extern char* myconfig_get_value(const char *key);
extern char* myconfig_get_multivalue(const char *key, int index);
extern int myconfig_cleanup(void);
extern void myconfig_register_reload(int (*reload_cb_func)(void), char** keys, int keynum);
extern int myconfig_update_value(const char *key, const char *value);
extern int myconfig_dump_to_file();
extern int myconfig_delete_value(const char *pre, const char *key0); 

#endif
