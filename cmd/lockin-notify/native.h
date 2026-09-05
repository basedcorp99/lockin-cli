#ifndef LOCKIN_NOTIFY_NATIVE_H
#define LOCKIN_NOTIFY_NATIVE_H

int lockin_native_init(int authorize, int status_only);
void lockin_native_run(void);
void lockin_native_stop(void);
void lockin_native_settings(unsigned long long token);
void lockin_native_reminder(unsigned long long token, const char *offer_id, const char *message, const char *label);
void lockin_native_result(unsigned long long token, const char *message);
void lockin_native_clear(void);

#endif
