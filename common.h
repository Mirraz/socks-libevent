#ifndef COMMON_H
#define COMMON_H

void everror(const char *s);
void printf_err(const char *format, ...);
int make_socket_nonblocking(int fd);

#endif/*COMMON_H*/

