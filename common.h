#ifndef COMMON_H
#define COMMON_H

void everror(const char *s);
void printf_err(const char *format, ...);
int make_socket_nonblocking(int fd);
ssize_t read_wrapper(int fd, void *buf, size_t count);
ssize_t write_wrapper(int fd, void *buf, size_t count);

#endif/*COMMON_H*/

