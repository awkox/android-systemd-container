#ifndef ASC_PLATFORM_BLOCKDEV_H
#define ASC_PLATFORM_BLOCKDEV_H

const char *detect_fs_type(const char *img_path);
int loop_attach(const char *img_path, char *loop_path_out, const size_t path_size);
void loop_detach(const char *loop_dev);

#endif
