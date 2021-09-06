#pragma once

#include <stddef.h>

#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif

EXTERN_C_BEGIN

size_t remap_text_and_data_to_huge_pages(void (*logger)(const char *));

EXTERN_C_END
