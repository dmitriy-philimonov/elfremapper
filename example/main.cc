#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <elfremapper.h>

int main() {
  size_t pages = remap_text_and_data_to_huge_pages(
      [](const char *msg) { printf("[ERROR] %s\n", msg); });
  if (pages)
    printf("[INFO] We are good! Remapped %lu\n", pages);
  else
    printf("[ERROR] Remap failed\n");

  char name[128] = {};
  snprintf(name, sizeof(name), "/proc/%d/maps", getpid());

  char buf[128] = {};
  FILE *input = fopen(name, "r");
  if (input == nullptr) {
    printf("Can't open '%s'\n", name);
    return 1;
  }
  while (size_t read = fread(buf, 1, sizeof(buf), input)) {
    fwrite(buf, 1, read, stdout);
  }
  fclose(input);
  return 0;
}
