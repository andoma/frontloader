#pragma once

struct err;

int file_download_extract(const char *source, const char *target,
                          int set_owner, int strip_components,
                          struct err **err);

int file_extract_from_FILE(FILE *source, const char *target,
                           int set_owner, int strip_components, int process_wh,
                           struct err **err);
