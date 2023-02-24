#pragma once

struct ntv;

int azure_config_reload(const struct ntv *meta_config);

struct ntv *azure_apply_meta_data(void);

void azure_monitor_init(const struct ntv *instance_metadata);
