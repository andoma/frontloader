#pragma once

struct ntv;

int aws_config_reload_sm(const struct ntv *meta_config);

struct ntv *ec2_apply_meta_data(void);
