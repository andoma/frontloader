
struct ntv;
struct err;

struct ntv *docker_image_load_manifest(const char *manifest_url,
                                       struct err **err,
                                       const struct ntv *docker_config);

int docker_image_install(const char *basepath,
                         const struct ntv *info, struct err **err,
                         const struct ntv *docker_config);

ntv_t * docker_image_get_config(const struct ntv *info, struct err **err,
                                const struct ntv *docker_config);

