#ifndef __KSU_SAMSUNG_KDP_H
#define __KSU_SAMSUNG_KDP_H

#include <linux/cred.h>
#include <linux/types.h>

int ksu_samsung_kdp_init(void);
void ksu_samsung_kdp_exit(void);
int ksu_samsung_kdp_commit_creds(struct cred *cred);
void ksu_samsung_kdp_put_cred(const struct cred *cred);
bool ksu_samsung_kdp_is_active(void);
bool ksu_is_samsung_rkp(void);

static inline void ksu_put_cred(const struct cred *cred)
{
    ksu_samsung_kdp_put_cred(cred);
}

#endif
