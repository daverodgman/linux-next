// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */

#include <linux/device.h>
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <keys/user-type.h>
#include "nd-core.h"
#include "nd.h"

/*
 * Retrieve kernel key for DIMM and request from user space if necessary.
 */
static struct key *nvdimm_request_key(struct nvdimm *nvdimm)
{
	struct key *key = NULL;
	char desc[NVDIMM_KEY_DESC_LEN + sizeof(NVDIMM_PREFIX)];

	sprintf(desc, "%s%s", NVDIMM_PREFIX, nvdimm->dimm_id);
	key = request_key(&key_type_logon, desc, "");
	if (IS_ERR(key))
		key = NULL;

	return key;
}

int nvdimm_security_get_state(struct nvdimm *nvdimm)
{
	if (!nvdimm->security_ops)
		return 0;

	return nvdimm->security_ops->state(nvdimm, &nvdimm->state);
}

int nvdimm_security_unlock_dimm(struct nvdimm *nvdimm)
{
	struct key *key;
	int rc = -ENXIO;
	struct user_key_payload *payload;
	struct device *dev = &nvdimm->dev;

	if (!nvdimm->security_ops)
		return 0;

	if (nvdimm->state == NVDIMM_SECURITY_UNLOCKED ||
			nvdimm->state == NVDIMM_SECURITY_UNSUPPORTED ||
			nvdimm->state == NVDIMM_SECURITY_DISABLED)
		return 0;

	mutex_lock(&nvdimm->key_mutex);
	key = nvdimm->key;
	if (!key) {
		key = nvdimm_request_key(nvdimm);
		if (key && key->datalen != NVDIMM_PASSPHRASE_LEN) {
			key_put(key);
			key = NULL;
			rc = -EINVAL;
		}
	}
	if (!key) {
		mutex_unlock(&nvdimm->key_mutex);
		return rc;
	}

	dev_dbg(dev, "%s: key: %#x\n", __func__, key_serial(key));
	down_read(&key->sem);
	payload = key->payload.data[0];
	rc = nvdimm->security_ops->unlock(nvdimm,
			(const struct nvdimm_key_data *)payload->data);
	up_read(&key->sem);

	if (rc == 0) {
		if (!nvdimm->key)
			nvdimm->key = key;
		nvdimm->state = NVDIMM_SECURITY_UNLOCKED;
		dev_dbg(dev, "DIMM %s unlocked\n", dev_name(dev));
	} else {
		key_invalidate(key);
		key_put(key);
		nvdimm->key = NULL;
		dev_warn(dev, "Failed to unlock dimm: %s\n", dev_name(dev));
	}

	mutex_unlock(&nvdimm->key_mutex);
	nvdimm_security_get_state(nvdimm);
	return rc;
}

void nvdimm_security_release(struct nvdimm *nvdimm)
{
	mutex_lock(&nvdimm->key_mutex);
	key_put(nvdimm->key);
	nvdimm->key = NULL;
	mutex_unlock(&nvdimm->key_mutex);
}
