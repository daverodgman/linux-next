/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018, Linaro Ltd.
 * Author: Georgi Djakov <georgi.djakov@linaro.org>
 */

#ifndef __LINUX_INTERCONNECT_H
#define __LINUX_INTERCONNECT_H

#include <linux/mutex.h>
#include <linux/types.h>

struct icc_path;
struct device;

#if IS_ENABLED(CONFIG_INTERCONNECT)

struct icc_path *icc_get(struct device *dev, const int src_id,
			 const int dst_id);
struct icc_path *of_icc_get(struct device *dev, const char *name);
void icc_put(struct icc_path *path);
int icc_set(struct icc_path *path, u32 avg_bw, u32 peak_bw);

#else

static inline struct icc_path *icc_get(struct device *dev, const int src_id,
				       const int dst_id)
{
	return NULL;
}

static inline struct icc_path *of_icc_get(struct device *dev,
					  const char *name)
{
	return NULL;
}

static inline void icc_put(struct icc_path *path)
{
}

static inline int icc_set(struct icc_path *path, u32 avg_bw, u32 peak_bw)
{
	return 0;
}

#endif /* CONFIG_INTERCONNECT */

#endif /* __LINUX_INTERCONNECT_H */
