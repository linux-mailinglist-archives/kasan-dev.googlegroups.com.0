Return-Path: <kasan-dev+bncBAABB6FBXCHQMGQEJ74V3ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 63ADE497771
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 03:37:46 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id r1-20020a639b01000000b0034243da71casf9065487pgd.7
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Jan 2022 18:37:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642991865; cv=pass;
        d=google.com; s=arc-20160816;
        b=DirS9TZRlFedjbcBYm+l473RiYsmfffYT9IzF/GrUENGIX39yiJ1iJ/4z5vrFCctT2
         3142om3aL5yFScsYzdxz4pbIY6Q+OZSL4L3d1ASBHFr771VirnJ6n9dmVxb9dnSnqezr
         w/NdrwPO+tvhjr30Uq2tXvvYxBBrUwjy16MmM32vBTvHw1ZXrJpXw6odCgV8FF0STElQ
         eEz7FiSmVwuPD3RY/STBWuhlLH5OGXO4JPPZ5FfjhEf7/Dwp7Fhfo3FIwxOCvKHoGLlE
         EznNLSmSB4OO3wIwY6iDr4I4fVEzT2ReHmaWoX1HM5zXNStSTlweGBwqeQAciGzANQIY
         tDIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=17KXxLpQ0/YgtlZAqk2BaxxbKpgj3UrsxOfXNQI3NSc=;
        b=Unf3nSG0Q7Dr4F40glircaLNmBKa5ENm3lrV8lb2TIWGB7o0xvNeWf3/4sawJAywWR
         /Xbm0aqMWlWbwA0SMtMqHmb8xPBa+QTviS8VWFkcGl8L6W1eVYG/bo3eIIg8Yki2d4KW
         CmVVHYDCinBdGq6LtyMa+z+Iowp/OzzX0mtrL85AE8Yg7l3GBmO0umIrrH7dveUm58e8
         ShT61a8NjIxK8R83c5AVGKPbOtuy5L8zIYX7ppYclJH0r77OjT8vKI3PYx2ICv9XpJe4
         uD3NMnehtYPc2Vnp9BfGHXhU+KuEjsLke8uCTWWVBAy2UuwT4+HWWoIKBy5NYIej7YG8
         bWWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=17KXxLpQ0/YgtlZAqk2BaxxbKpgj3UrsxOfXNQI3NSc=;
        b=Y/VJ4uowr8w/K5EQDPz+WgKicb2aeuDet7ImNl2eCAwhUCTVaJC80Ofeq0jQ2qfc/j
         WFBhnNpJUhuQf7ItJtGnQA4f2kWuYHQ/SWbFC6tlOP37ZIon6BDAB+2LGkcrVjkPWxy3
         ZtOcYAqcXwmebgISsmjeqF8NXuW4EbDP58QPlc3Qm0aoEUxARiIfy7Ie6N3LlV/4oWCJ
         ooUrTkp51medKgHwIL+/oM6bho7f44yQpaWbu1NM9heGtJzwFxEv4qCLDSIst/YP/SqO
         r56Bp0i60jwgM8T5V84oL+BgE/EF6X+yQs8vPplKZzPYd/tNbs79TWyr8BuqmdGE4LzJ
         hC+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=17KXxLpQ0/YgtlZAqk2BaxxbKpgj3UrsxOfXNQI3NSc=;
        b=ZmyHGBh8hOQaxhsJOc0JRlUOFsFZ176cgmEGCrOVevPBdclr+/e3JhAbMsd68qLX87
         qgrK+zotCzDpHNItdhEwmHlwsNNz1g8y5a7Itj16vAZNlDblpcv1b8fkkdcpSl3XGgjz
         PS5k4t5fLnDu337rHj1gfI1id+ivbO2QAosG6FMg4Y8XistPBGUsN3KFrHLdScvG3oFh
         ZJGPOBASNqpXnrVe1Tc22NDxV7g40DO6WbtCdc12wECyfXiSaEDigHTgZJOHEE6hiEDv
         OlChU9Yr16otBGAFZIQ4uw5o+r4+ECQ7s1egq12U72s/BR4lIXyfR2mMXTpS8Rr73pnY
         XzXg==
X-Gm-Message-State: AOAM532Z71PxIPd5TdY+yRG2z3PxqrT9MpnDAMsi5oaiZD/0hmjyS3Kj
	Z4n2lwN16u354fNGRG511pI=
X-Google-Smtp-Source: ABdhPJyag1x2Zz8Pde3gA825fMWVoFXK15qAPwHeubGP2EXjjp8Y2e9RzKC2wKIiPr4tYWuU14Lkvg==
X-Received: by 2002:a63:88c8:: with SMTP id l191mr5548404pgd.291.1642991864801;
        Sun, 23 Jan 2022 18:37:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:97:: with SMTP id bb23ls2458891pjb.0.gmail; Sun, 23
 Jan 2022 18:37:44 -0800 (PST)
X-Received: by 2002:a17:902:b60b:b0:14a:fa6d:7e4c with SMTP id b11-20020a170902b60b00b0014afa6d7e4cmr12903778pls.109.1642991864298;
        Sun, 23 Jan 2022 18:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642991864; cv=none;
        d=google.com; s=arc-20160816;
        b=wZr+67xhyxwdFpC2Ny6tDzq7zGQx7Zh1mBiXNCPOE5da4xdDwMSuQizPWU2+vzTJ2B
         tfgPN8NBi1wb0XG29is9PM5IlugwgwWQAQS/EpoX7E1uG0tAwC0bULjBa2g8dBqIKvTa
         PCbTZni+rVB/iBGDiSAKHFVz3ooVrtxl0zGh58GOMnZIPQ+acmEtYofeNR85+sVajgGR
         5WlfPzv/+Z8s+9JboVB9GRf66MijRP6ZrEScwDz4BKy9UHn64SdsFd9qCdyomkxwLFqG
         Xpd7Vk7d+S+/97cNiY1OjmaB3/K8htTLhdIt+PUQAOMrdDIgFqcRmanbmGzDVJa1IMLb
         NweA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=Hg8bH7Cf25aQh59DTqLjNUiSFt7cY/b6zcS3zIImc3Q=;
        b=CXglNbhXo7OINA7APRlsmSDJvhSBeH9Dy8eJ3FAPYeMW+ZjL0yH0XiZhZDSExtpA9B
         CL91LWsX2MU2SNmcWL1c3/swFwxmhAPZABYVaPEtVKf9Lp+15R5hlDDhy4zok0BiJ0Fz
         wM8adWAEttfp+vbavyAaEaeE2sczDXui1CITpDBAEwxdpaNBK67gy7UFHSK9qO8cMmtK
         KhP0ygGKE0n7atsSuMZ0VgDtXYYCiGEsOdofYAUMClhHAT3+omQHvdE5Jv6Z6AkGTBHZ
         gYi/2GGy16in7Kh50SN/KxnpBxPWrKGaCEVVh5bkHDspldkVSaOwcLB+eTzU4bQPoxDn
         uHTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id p26si853660pfh.4.2022.01.23.18.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 Jan 2022 18:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi500015.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4JhvHr3BYCz9sHF;
	Mon, 24 Jan 2022 10:36:24 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500015.china.huawei.com (7.221.188.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 10:37:42 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 10:37:41 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<corbet@lwn.net>, <sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <linaro-mm-sig@lists.linaro.org>,
	<linux-mm@kvack.org>, <liupeng256@huawei.com>
Subject: [PATCH RFC 1/3] kfence: Add a module parameter to adjust kfence objects
Date: Mon, 24 Jan 2022 02:52:03 +0000
Message-ID: <20220124025205.329752-2-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
In-Reply-To: <20220124025205.329752-1-liupeng256@huawei.com>
References: <20220124025205.329752-1-liupeng256@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Liu <liupeng256@huawei.com>
Reply-To: Peng Liu <liupeng256@huawei.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

KFENCE is designed to be enabled in production kernels, but it can
be also useful in some debug situations. For machines with limited
memory and CPU resources, KASAN is really hard to run. Fortunately,
KFENCE can be a suitable candidate. For KFENCE running on a single
machine, the possibility of discovering existed bugs will increase
as the increasing of KFENCE objects, but this will cost more memory.
In order to balance the possibility of discovering existed bugs and
memory cost, KFENCE objects need to be adjusted according to memory
resources for a compiled kernel Image. Add a module parameter to
adjust KFENCE objects will make kfence to use in different machines
with the same kernel Image.

In short, the following reasons motivate us to add this parameter.
1) In some debug situations, this will make kfence flexible.
2) For some production machines with different memory and CPU size,
this will reduce the kernel-Image-version burden.

The main change is just using kfence_num_objects to replace config
CONFIG_KFENCE_NUM_OBJECTS for dynamic configuration convenient. To
make compatible, kfence_metadata and alloc_covered are alloced by
memblock_alloc. Considering "cat /sys/kernel/debug/kfence/objects"
will read kfence_metadata, the initialization of this fs should
check whether kfence_metadata is successfully allocated.

This patch (of 3):

The most important motivation of this patch series is to make
KFENCE easy-to-use in business situations.

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 Documentation/dev-tools/kfence.rst |  14 ++--
 include/linux/kfence.h             |   3 +-
 mm/kfence/core.c                   | 108 ++++++++++++++++++++++++-----
 mm/kfence/kfence.h                 |   2 +-
 mm/kfence/kfence_test.c            |   2 +-
 5 files changed, 103 insertions(+), 26 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index ac6b89d1a8c3..e079dfb81dfe 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -41,12 +41,14 @@ guarded by KFENCE. The default is configurable via the Kconfig option
 ``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=0``
 disables KFENCE.
 
-The KFENCE memory pool is of fixed size, and if the pool is exhausted, no
-further KFENCE allocations occur. With ``CONFIG_KFENCE_NUM_OBJECTS`` (default
-255), the number of available guarded objects can be controlled. Each object
-requires 2 pages, one for the object itself and the other one used as a guard
-page; object pages are interleaved with guard pages, and every object page is
-therefore surrounded by two guard pages.
+The KFENCE memory pool size is also an important parameter, which can be
+can be set via the kernel boot parameter ``kfence.num_objects``, and if the
+pool is exhausted, no further KFENCE allocations occur. The KFENCE memory
+pool size Each object requires 2 pages, one for the object itself and the
+other one used as a guard page; object pages are interleaved with guard pages,
+and every object page is therefore surrounded by two guard pages. The default
+is configurable via the Kconfig option ``CONFIG_KFENCE_SAMPLE_INTERVAL``
+(default 255).
 
 The total memory dedicated to the KFENCE memory pool can be computed as::
 
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 4b5e3679a72c..aec4f6b247b5 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -17,12 +17,13 @@
 #include <linux/atomic.h>
 #include <linux/static_key.h>
 
+extern unsigned long kfence_num_objects;
 /*
  * We allocate an even number of pages, as it simplifies calculations to map
  * address to metadata indices; effectively, the very first page serves as an
  * extended guard page, but otherwise has no special purpose.
  */
-#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
+#define KFENCE_POOL_SIZE ((kfence_num_objects + 1) * 2 * PAGE_SIZE)
 extern char *__kfence_pool;
 
 DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5ad40e3add45..4655bcc0306e 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -34,6 +34,9 @@
 
 #include "kfence.h"
 
+#define MIN_KFENCE_OBJECTS 1
+#define MAX_KFENCE_OBJECTS 65535
+
 /* Disables KFENCE on the first warning assuming an irrecoverable error. */
 #define KFENCE_WARN_ON(cond)                                                   \
 	({                                                                     \
@@ -93,12 +96,53 @@ module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644)
 char *__kfence_pool __ro_after_init;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
 
+/*
+ * The number of kfence objects will affect performance and bug detection
+ * accuracy. The initial value of this global parameter is determined by
+ * compiling settings.
+ */
+unsigned long kfence_num_objects = CONFIG_KFENCE_NUM_OBJECTS;
+EXPORT_SYMBOL(kfence_num_objects); /* Export for test modules. */
+
+static int param_set_num_objects(const char *val, const struct kernel_param *kp)
+{
+	unsigned long num;
+
+	if (system_state != SYSTEM_BOOTING)
+		return -EINVAL; /* Cannot adjust KFENCE objects number on-the-fly. */
+
+	if (kstrtoul(val, 0, &num) < 0)
+		return -EINVAL;
+
+	if (num < MIN_KFENCE_OBJECTS || num > MAX_KFENCE_OBJECTS) {
+		pr_warn("kfence_num_objects = %lu is not in valid range [%d,%d]\n",
+			num, MIN_KFENCE_OBJECTS, MAX_KFENCE_OBJECTS);
+		return -EINVAL;
+	}
+
+	*((unsigned long *)kp->arg) = num;
+	return 0;
+}
+
+static int param_get_num_objects(char *buffer, const struct kernel_param *kp)
+{
+	if (!READ_ONCE(kfence_enabled))
+		return sprintf(buffer, "0\n");
+
+	return param_get_ulong(buffer, kp);
+}
+
+static const struct kernel_param_ops num_objects_param_ops = {
+	.set = param_set_num_objects,
+	.get = param_get_num_objects,
+};
+module_param_cb(num_objects, &num_objects_param_ops, &kfence_num_objects, 0600);
+
 /*
  * Per-object metadata, with one-to-one mapping of object metadata to
  * backing pages (in __kfence_pool).
  */
-static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
-struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
+struct kfence_metadata *kfence_metadata;
 
 /* Freelist with available objects. */
 static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
@@ -124,11 +168,11 @@ atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
  *	P(alloc_traces) = (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HNUM
  */
 #define ALLOC_COVERED_HNUM	2
-#define ALLOC_COVERED_ORDER	(const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2)
+#define ALLOC_COVERED_ORDER	(const_ilog2(kfence_num_objects) + 2)
 #define ALLOC_COVERED_SIZE	(1 << ALLOC_COVERED_ORDER)
 #define ALLOC_COVERED_HNEXT(h)	hash_32(h, ALLOC_COVERED_ORDER)
 #define ALLOC_COVERED_MASK	(ALLOC_COVERED_SIZE - 1)
-static atomic_t alloc_covered[ALLOC_COVERED_SIZE];
+static atomic_t *alloc_covered;
 
 /* Stack depth used to determine uniqueness of an allocation. */
 #define UNIQUE_ALLOC_STACK_DEPTH ((size_t)8)
@@ -168,7 +212,7 @@ static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
 
 static inline bool should_skip_covered(void)
 {
-	unsigned long thresh = (CONFIG_KFENCE_NUM_OBJECTS * kfence_skip_covered_thresh) / 100;
+	unsigned long thresh = (kfence_num_objects * kfence_skip_covered_thresh) / 100;
 
 	return atomic_long_read(&counters[KFENCE_COUNTER_ALLOCATED]) > thresh;
 }
@@ -236,7 +280,7 @@ static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
 	 * error.
 	 */
 	index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
-	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
+	if (index < 0 || index >= kfence_num_objects)
 		return NULL;
 
 	return &kfence_metadata[index];
@@ -251,7 +295,7 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
 
 	/* Only call with a pointer into kfence_metadata. */
 	if (KFENCE_WARN_ON(meta < kfence_metadata ||
-			   meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
+			   meta >= kfence_metadata + kfence_num_objects))
 		return 0;
 
 	/*
@@ -577,7 +621,7 @@ static bool __init kfence_init_pool(void)
 		addr += PAGE_SIZE;
 	}
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < kfence_num_objects; i++) {
 		struct kfence_metadata *meta = &kfence_metadata[i];
 
 		/* Initialize metadata. */
@@ -638,7 +682,7 @@ DEFINE_SHOW_ATTRIBUTE(stats);
  */
 static void *start_object(struct seq_file *seq, loff_t *pos)
 {
-	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
+	if (*pos < kfence_num_objects)
 		return (void *)((long)*pos + 1);
 	return NULL;
 }
@@ -650,7 +694,7 @@ static void stop_object(struct seq_file *seq, void *v)
 static void *next_object(struct seq_file *seq, void *v, loff_t *pos)
 {
 	++*pos;
-	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
+	if (*pos < kfence_num_objects)
 		return (void *)((long)*pos + 1);
 	return NULL;
 }
@@ -692,7 +736,10 @@ static int __init kfence_debugfs_init(void)
 	struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
 
 	debugfs_create_file("stats", 0444, kfence_dir, NULL, &stats_fops);
-	debugfs_create_file("objects", 0400, kfence_dir, NULL, &objects_fops);
+
+	/* Variable kfence_metadata may fail to allocate. */
+	if (kfence_metadata)
+		debugfs_create_file("objects", 0400, kfence_dir, NULL, &objects_fops);
 	return 0;
 }
 
@@ -756,13 +803,40 @@ static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
 
 void __init kfence_alloc_pool(void)
 {
+	phys_addr_t metadata_size;
+	phys_addr_t covered_size;
+
 	if (!kfence_sample_interval)
 		return;
 
-	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	metadata_size = sizeof(struct kfence_metadata) * kfence_num_objects;
+	kfence_metadata = memblock_alloc(metadata_size, PAGE_SIZE);
+	if (!kfence_metadata) {
+		pr_err("failed to allocate metadata\n");
+		return;
+	}
 
-	if (!__kfence_pool)
+	covered_size = sizeof(atomic_t) * kfence_num_objects;
+	alloc_covered = memblock_alloc(covered_size, PAGE_SIZE);
+	if (!alloc_covered) {
+		pr_err("failed to allocate covered\n");
+		goto fail_covered;
+	}
+
+	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	if (!__kfence_pool) {
 		pr_err("failed to allocate pool\n");
+		goto fail_pool;
+	}
+
+	return;
+
+fail_pool:
+	memblock_free(alloc_covered, covered_size);
+	alloc_covered = NULL;
+fail_covered:
+	memblock_free(kfence_metadata, metadata_size);
+	kfence_metadata = NULL;
 }
 
 void __init kfence_init(void)
@@ -781,8 +855,8 @@ void __init kfence_init(void)
 		static_branch_enable(&kfence_allocation_key);
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
-	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
-		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
+	pr_info("initialized - using %lu bytes for %lu objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
+		kfence_num_objects, (void *)__kfence_pool,
 		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
 }
 
@@ -792,7 +866,7 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 	struct kfence_metadata *meta;
 	int i;
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < kfence_num_objects; i++) {
 		bool in_use;
 
 		meta = &kfence_metadata[i];
@@ -831,7 +905,7 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 		}
 	}
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < kfence_num_objects; i++) {
 		meta = &kfence_metadata[i];
 
 		/* See above. */
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 2a2d5de9d379..c6d37fad977a 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -91,7 +91,7 @@ struct kfence_metadata {
 	u32 alloc_stack_hash;
 };
 
-extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
+extern struct kfence_metadata *kfence_metadata;
 
 /* KFENCE error types for report generation. */
 enum kfence_error_type {
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index a22b1af85577..084e3a55aebb 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -623,7 +623,7 @@ static void test_gfpzero(struct kunit *test)
 			break;
 		test_free(buf2);
 
-		if (i == CONFIG_KFENCE_NUM_OBJECTS) {
+		if (i == kfence_num_objects) {
 			kunit_warn(test, "giving up ... cannot get same object back\n");
 			return;
 		}
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220124025205.329752-2-liupeng256%40huawei.com.
