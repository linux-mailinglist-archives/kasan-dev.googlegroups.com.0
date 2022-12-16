Return-Path: <kasan-dev+bncBAABBYG46OOAMGQEISPNI7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id DBCFB64F3DC
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 23:17:05 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id v19-20020ac25933000000b004b55ec28779sf1520054lfi.8
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 14:17:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671229025; cv=pass;
        d=google.com; s=arc-20160816;
        b=oz8/MxD0yAh6u2vzO8TbETTswNlOhw9MFU+8AzbBR40nPw84I++mZcRz8NDshIcMWK
         sddDgyE+iE8sAJOsBWRPrMJshrBYDR55j/Poxqy+b7pd37zqy0nY7nHJVoympOoSp7/g
         ictEseYOrQ8pr4oGwx+r9un0VMmoBuxX2a5DRKip9+JoRiGq2Jr0CBH4t0YFSrRZZTpD
         mo1AJxTmonJw0JFLz9WN3TikZ4s7DZYJzOB4xBmi273IukwhrmCylHJe5n6oAgZcSS9T
         gvjUsDumbHbmk+Dobbh//jAyIl+c2uUIkNMlLfpX+d7wInb5u3dsASPE3tpM0dzfdabp
         uAgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=QeP+XevAB19gpMJCAUV7SMwqcGUb9GoMV0RcuZ3OWk4=;
        b=e+9q9Wt25pzRpEdTxmAhVYtybO3A2igbMmU7cGqZpwcRDryY56cVYPxlElEANdS6em
         PB/nyv/zJQOie9Kf2S+iN5HWk215Th7euG82h3LvqINctqpWDxW2tk95P7S9q9iY1li0
         WSuszRxN0q+uX23QiLLlYGZNOpEzE/oB4bh5MI305xIfqO6RiELoEZx/wyfBWS7gYVlt
         Ry9X56ztWfm6p17wL303S5a3p6u1gXV/GRo74yr4grWgV/0ujX3g3/ITDNxAsix13D+S
         hyRtDn0dInGXHxLTqHBm19fNokmG+oXd5qvO2YYowjefVY/sxMnJ+3/v06mhv3+fCLDl
         gjVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n6U8DMpf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QeP+XevAB19gpMJCAUV7SMwqcGUb9GoMV0RcuZ3OWk4=;
        b=UCCM1RRkVUaj+pKONwRkiJC3Bz0/X7rxHMbQCazd6t+gheAhMIhLYcLe9lkgzlhSrC
         28M0scjc0j+wtc9YJFNMxGA5MRr7kjgFJmNe7Y+JXS6bzOkBjkCjJ6Ju5Szg0FktjJNV
         XviDFkNNG+dctPwoAi6vSuaE3tDses/thMEqq/KC+6SUONQIVhxm3OaffX2BYIxl3Hmc
         BzFxPYvNjT3wL5j9DFowe6Tmfj4bWFt5rNrAohd/fgh2fFYExm8M4yb9kCjkirQjrqM9
         o5tk4++OEntNAqF71U9k4coiMqJoUsA07RxKj1ciYPjO9HOCjfDA4o6DKPEYrCSqLIXH
         uOug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=QeP+XevAB19gpMJCAUV7SMwqcGUb9GoMV0RcuZ3OWk4=;
        b=TheZZjGaBOwDABLlND9oOxIcP8fEzSm6J/Eq3BeYHqdf4wbZJDGGyphyouX234zedL
         sb1tYM2aYtN2aDJ3tisjN0Q/3743+y+dddwltj7hLbcToA9/vvgEEkBO4ocpF2cGFptM
         F8YCcp258M+5ENQlIwRzWkZx/jWTdYg4yg76PAfPOK3JzTbZFDJsCPR1h0jkITs1zFQl
         Y+qMKEV9IotBZ0Lx7W/rPMk6R6K9AxPiXA3N79a6JKiAxu73uexsgPlR4sfXNdzLoJnT
         XeQoxWIZj52EHU26NNOPJDauMwmydaqqXFb79CHAhOLe+VyypXhT8WtmMavc03PHf6sl
         Vb8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpQ7Njd/bzQ/91G5HvES+3hgUTlPwMddjcOjNerAPBMDcZQtgUB
	7uviSRAlp8Yi0pmZcMYyhic=
X-Google-Smtp-Source: AMrXdXtKWjTYXe2DuEDye/nHMhAiybbtoVj1+gByla1S3PkFNM4d0HcY01NUUcq7KUuxOLa9M+OcYA==
X-Received: by 2002:a05:6512:3083:b0:4c1:aad6:2f9f with SMTP id z3-20020a056512308300b004c1aad62f9fmr143070lfd.683.1671229025249;
        Fri, 16 Dec 2022 14:17:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3242:b0:4b5:3cdf:5a65 with SMTP id
 c2-20020a056512324200b004b53cdf5a65ls1001579lfr.2.-pod-prod-gmail; Fri, 16
 Dec 2022 14:17:04 -0800 (PST)
X-Received: by 2002:a05:6512:2314:b0:4b6:ed8b:4f17 with SMTP id o20-20020a056512231400b004b6ed8b4f17mr8159907lfu.51.1671229024094;
        Fri, 16 Dec 2022 14:17:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671229024; cv=none;
        d=google.com; s=arc-20160816;
        b=MUWtt2UfrJyUtia5WIuIpyLAGvu4jdjaJYCPgAk22sI+8OxJ7N7+Nt6q33nxEE25Hm
         OmvzUu/g7jshJnb6l4pqr7xy8rN/EFYwwxE4XCwuxo0Ws3UxAl0fvRTL8E1wWtb/3K3m
         HxRtyG6s9iqM/GPnLUY5AKtJu7ue22oH68jun2qlo5QpriKRLI7Kd5R1NdU6i2Zc13xq
         sy8dOowW9lsCWEG0cupHX1ZRbUTXq7hwJoevJZB0IWlw2oftFJB/qEk9mpt3j5zoqy2c
         EHPPhjH38okvuNlFPlmVpLuxnAMB8JnvGrq5FOrCEWW9FW+PuPRY86OcbuykAdmxxqSq
         v2GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=T1sWzmWH45qh/pr3yJYA5mK6XRRop2e+j5E2G9NZhYg=;
        b=y9gkpyg6Vo4+VEM+YFEwshtRnhrF2Hp20mXEIwXjCouLfaeSbTrq1gPc7PG/Jn3N3U
         Ly7IiZ7Q2OgQGZ01UBBEqA2BSncpmqMC2do36/eGl1vBSaojNOaMwlwoYZSdbzZxfeHK
         4OwXK+l2gvByY1b2GaAFci6x5k3l1hIY2t2QfE51PsVKXqMCjHjsRPxyOg4Ejn7n7u48
         4ilxphSSgxcq0u4YZh34T3D/bPAUpi+tBMkhA9uJ0nX25l/iPh580Sf/fDHrN4Tz55ws
         fEmst8rtfnVxd1YPzjciVg9w39ZUu9pDZ4hLHFZh0Ux4c6UWl3grIrrTJBGtbHuMtnFe
         EiJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n6U8DMpf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id b4-20020a056512070400b004b49cc7bf6asi150985lfs.9.2022.12.16.14.17.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Dec 2022 14:17:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Jann Horn <jannh@google.com>,
	Mark Brand <markbrand@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3] kasan: allow sampling page_alloc allocations for HW_TAGS
Date: Fri, 16 Dec 2022 23:16:54 +0100
Message-Id: <323d51d422d497b3783dacb130af245f67d77671.1671228324.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=n6U8DMpf;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

As Hardware Tag-Based KASAN is intended to be used in production, its
performance impact is crucial. As page_alloc allocations tend to be big,
tagging and checking all such allocations can introduce a significant
slowdown.

Add two new boot parameters that allow to alleviate that slowdown:

- kasan.page_alloc.sample, which makes Hardware Tag-Based KASAN tag only
  every Nth page_alloc allocation with the order configured by the second
  added parameter (default: tag every such allocation).

- kasan.page_alloc.sample.order, which makes sampling enabled by the first
  parameter only affect page_alloc allocations with the order equal or
  greater than the specified value (default: 3, see below).

The exact performance improvement caused by using the new parameters
depends on their values and the applied workload.

The chosen default value for kasan.page_alloc.sample.order is 3, which
matches both PAGE_ALLOC_COSTLY_ORDER and SKB_FRAG_PAGE_ORDER. This is done
for two reasons:

1. PAGE_ALLOC_COSTLY_ORDER is "the order at which allocations are deemed
   costly to service", which corresponds to the idea that only large and
   thus costly allocations are supposed to sampled.

2. One of the workloads targeted by this patch is a benchmark that sends
   a large amount of data over a local loopback connection. Most multi-page
   data allocations in the networking subsystem have the order of
   SKB_FRAG_PAGE_ORDER (or PAGE_ALLOC_COSTLY_ORDER).

When running a local loopback test on a testing MTE-enabled device in sync
mode, enabling Hardware Tag-Based KASAN introduces a ~50% slowdown.
Applying this patch and setting kasan.page_alloc.sampling to a value higher
than 1 allows to lower the slowdown. The performance improvement saturates
around the sampling interval value of 10 with the default sampling page
order of 3. This lowers the slowdown to ~20%. The slowdown in real
scenarios involving the network will likely be better.

Enabling page_alloc sampling has a downside: KASAN misses bad accesses to
a page_alloc allocation that has not been tagged. This lowers the value of
KASAN as a security mitigation.

However, based on measuring the number of page_alloc allocations of
different orders during boot in a test build, sampling with the default
kasan.page_alloc.sample.order value affects only ~7% of allocations.
The rest ~93% of allocations are still checked deterministically.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2-v3:
- Drop __GFP_KASAN_SAMPLE flag.
- Add kasan.page_alloc.sample.order.
- Add fast-path for disabled sampling to kasan_sample_page_alloc.

Changes v1->v2:
- Only sample allocations when __GFP_KASAN_SAMPLE is provided to
  alloc_pages().
- Fix build when KASAN is disabled.
- Add more information about the flag to documentation.
- Use optimized preemption-safe approach for sampling suggested by Marco.
---
 Documentation/dev-tools/kasan.rst | 16 +++++++++
 include/linux/kasan.h             | 14 +++++---
 mm/kasan/common.c                 |  9 +++--
 mm/kasan/hw_tags.c                | 60 +++++++++++++++++++++++++++++++
 mm/kasan/kasan.h                  | 27 ++++++++++++++
 mm/page_alloc.c                   | 43 ++++++++++++++--------
 6 files changed, 148 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 5c93ab915049..d983e4fcee7c 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -140,6 +140,22 @@ disabling KASAN altogether or controlling its features:
 - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
   allocations (default: ``on``).
 
+- ``kasan.page_alloc.sample=<sampling interval>`` makes KASAN tag only every
+  Nth page_alloc allocation with the order equal or greater than
+  ``kasan.page_alloc.sample.order``, where N is the value of the ``sample``
+  parameter (default: ``1``, or tag every such allocation).
+  This parameter is intended to mitigate the performance overhead introduced
+  by KASAN.
+  Note that enabling this parameter makes Hardware Tag-Based KASAN skip checks
+  of allocations chosen by sampling and thus miss bad accesses to these
+  allocations. Use the default value for accurate bug detection.
+
+- ``kasan.page_alloc.sample.order=<minimum page order>`` specifies the minimum
+  order of allocations that are affected by sampling (default: ``3``).
+  Only applies when ``kasan.page_alloc.sample`` is set to a non-default value.
+  This parameter is intended to allow sampling only large page_alloc
+  allocations, which is the biggest source of the performace overhead.
+
 Error reports
 ~~~~~~~~~~~~~
 
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 96c9d56e5510..5ebbaf672009 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -120,12 +120,13 @@ static __always_inline void kasan_poison_pages(struct page *page,
 		__kasan_poison_pages(page, order, init);
 }
 
-void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init);
-static __always_inline void kasan_unpoison_pages(struct page *page,
+bool __kasan_unpoison_pages(struct page *page, unsigned int order, bool init);
+static __always_inline bool kasan_unpoison_pages(struct page *page,
 						 unsigned int order, bool init)
 {
 	if (kasan_enabled())
-		__kasan_unpoison_pages(page, order, init);
+		return __kasan_unpoison_pages(page, order, init);
+	return false;
 }
 
 void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
@@ -249,8 +250,11 @@ static __always_inline bool kasan_check_byte(const void *addr)
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
-static inline void kasan_unpoison_pages(struct page *page, unsigned int order,
-					bool init) {}
+static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
+					bool init)
+{
+	return false;
+}
 static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 833bf2cfd2a3..1d0008e1c420 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -95,19 +95,24 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
+bool __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
 {
 	u8 tag;
 	unsigned long i;
 
 	if (unlikely(PageHighMem(page)))
-		return;
+		return false;
+
+	if (!kasan_sample_page_alloc(order))
+		return false;
 
 	tag = kasan_random_tag();
 	kasan_unpoison(set_tag(page_address(page), tag),
 		       PAGE_SIZE << order, init);
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
+
+	return true;
 }
 
 void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index b22c4f461cb0..d1bcb0205327 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -59,6 +59,24 @@ EXPORT_SYMBOL_GPL(kasan_mode);
 /* Whether to enable vmalloc tagging. */
 DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
 
+#define PAGE_ALLOC_SAMPLE_DEFAULT	1
+#define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
+
+/*
+ * Sampling interval of page_alloc allocation (un)poisoning.
+ * Defaults to no sampling.
+ */
+unsigned long kasan_page_alloc_sample = PAGE_ALLOC_SAMPLE_DEFAULT;
+
+/*
+ * Minimum order of page_alloc allocations to be affected by sampling.
+ * The default value is chosen to match both
+ * PAGE_ALLOC_COSTLY_ORDER and SKB_FRAG_PAGE_ORDER.
+ */
+unsigned int kasan_page_alloc_sample_order = PAGE_ALLOC_SAMPLE_ORDER_DEFAULT;
+
+DEFINE_PER_CPU(long, kasan_page_alloc_skip);
+
 /* kasan=off/on */
 static int __init early_kasan_flag(char *arg)
 {
@@ -122,6 +140,48 @@ static inline const char *kasan_mode_info(void)
 		return "sync";
 }
 
+/* kasan.page_alloc.sample=<sampling interval> */
+static int __init early_kasan_flag_page_alloc_sample(char *arg)
+{
+	int rv;
+
+	if (!arg)
+		return -EINVAL;
+
+	rv = kstrtoul(arg, 0, &kasan_page_alloc_sample);
+	if (rv)
+		return rv;
+
+	if (!kasan_page_alloc_sample || kasan_page_alloc_sample > LONG_MAX) {
+		kasan_page_alloc_sample = PAGE_ALLOC_SAMPLE_DEFAULT;
+		return -EINVAL;
+	}
+
+	return 0;
+}
+early_param("kasan.page_alloc.sample", early_kasan_flag_page_alloc_sample);
+
+/* kasan.page_alloc.sample.order=<minimum page order> */
+static int __init early_kasan_flag_page_alloc_sample_order(char *arg)
+{
+	int rv;
+
+	if (!arg)
+		return -EINVAL;
+
+	rv = kstrtouint(arg, 0, &kasan_page_alloc_sample_order);
+	if (rv)
+		return rv;
+
+	if (kasan_page_alloc_sample_order > INT_MAX) {
+		kasan_page_alloc_sample_order = PAGE_ALLOC_SAMPLE_ORDER_DEFAULT;
+		return -EINVAL;
+	}
+
+	return 0;
+}
+early_param("kasan.page_alloc.sample.order", early_kasan_flag_page_alloc_sample_order);
+
 /*
  * kasan_init_hw_tags_cpu() is called for each CPU.
  * Not marked as __init as a CPU can be hot-plugged after boot.
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ea8cf1310b1e..32413f22aa82 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -42,6 +42,10 @@ enum kasan_mode {
 
 extern enum kasan_mode kasan_mode __ro_after_init;
 
+extern unsigned long kasan_page_alloc_sample;
+extern unsigned int kasan_page_alloc_sample_order;
+DECLARE_PER_CPU(long, kasan_page_alloc_skip);
+
 static inline bool kasan_vmalloc_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_vmalloc);
@@ -57,6 +61,24 @@ static inline bool kasan_sync_fault_possible(void)
 	return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
 }
 
+static inline bool kasan_sample_page_alloc(unsigned int order)
+{
+	/* Fast-path for when sampling is disabled. */
+	if (kasan_page_alloc_sample == 1)
+		return true;
+
+	if (order < kasan_page_alloc_sample_order)
+		return true;
+
+	if (this_cpu_dec_return(kasan_page_alloc_skip) < 0) {
+		this_cpu_write(kasan_page_alloc_skip,
+			       kasan_page_alloc_sample - 1);
+		return true;
+	}
+
+	return false;
+}
+
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_async_fault_possible(void)
@@ -69,6 +91,11 @@ static inline bool kasan_sync_fault_possible(void)
 	return true;
 }
 
+static inline bool kasan_sample_page_alloc(unsigned int order)
+{
+	return true;
+}
+
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #ifdef CONFIG_KASAN_GENERIC
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0745aedebb37..7d980dc0000e 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1356,6 +1356,8 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
  *    see the comment next to it.
  * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
  *    see the comment next to it.
+ * 4. The allocation is excluded from being checked due to sampling,
+ *    see the call to kasan_unpoison_pages.
  *
  * Poisoning pages during deferred memory init will greatly lengthen the
  * process and cause problem in large memory systems as the deferred pages
@@ -2468,7 +2470,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 {
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
-	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+	bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+	bool reset_tags = !zero_tags;
 	int i;
 
 	set_page_private(page, 0);
@@ -2491,30 +2494,42 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	 */
 
 	/*
-	 * If memory tags should be zeroed (which happens only when memory
-	 * should be initialized as well).
+	 * If memory tags should be zeroed
+	 * (which happens only when memory should be initialized as well).
 	 */
-	if (init_tags) {
+	if (zero_tags) {
 		/* Initialize both memory and tags. */
 		for (i = 0; i != 1 << order; ++i)
 			tag_clear_highpage(page + i);
 
-		/* Note that memory is already initialized by the loop above. */
+		/* Take note that memory was initialized by the loop above. */
 		init = false;
 	}
 	if (!should_skip_kasan_unpoison(gfp_flags)) {
-		/* Unpoison shadow memory or set memory tags. */
-		kasan_unpoison_pages(page, order, init);
-
-		/* Note that memory is already initialized by KASAN. */
-		if (kasan_has_integrated_init())
-			init = false;
-	} else {
-		/* Ensure page_address() dereferencing does not fault. */
+		/* Try unpoisoning (or setting tags) and initializing memory. */
+		if (kasan_unpoison_pages(page, order, init)) {
+			/* Take note that memory was initialized by KASAN. */
+			if (kasan_has_integrated_init())
+				init = false;
+			/* Take note that memory tags were set by KASAN. */
+			reset_tags = false;
+		} else {
+			/*
+			 * KASAN decided to exclude this allocation from being
+			 * poisoned due to sampling. Skip poisoning as well.
+			 */
+			SetPageSkipKASanPoison(page);
+		}
+	}
+	/*
+	 * If memory tags have not been set, reset the page tags to ensure
+	 * page_address() dereferencing does not fault.
+	 */
+	if (reset_tags) {
 		for (i = 0; i != 1 << order; ++i)
 			page_kasan_tag_reset(page + i);
 	}
-	/* If memory is still not initialized, do it now. */
+	/* If memory is still not initialized, initialize it now. */
 	if (init)
 		kernel_init_pages(page, 1 << order);
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/323d51d422d497b3783dacb130af245f67d77671.1671228324.git.andreyknvl%40google.com.
