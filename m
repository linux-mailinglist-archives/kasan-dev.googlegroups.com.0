Return-Path: <kasan-dev+bncBAABBEGKRGOAMGQEOL4QYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 29B39639805
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 20:12:17 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 187-20020a1c02c4000000b003d016c210f7sf6065206wmc.6
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 11:12:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669489936; cv=pass;
        d=google.com; s=arc-20160816;
        b=yL5Trnb2X6V3lKr2hW44OBpPABp0gHoEAD4sgm/9V9GLR8edrtg9tFYY1d8An4fEx6
         HJ6vxGd3Ky/nEA0FpTTZy61f6w6pNyqPiVhqWyhqTmJdN/IMk4yTUWHEG8YygLT1+SA9
         0xdHkhxbPqjj50/v+BRCRVV5dyKVtOzPDqUiVqgNdYv8iEtrnxgOYQyvoyl8fkCDqc8Z
         1XzrmtUol1lHvhyMw2BgU8lTKLsE8WNKZnmBAQgl2g9LFtt6IdUgMULAnUfyALCJ73Aw
         Nc/I7TTIYN++QpQpN0vrSt0RknHII5nnlHhPDoBjFsrMYC1dNCf1IVe34SRvXQVL7QOx
         kErg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SEXP8+MDf+unUmHAG0wuw/YQSXlRnH0ZNmReRvnCL14=;
        b=cRVHoap2EAseiSOyce7Ukt7J0M0jKpBtssM1vUc4Mx9+3JlyIIzIMuN+gFkBDvKDB7
         qY+cyRYCaYtVoIYDlJg62HJ3Ud9deEfe+QCsZKKHLAlZqp4oJ/HMlHGOZlrKsY2wJneq
         L3+o2GAok6a/xM+0SFeeC2a8+JyGt7OO/T/isetJEaq6CEGpJUmQmw004k85gFNIRKXp
         zEuDK12NHLnEo/CYND3DUKe9twa16qYAMBdmMMCn5DCki6cOfgDGbekwdhNr2AHd2r1Y
         qhou7NV+OkYUSZr4iIBcy37rWTLKCz5fEPRlIbAVKSNr95flU2vGfHYBQ/+crkZZes7t
         eaiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L7yLkp2s;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SEXP8+MDf+unUmHAG0wuw/YQSXlRnH0ZNmReRvnCL14=;
        b=PSW2hmkmc8obwNRuuN7DhQxFN33suU1uyza5k2b9nweHGaqiXlzDcIme0rJg0cOAH3
         dlc76MnPmIMTahSUqTqMVxQbKB+v8GI8RTUukNjUxehwb0GOLptY+xvlEgyyP0LvtyyX
         L/efrVYat/aIozPjYG9Ppjw+gVa+waVYJLz1Rs/c2IYYo+rMUtHXUCCPCmXZo2x4TtVA
         0Co/aFTUXysYUmPGWjvYk9oOlOlga3FvyGaTpDNK9VbI1Gw0uflxBwHz0PnVGJj4pnp9
         dcBkWkZcT8wlxx8yM+xVKlg9TV1+z2ueIlGgSgaHeNtIhpGMOwJe2hQ7nZYwminu7Wgk
         dg6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=SEXP8+MDf+unUmHAG0wuw/YQSXlRnH0ZNmReRvnCL14=;
        b=IYbJ+y/DdRVIws7aLJsMgdXI54OvtPnPoeFHM16zYsNF/YwkIBN/xCzKMHeAnWuYDg
         uJe7+ML013sZI7jTSuKx+DnpU2gcSZ32m7sf+r+nk+COv1JzLX+vY6JF0R9Du9nFGJm5
         H2U+XznkNw0GOSvOTOFA6HqHFMqyslUhJhw7Upk2Ps+dCjM4ZOWeo/6KTwvUFmS8fJZP
         dpb0Y+cxzT9zwOUfs7CKFAwkTDwkWdr/v5Y55G1n/yagMe8n3/p1u5Ipd2D81c4sBg6z
         3cV8Es1d4hwy92oc2kJEpWJxYAaPzfddNVen6OcYBSVnGDpNLNujFhUuftOHIZI88PLu
         96Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pk44F1Lop7YpCTDCi9u+aNHqgVLunHXpU/tF5sc1Z+L+xqgWro9
	yRQefRal6ibdXPvm37wSf4c=
X-Google-Smtp-Source: AA0mqf6IMPJychnrNyf1TmEYbVYvJYkXdCfFW9woFlaInA+DVsnnko8MM4l98Bjj6SMyGi9dQc2tFA==
X-Received: by 2002:a05:600c:15d6:b0:3cf:54a5:b7ee with SMTP id v22-20020a05600c15d600b003cf54a5b7eemr18792582wmf.106.1669489936330;
        Sat, 26 Nov 2022 11:12:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:236:b0:22c:d34e:768c with SMTP id
 l22-20020a056000023600b0022cd34e768cls5424629wrz.0.-pod-prod-gmail; Sat, 26
 Nov 2022 11:12:15 -0800 (PST)
X-Received: by 2002:a05:6000:78d:b0:22e:3d63:80bc with SMTP id bu13-20020a056000078d00b0022e3d6380bcmr28406958wrb.30.1669489935486;
        Sat, 26 Nov 2022 11:12:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669489935; cv=none;
        d=google.com; s=arc-20160816;
        b=h0acxuFbghhG6NgW2HxG9HgDHzik39eAwY2fHOgcIrpdocR7Kfe5YJMfOVnRN3xqpY
         Mib19qWkXSKTdEpDqj4N8gd6gK83qXTQ9qRXdkF3uDIUP2srlOLWi1sDgRGwgdd//UWZ
         I3aqP0HUmJre8bBGu3WE9aUnEf6tAFZ/nKb79nL0A3drd5sA6obtDBn6dAdC2GFP1vcx
         Kmj2n5pN/pucYPJqRA22Mm8r96151EzOl3qdyL0Fa0S+QyPPKNoX0Ty/o8923zoDTwJk
         7BcM+Lct76b86LIN/KEUkw920nHPGQTT199WSLUC/I+uj7kKM+7aFOylyhRSz44AnP/E
         HNfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NTvtLdwKAsdZetytnk3lwJCHGI1QRaGE6wDffqLm6HM=;
        b=pn0EddWzJgpCQJeo/WyYKevqQQl8lzsZ3Xtmu3Whke1gLir/oBnUi1RyfD9ZT30I6Z
         Pj0G5vFgk4lPI19qt3hOUhs0OIqR/BlXxmB3JR69v9WMOmWx+fhs64TkN2jb6MMEbjwj
         ubHuttmG+ipLXnJiTNmDFwBF8qTkmf8asZ+qdPJV4gQfR4IlABGeTYOSp4cI0RYcuDxM
         W54v5aZMvClbvATdu+RHiDcz5CgOjXRHeDR6e2ES6w92DR2dpr3YEgCBN7kOFBI3VkCs
         Gy8ccoCLTFs7NCPlxSI7TrfSJ477Zwi2EPiunYTWG6tk1HnZuYVCcI9ng6+yBsDsMLdc
         18XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L7yLkp2s;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-4.mta0.migadu.com (out-4.mta0.migadu.com. [2001:41d0:1004:224b::4])
        by gmr-mx.google.com with ESMTPS id bx13-20020a5d5b0d000000b00239778ccf84si357152wrb.2.2022.11.26.11.12.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Nov 2022 11:12:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::4 as permitted sender) client-ip=2001:41d0:1004:224b::4;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>
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
	netdev@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 1/2] kasan: allow sampling page_alloc allocations for HW_TAGS
Date: Sat, 26 Nov 2022 20:12:12 +0100
Message-Id: <4c341c5609ed09ad6d52f937eeec28d142ff1f46.1669489329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L7yLkp2s;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add a new boot parameter called kasan.page_alloc.sample, which makes
Hardware Tag-Based KASAN tag only every Nth page_alloc allocation for
allocations marked with __GFP_KASAN_SAMPLE.

As Hardware Tag-Based KASAN is intended to be used in production, its
performance impact is crucial. As page_alloc allocations tend to be big,
tagging and checking all such allocations can introduce a significant
slowdown. The new flag allows to alleviate that slowdown for chosen
allocations.

The exact performance improvement caused by using __GFP_KASAN_SAMPLE and
kasan.page_alloc.sample depends on how often the marked allocations happen
and how large the are. See the next patch for the details about marking and
sampling skb allocations.

Enabling page_alloc sampling has a downside: KASAN will miss bad accesses
to a page_alloc allocation that has not been tagged.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Only sample allocations when __GFP_KASAN_SAMPLE is provided to
  alloc_pages().
- Fix build when KASAN is disabled.
- Add more information about the flag to documentation.
- Use optimized preemption-safe approach for sampling suggested by Marco.
---
 Documentation/dev-tools/kasan.rst |  8 ++++++
 include/linux/gfp_types.h         | 10 +++++--
 include/linux/kasan.h             | 18 ++++++++-----
 include/trace/events/mmflags.h    |  3 ++-
 mm/kasan/common.c                 | 10 +++++--
 mm/kasan/hw_tags.c                | 26 ++++++++++++++++++
 mm/kasan/kasan.h                  | 19 +++++++++++++
 mm/mempool.c                      |  2 +-
 mm/page_alloc.c                   | 44 +++++++++++++++++++++----------
 9 files changed, 114 insertions(+), 26 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 5c93ab915049..bd6d064c7419 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -140,6 +140,14 @@ disabling KASAN altogether or controlling its features:
 - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
   allocations (default: ``on``).
 
+- ``kasan.page_alloc.sample=<sampling interval>`` makes KASAN tag only every
+  Nth page_alloc allocation for allocations marked with __GFP_KASAN_SAMPLE,
+  where N is the value of the parameter (default: ``1``).
+  This parameter is intended to mitigate the performance overhead.
+  Note that enabling this parameter makes Hardware Tag-Based KASAN skip checks
+  of allocations chosen by sampling and thus miss bad accesses to these
+  allocations. Use the default value for accurate bug detection.
+
 Error reports
 ~~~~~~~~~~~~~
 
diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index d88c46ca82e1..c322cd159445 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -50,13 +50,15 @@ typedef unsigned int __bitwise gfp_t;
 #define ___GFP_SKIP_ZERO		0x1000000u
 #define ___GFP_SKIP_KASAN_UNPOISON	0x2000000u
 #define ___GFP_SKIP_KASAN_POISON	0x4000000u
+#define ___GFP_KASAN_SAMPLE		0x8000000u
 #else
 #define ___GFP_SKIP_ZERO		0
 #define ___GFP_SKIP_KASAN_UNPOISON	0
 #define ___GFP_SKIP_KASAN_POISON	0
+#define ___GFP_KASAN_SAMPLE		0
 #endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x8000000u
+#define ___GFP_NOLOCKDEP	0x10000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -243,6 +245,9 @@ typedef unsigned int __bitwise gfp_t;
  *
  * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocation.
  * Typically, used for userspace pages. Only effective in HW_TAGS mode.
+ *
+ * %__GFP_KASAN_SAMPLE makes KASAN use sampling to skip poisoning and
+ * unpoisoning of page allocations. Only effective in HW_TAGS mode.
  */
 #define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
@@ -251,12 +256,13 @@ typedef unsigned int __bitwise gfp_t;
 #define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
 #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
 #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
+#define __GFP_KASAN_SAMPLE        ((__force gfp_t)___GFP_KASAN_SAMPLE)
 
 /* Disable lockdep for GFP context tracking */
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (28 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d811b3d7d2a1..4cc946b8cbc8 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -120,12 +120,15 @@ static __always_inline void kasan_poison_pages(struct page *page,
 		__kasan_poison_pages(page, order, init);
 }
 
-void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init);
-static __always_inline void kasan_unpoison_pages(struct page *page,
-						 unsigned int order, bool init)
+bool __kasan_unpoison_pages(struct page *page, unsigned int order,
+			    bool init, bool sample);
+static __always_inline bool kasan_unpoison_pages(struct page *page,
+						 unsigned int order,
+						 bool init, bool sample)
 {
 	if (kasan_enabled())
-		__kasan_unpoison_pages(page, order, init);
+		return __kasan_unpoison_pages(page, order, init, sample);
+	return false;
 }
 
 void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
@@ -249,8 +252,11 @@ static __always_inline bool kasan_check_byte(const void *addr)
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
-static inline void kasan_unpoison_pages(struct page *page, unsigned int order,
-					bool init) {}
+static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
+					bool init, bool sample)
+{
+	return false;
+}
 static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index e87cb2b80ed3..bcaecf859d1f 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -57,7 +57,8 @@
 #define __def_gfpflag_names_kasan ,			\
 	gfpflag_string(__GFP_SKIP_ZERO),		\
 	gfpflag_string(__GFP_SKIP_KASAN_POISON),	\
-	gfpflag_string(__GFP_SKIP_KASAN_UNPOISON)
+	gfpflag_string(__GFP_SKIP_KASAN_UNPOISON),	\
+	gfpflag_string(__GFP_KASAN_SAMPLE)
 #else
 #define __def_gfpflag_names_kasan
 #endif
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 833bf2cfd2a3..05d799ada873 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -95,19 +95,25 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
+bool __kasan_unpoison_pages(struct page *page, unsigned int order,
+			    bool init, bool sample)
 {
 	u8 tag;
 	unsigned long i;
 
 	if (unlikely(PageHighMem(page)))
-		return;
+		return false;
+
+	if (sample && !kasan_sample_page_alloc())
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
index b22c4f461cb0..5e6571820a3f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -59,6 +59,11 @@ EXPORT_SYMBOL_GPL(kasan_mode);
 /* Whether to enable vmalloc tagging. */
 DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
 
+/* Sampling interval of page_alloc allocation (un)poisoning. */
+unsigned long kasan_page_alloc_sample = 1;
+
+DEFINE_PER_CPU(long, kasan_page_alloc_skip);
+
 /* kasan=off/on */
 static int __init early_kasan_flag(char *arg)
 {
@@ -122,6 +127,27 @@ static inline const char *kasan_mode_info(void)
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
+		kasan_page_alloc_sample = 1;
+		return -EINVAL;
+	}
+
+	return 0;
+}
+early_param("kasan.page_alloc.sample", early_kasan_flag_page_alloc_sample);
+
 /*
  * kasan_init_hw_tags_cpu() is called for each CPU.
  * Not marked as __init as a CPU can be hot-plugged after boot.
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index abbcc1b0eec5..ce0b30889587 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -42,6 +42,9 @@ enum kasan_mode {
 
 extern enum kasan_mode kasan_mode __ro_after_init;
 
+extern unsigned long kasan_page_alloc_sample;
+DECLARE_PER_CPU(long, kasan_page_alloc_skip);
+
 static inline bool kasan_vmalloc_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_vmalloc);
@@ -57,6 +60,17 @@ static inline bool kasan_sync_fault_possible(void)
 	return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
 }
 
+static inline bool kasan_sample_page_alloc(void)
+{
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
@@ -69,6 +83,11 @@ static inline bool kasan_sync_fault_possible(void)
 	return true;
 }
 
+static inline bool kasan_sample_page_alloc(void)
+{
+	return true;
+}
+
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #ifdef CONFIG_KASAN_GENERIC
diff --git a/mm/mempool.c b/mm/mempool.c
index 96488b13a1ef..d3b3702e5191 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -115,7 +115,7 @@ static void kasan_unpoison_element(mempool_t *pool, void *element)
 		kasan_unpoison_range(element, __ksize(element));
 	else if (pool->alloc == mempool_alloc_pages)
 		kasan_unpoison_pages(element, (unsigned long)pool->pool_data,
-				     false);
+				     false, false);
 }
 
 static __always_inline void add_element(mempool_t *pool, void *element)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 6e60657875d3..969b0e4f0046 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1367,6 +1367,8 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
  *    see the comment next to it.
  * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
  *    see the comment next to it.
+ * 4. The allocation is excluded from being checked due to sampling,
+ *    see the call to kasan_unpoison_pages.
  *
  * Poisoning pages during deferred memory init will greatly lengthen the
  * process and cause problem in large memory systems as the deferred pages
@@ -2476,7 +2478,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 {
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
-	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+	bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+	bool reset_tags = !zero_tags;
 	int i;
 
 	set_page_private(page, 0);
@@ -2499,30 +2502,43 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
+		if (kasan_unpoison_pages(page, order, init,
+					 gfp_flags & __GFP_KASAN_SAMPLE)) {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4c341c5609ed09ad6d52f937eeec28d142ff1f46.1669489329.git.andreyknvl%40google.com.
