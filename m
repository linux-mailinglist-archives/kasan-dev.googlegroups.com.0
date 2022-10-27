Return-Path: <kasan-dev+bncBAABBKOL5ONAMGQE2OZRUHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 58E01610264
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 22:10:18 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id xh12-20020a170906da8c00b007413144e87fsf1641374ejb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 13:10:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666901418; cv=pass;
        d=google.com; s=arc-20160816;
        b=ruc6EhS1EOHTSBaLEWsJlTNTKh9md94ShPg9mR1xobzkcZOOoReThVUfH/KLTrhg3d
         FEUxeLNxUp4ZalwmTDUV+qv2TogYOrrJsa3BlxsKds3PBpt8to9/MCM3QhylToDNiDIp
         WYOFdS3ldMRdb5Jv+sDOoNV15UHtPZcwSUt+dHy/V4Lu0ZSdGy8vmxitbIhIB7VNMeO7
         BXUVZCKA1G5mfOy2BSriVo5HJ601TQrSh+3qHenXwkh1NJwZPmq0R4rg6vnwV/wBe8eK
         UEk49L0RvleNfReyG5iYuROQn2UTr/kvxYQ0C+Niaa4THDHFhD+O6UHEtq6MLdHHXc7F
         HEHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=aQVwU3Qtnwjaxs+RZvSNPx2RNPLrjF50GCplH1quOYM=;
        b=rbDkE52JRPsXle3seCyav/uEfhxf9Yha+tI9l+7ceOat3Gk5byNlyizZaTt6Zxl7tl
         cHAWj44U7h9qt+MZwKKZ0xMG3lNbFd6XKplbyhYyYCcBZjMG79AV5/mjy3Tid+uff+w0
         VEAHnBTuw1kkpGqvBz8qgKOkeRFHd5ZzgY4qlLDH2moB0N5Ojzo84iFWj4ydrR6YZ7RW
         del+3mrXwHJ++J0qx1ev/OO9eDTqEvAmBWJe2/TrpOIvxhjulfKqVDF74EFXA2bz7hk3
         SbNcktKnm5dSGWb//8e7BGsk0wScZ04G4fOD7sRf0zRWUc3ChEEoQA60jmofxVo82XnP
         R2+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MLRzYvvq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aQVwU3Qtnwjaxs+RZvSNPx2RNPLrjF50GCplH1quOYM=;
        b=PZEtkcETxBWdSY2qM94bh2tC4zA8tTetfOCRHRmVnd2699Zlh6Qzhj8tN+13PKuaCS
         qYVGkqvpXWKz5AXmMsfY7KuzU9VoR+irE5UwonY6nxAs38hvOeHgwvYXfER+/9mQVv/D
         1Ee1PaIAVXB81yK6OXgXVQfpVP9bgovjGWJb90EYgz28l86tet8v7Bfd7e36uL+ngPkw
         H84eTr+wKdOawNQyiDi9m1tWFebKCugTdeu+Kx3eHMYp6JFbxLPobSRx451nYOtG5QEw
         vi48MKgrZ/JcI/iVSsYanvRh3e4wha4V1n4HllC2UovDGdqgARIm62GafN187h9Suo3e
         JHQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=aQVwU3Qtnwjaxs+RZvSNPx2RNPLrjF50GCplH1quOYM=;
        b=gzFnUGIKC+Sf3B2wZg4q/klGlpeLMFZztk+lOSVi9GTRq56tSu4T9PZApwv9l+Pb+l
         voGZiVAviobDz0q90EvQ7i3vAReDEKIdvBDfD6U0LEHjNY8U+qgbGOeUMN30bvMkiwBN
         pKhnfY/K5oAjSAAukAraZ4tejUdbI5dm+Exdv4wjULwqYDai1FkNC1UtXgIMPjebX9Gc
         HJfoC/5raFDO7c2mrkwrMqkCb7jp9cvwN6utqaFECD2IbgbJxSH8VFJOzkqgxnBKowjW
         XTzpnRM97pQcy85+aS86nnqDvV+nCsbAjF8zR3JvtWjKzMiqaOFHFCVAutOj1nF/OBPf
         pPpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2G1/oYEXgbMpSwvDjkI08tlZjqw/CGieyRpAjoHlD2pV2YFKoN
	sU5fV1D16IiRoT/4nbceYag=
X-Google-Smtp-Source: AMsMyM4qrSoUWIWlUSSwg+69yzrK4D4m9K8WlsERZIBk2cXbfAOmnMBIJ4xoiC/z1UFn7IUJFCMxnA==
X-Received: by 2002:a17:906:8a46:b0:7a0:b8ee:ac06 with SMTP id gx6-20020a1709068a4600b007a0b8eeac06mr26664590ejc.42.1666901417885;
        Thu, 27 Oct 2022 13:10:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4345:b0:791:9801:e4e4 with SMTP id
 z5-20020a170906434500b007919801e4e4ls17121ejm.3.-pod-prod-gmail; Thu, 27 Oct
 2022 13:10:17 -0700 (PDT)
X-Received: by 2002:a17:906:3287:b0:78d:8877:d50f with SMTP id 7-20020a170906328700b0078d8877d50fmr43339189ejw.486.1666901417081;
        Thu, 27 Oct 2022 13:10:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666901417; cv=none;
        d=google.com; s=arc-20160816;
        b=dsvnB9rU19pVXzz3MVLhlj+9wnfFaFYcZY6/bqR9ssjymKoNC+fmbwnXu9hWAsqway
         zrlTE+PspPC/WS352BCQ8rb9GLuMccmfST76+XVr6TnuBKDBPNlTPD/BwppOcEhVb+b4
         m/+2qIaSG7VDIE+cIL3pCiLMsoqpnxcG5c4GuA1PIL/IIM5xH8RPco7w+hwkOET1RBRH
         aVT7hq0XokbjH82cLO/fUF1C/ylwm/tnVLm120512L6jBgrwmEdD3FIWHyLCMeJlIZRy
         5Lt+YDxxHvgcqexb7hnVIAP5UvYQUOdHQVA1A3af4DtJbkLKcVuh/gt5p4dcK/APy0ZC
         CQOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OIqcZRUcgxs1qDADU8Zu6W54GU95YqrDSNAf8mGexD8=;
        b=rGuMEtcHwOCtyiZnrboRRdMtLRz1vFiAjQTgNvKA9+PvqFCCSXaCs9dzmtFIgx62yT
         siruujCuTX1q82WlnWuSHk4cpAJrWoKttDhtNt0pf6LIupn5CP25AkDL9nUGrCS5slC0
         PE59+S8CXHI7VOwGWjYHfTnkg05+8KKI6/PIrgW+sltgY9AF6eGyKZowF93xg4wkxudM
         pTSqDtl7btyAi8UNFfWUTBYIHz0TxfhspoZHuhUcdEhoSLOVTIRZXvqgRZHV2a9/ztJw
         CEwKSdNtN9fL7258qXid7FqGAXv6fmyO9D37vnSz1yvXmYmfwpVRh/qMQxc9UWiDdbKv
         kwxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MLRzYvvq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id ml21-20020a170906cc1500b0078d3ac8bbedsi57127ejb.0.2022.10.27.13.10.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Oct 2022 13:10:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan: allow sampling page_alloc allocations for HW_TAGS
Date: Thu, 27 Oct 2022 22:10:09 +0200
Message-Id: <c124467c401e9d44dd35a36fdae1c48e4e505e9e.1666901317.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=MLRzYvvq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
Hardware Tag-Based KASAN tag only every Nth page_alloc allocation.

As Hardware Tag-Based KASAN is intended to be used in production, its
performance impact is crucial. As page_alloc allocations tend to be big,
tagging and checking all such allocations introduces a significant
slowdown in some testing scenarios. The new flag allows to alleviate
that slowdown.

Enabling page_alloc sampling has a downside: KASAN will miss bad accesses
to a page_alloc allocation that has not been tagged.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst |  4 +++
 include/linux/kasan.h             |  7 ++---
 mm/kasan/common.c                 |  9 +++++--
 mm/kasan/hw_tags.c                | 26 +++++++++++++++++++
 mm/kasan/kasan.h                  | 15 +++++++++++
 mm/page_alloc.c                   | 43 +++++++++++++++++++++----------
 6 files changed, 85 insertions(+), 19 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 5c93ab915049..bd97301845ef 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -140,6 +140,10 @@ disabling KASAN altogether or controlling its features:
 - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
   allocations (default: ``on``).
 
+- ``kasan.page_alloc.sample=<sampling frequency>`` makes KASAN tag only
+  every Nth page_alloc allocation, where N is the value of the parameter
+  (default: ``1``).
+
 Error reports
 ~~~~~~~~~~~~~
 
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d811b3d7d2a1..d45d45dfd007 100644
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
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 833bf2cfd2a3..1f30080a7a4c 100644
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
+	if (!kasan_sample_page_alloc())
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
index b22c4f461cb0..aa3b5a080297 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -59,6 +59,11 @@ EXPORT_SYMBOL_GPL(kasan_mode);
 /* Whether to enable vmalloc tagging. */
 DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
 
+/* Frequency of page_alloc allocation poisoning. */
+unsigned long kasan_page_alloc_sample = 1;
+
+DEFINE_PER_CPU(unsigned long, kasan_page_alloc_count);
+
 /* kasan=off/on */
 static int __init early_kasan_flag(char *arg)
 {
@@ -122,6 +127,27 @@ static inline const char *kasan_mode_info(void)
 		return "sync";
 }
 
+/* kasan.page_alloc.sample=<sampling frequency> */
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
+	if (!kasan_page_alloc_sample) {
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
index abbcc1b0eec5..ee67eb35f4a7 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -42,6 +42,9 @@ enum kasan_mode {
 
 extern enum kasan_mode kasan_mode __ro_after_init;
 
+extern unsigned long kasan_page_alloc_sample;
+DECLARE_PER_CPU(unsigned long, kasan_page_alloc_count);
+
 static inline bool kasan_vmalloc_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_vmalloc);
@@ -57,6 +60,13 @@ static inline bool kasan_sync_fault_possible(void)
 	return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
 }
 
+static inline bool kasan_sample_page_alloc(void)
+{
+	unsigned long *count = this_cpu_ptr(&kasan_page_alloc_count);
+
+	return (*count)++ % kasan_page_alloc_sample == 0;
+}
+
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_async_fault_possible(void)
@@ -69,6 +79,11 @@ static inline bool kasan_sync_fault_possible(void)
 	return true;
 }
 
+static inline bool kasan_sample_page_alloc(void)
+{
+	return true;
+}
+
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #ifdef CONFIG_KASAN_GENERIC
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index b5a6c815ae28..0b36456aedfb 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1366,6 +1366,8 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
  *    see the comment next to it.
  * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
  *    see the comment next to it.
+ * 4. The allocation is excluded from being checked due to sampling,
+ *    see the call to kasan_unpoison_pages.
  *
  * Poisoning pages during deferred memory init will greatly lengthen the
  * process and cause problem in large memory systems as the deferred pages
@@ -2475,7 +2477,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 {
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
-	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+	bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+	bool reset_tags = !zero_tags;
 	int i;
 
 	set_page_private(page, 0);
@@ -2498,30 +2501,42 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c124467c401e9d44dd35a36fdae1c48e4e505e9e.1666901317.git.andreyknvl%40google.com.
