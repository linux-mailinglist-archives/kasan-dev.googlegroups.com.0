Return-Path: <kasan-dev+bncBD52JJ7JXILRB3FNUGJQMGQEUXE2EAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 514EA510A81
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 22:32:46 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 53-20020a9d0eb8000000b00605d4aa1e35sf940870otj.23
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 13:32:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651005164; cv=pass;
        d=google.com; s=arc-20160816;
        b=t5U53w8WfCfh+QAhTonrNfWp8DPq5JqbTD/21wdJYImRa7e2MATbqTUP8txw0mBTVG
         MzGBh6qJYSrhU4SuqiXhQLnVD6pDPthAxk8qyNjBylqXEp2AWOWMUxBr5i4IbmADIhfU
         MD+i8izGzL7FDRS8wk7c6Q6xR21lO9V2XxFrhFjueS7PWbUcBvGJnQdj6ra2vXRBpxdy
         QzZu9HjSAy5skvd1wf4YDmYhm9N+MAyrBZyzA0zAVJNNrJo4Z9Vuvil440FpKYFhPYRE
         y7+U4ncFUlM8jTz0hS3h2u62YAtBnVNoAxOsEbTjr2sLiIgt9ONLEZjhCyZYSH2L/5ps
         pzJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=aPqJBqNdQvsGsxYSdYX36Qg8tpnPdThb5kbdjR6Wplg=;
        b=03xbRAoHFdn5n1pKrhZfM6WATZF3lxl+30a8aK+pC2lSdDZo/hYgvGBNYaExyxw8Hd
         kD7fmxHL0Lj+EipYi+p4LK052Blg2oelsxKpLpM1YNvzULt/b/BpfbelBlkPvfnbpe0n
         MTAgFHoXTNqWDif10szRlXwwSGyOPvG28c3rUsiWBftaEKr5xlbZM1du6TBqCmPmffIl
         jzMl3yjqTxDA8jV2T0BZCv/8sieKSU9HvYjk1a/FsX1UGWmBaYGgwOOPlOdK+www+o2A
         5lw1ATj6SfNlmf3Y79CQW3tzAJ5DT4Lzn+djmHWiG+K+sO2qulfkYILZWt0CeWd3Pvpp
         3EIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NzL50QDr;
       spf=pass (google.com: domain of 361zoygmkcvqbyy2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=361ZoYgMKCVQByy2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aPqJBqNdQvsGsxYSdYX36Qg8tpnPdThb5kbdjR6Wplg=;
        b=B6aPKr2S9nPGSO7uAEKWX/bKcBdMHyFLsCgjIppAKYjqyVtNNyOXwy0i8YEz8Q4KM6
         gvcUP3DVDFevRG8oC4fcaQH731wkP9Xoe19g20Bj38d4/eDl99qgnGSAF/ho4m8/26vp
         FxYQ5ZZLpEi/eySH2Hkt/sjxRQxa3wVEFU+XLuVKCHMu9tdcjANI7CoQtjhApf8T5KBs
         et4VGfLFZzVyn82VW6t2FhyK3pyuJTKw2z+gDV+NNpzkMwOOjt2BpOUSKU1CiRuqNWxS
         SzeDM2YZwtsQSMlA/apZh4mK74d7eApq7vRN6ktOhSNcqOJMp7b+wD7UK/YclypZH2qZ
         uaeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aPqJBqNdQvsGsxYSdYX36Qg8tpnPdThb5kbdjR6Wplg=;
        b=XBNTrtr+5ULXt4kgQKup0bOoTP7u9+wu1OSDiCIiVXQiVRgCnED3KB6s4elPtM1uLW
         rZGYifYVR8kQziYt0rCYFmafJcASZOBgADB+bNhB8cDEjBJ4Hazb6J39ZLNqagTKQoyM
         uU8PhNz63s43nJi3uShLec7GK8kMMgyTdxMj4HqYAhQkH0++gsOxeLu7XiG+9/Rb3HAl
         OkyskThAn1MXlMrn4E6lX8Jg/payIBkeH4br/4fhMz50NDt1S8UScNyzu+H/yLzE13+d
         Jew9HD9UM6/n3VHge7SRiIq3ixwYcOrNaDzStI4L+d4dDoHsUBfKN0K/kCFBXQU2VviM
         iygQ==
X-Gm-Message-State: AOAM5317G281jorwmp278Ldxx7yfmstbUaIV6vJ0WWVwsfebClGOHWV7
	wVSgorpMCVSiCsqHIiycXdg=
X-Google-Smtp-Source: ABdhPJyE1r2i5e70dq4eHGVOq9l+VxuQ1CmnmJWO45bPqxS8syhfIULPrCtSpdgMuhHfcOEtIpF57w==
X-Received: by 2002:a05:6870:d68e:b0:e2:af08:6cc3 with SMTP id z14-20020a056870d68e00b000e2af086cc3mr14276645oap.189.1651005164762;
        Tue, 26 Apr 2022 13:32:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:13cd:b0:de:c1c1:ac0e with SMTP id
 13-20020a05687013cd00b000dec1c1ac0els5067421oat.8.gmail; Tue, 26 Apr 2022
 13:32:44 -0700 (PDT)
X-Received: by 2002:a05:6870:ec9f:b0:e9:18a5:436d with SMTP id eo31-20020a056870ec9f00b000e918a5436dmr7116871oab.151.1651005164350;
        Tue, 26 Apr 2022 13:32:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651005164; cv=none;
        d=google.com; s=arc-20160816;
        b=XtXIfB4qM+NHuLFzXoaEPoITLSWXjlGkpzJp+ZTSXDNJJj3CTK2qQMd1ylSoTonC/q
         rba/8ufO5eSWjlzUCiCnCoU9m2kL3ke4eZUW7zRIe0OT2Ma0YxnjW3rRuj6dtPqLraCd
         /MAtA4dtrIt0n+5wIKR9TZIsjk6cgwHr4rvohoNbiy0Ge8DjvnxbXNQKm9aqyFyHU6pU
         f5brOOE469+fyAZWuPTzSIjPOkWmy64h7ZYBm/MZTd7Lc0js2ESao0eLASUuW4HEEIZ9
         15orcPg/3qsnfqLnM26MsW+JYDYCDKodytU9DiojxdHVr0WMYHvWU/Tokp5hVGhON9UR
         NkkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ltoHorK2wXcd+a1S2OPAtE1WX5XYl1FW0si4xQoCroE=;
        b=wIVYbqCtrE5J60+Nbit/hhXTx5TRRxpIBEmK6YTsfo3t6n/dm7cVIFhg6t5O5PSS8q
         Xos4SqWnyvIZ68bunwGGHzKjBrQsM2bF5HqlDHQaCEYEjqDYMHMrd6+xr0FghYuHGwbl
         hSZrHWmvBnFJb/b/QG3UzY02GgNd7nVwDtBVl8NULxJtrHq0cesDgWTEzN1C9ULchcRX
         TeYYidyA7uGszsehW4U68YAXhzqUkIKXdxwQWCe0wcM5i/rM4/3ZPmXACeezwRhL02oD
         XIKTrwApplmVonS56tIYp4UR6moX3dOZhyMYT8rQXzSy3regdQuFsCTXTINergptAJ1h
         QrUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NzL50QDr;
       spf=pass (google.com: domain of 361zoygmkcvqbyy2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=361ZoYgMKCVQByy2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id x56-20020a05683040b800b005e6c62a483dsi1401298ott.0.2022.04.26.13.32.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 13:32:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 361zoygmkcvqbyy2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-2f4dfd09d7fso124171727b3.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 13:32:44 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:709f:5eff:336a:4109])
 (user=pcc job=sendgmr) by 2002:a81:9146:0:b0:2f7:da3d:8bfa with SMTP id
 i67-20020a819146000000b002f7da3d8bfamr13154889ywg.206.1651005163884; Tue, 26
 Apr 2022 13:32:43 -0700 (PDT)
Date: Tue, 26 Apr 2022 13:32:31 -0700
In-Reply-To: <20220426203231.2107365-1-pcc@google.com>
Message-Id: <20220426203231.2107365-2-pcc@google.com>
Mime-Version: 1.0
References: <20220426203231.2107365-1-pcc@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v4 2/2] mm: make minimum slab alignment a runtime property
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, vbabka@suse.cz, penberg@kernel.org, 
	roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com, rientjes@google.com, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NzL50QDr;       spf=pass
 (google.com: domain of 361zoygmkcvqbyy2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=361ZoYgMKCVQByy2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
slab alignment to 16. This happens even if MTE is not supported in
hardware or disabled via kasan=off, which creates an unnecessary
memory overhead in those cases. Eliminate this overhead by making
the minimum slab alignment a runtime property and only aligning to
16 if KASAN is enabled at runtime.

On a DragonBoard 845c (non-MTE hardware) with a kernel built with
CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
boot I see the following Slab measurements in /proc/meminfo (median
of 3 reboots):

Before: 169020 kB
After:  167304 kB

Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
Signed-off-by: Peter Collingbourne <pcc@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Acked-by: David Rientjes <rientjes@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
v4:
- add a dependent patch to fix the build with CONFIG_JUMP_LABEL disabled

v3:
- go back to ARCH_SLAB_MINALIGN
- revert changes to fs/binfmt_flat.c
- update arch_slab_minalign() comment to say that it must be a power of two

v2:
- use max instead of max_t in flat_stack_align()

 arch/arm64/include/asm/cache.h | 17 ++++++++++++-----
 include/linux/slab.h           | 12 ++++++++++++
 mm/slab.c                      |  7 +++----
 mm/slab_common.c               |  3 +--
 mm/slob.c                      |  6 +++---
 5 files changed, 31 insertions(+), 14 deletions(-)

diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
index a074459f8f2f..22b22dc1b1b5 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte-def.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
@@ -49,16 +50,22 @@
  */
 #define ARCH_DMA_MINALIGN	(128)
 
+#ifndef __ASSEMBLY__
+
+#include <linux/bitops.h>
+#include <linux/kasan-enabled.h>
+
 #ifdef CONFIG_KASAN_SW_TAGS
 #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
 #elif defined(CONFIG_KASAN_HW_TAGS)
-#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
+static inline size_t arch_slab_minalign(void)
+{
+	return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
+					 __alignof__(unsigned long long);
+}
+#define arch_slab_minalign() arch_slab_minalign()
 #endif
 
-#ifndef __ASSEMBLY__
-
-#include <linux/bitops.h>
-
 #define ICACHEF_ALIASING	0
 #define ICACHEF_VPIPT		1
 extern unsigned long __icache_flags;
diff --git a/include/linux/slab.h b/include/linux/slab.h
index 373b3ef99f4e..2c7190db4cc0 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -209,6 +209,18 @@ void kmem_dump_obj(void *object);
 #define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
 #endif
 
+/*
+ * Arches can define this function if they want to decide the minimum slab
+ * alignment at runtime. The value returned by the function must be a power
+ * of two and >= ARCH_SLAB_MINALIGN.
+ */
+#ifndef arch_slab_minalign
+static inline size_t arch_slab_minalign(void)
+{
+	return ARCH_SLAB_MINALIGN;
+}
+#endif
+
 /*
  * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
  * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MINALIGN
diff --git a/mm/slab.c b/mm/slab.c
index 0edb474edef1..97b756976c8b 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3009,10 +3009,9 @@ static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
 	objp += obj_offset(cachep);
 	if (cachep->ctor && cachep->flags & SLAB_POISON)
 		cachep->ctor(objp);
-	if (ARCH_SLAB_MINALIGN &&
-	    ((unsigned long)objp & (ARCH_SLAB_MINALIGN-1))) {
-		pr_err("0x%px: not aligned to ARCH_SLAB_MINALIGN=%d\n",
-		       objp, (int)ARCH_SLAB_MINALIGN);
+	if ((unsigned long)objp & (arch_slab_minalign() - 1)) {
+		pr_err("0x%px: not aligned to arch_slab_minalign()=%d\n", objp,
+		       (int)arch_slab_minalign());
 	}
 	return objp;
 }
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 2b3206a2c3b5..33cc49810a54 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -154,8 +154,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
 		align = max(align, ralign);
 	}
 
-	if (align < ARCH_SLAB_MINALIGN)
-		align = ARCH_SLAB_MINALIGN;
+	align = max_t(size_t, align, arch_slab_minalign());
 
 	return ALIGN(align, sizeof(void *));
 }
diff --git a/mm/slob.c b/mm/slob.c
index 40ea6e2d4ccd..3bd2669bd690 100644
--- a/mm/slob.c
+++ b/mm/slob.c
@@ -478,7 +478,7 @@ static __always_inline void *
 __do_kmalloc_node(size_t size, gfp_t gfp, int node, unsigned long caller)
 {
 	unsigned int *m;
-	int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
+	int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
 	void *ret;
 
 	gfp &= gfp_allowed_mask;
@@ -555,7 +555,7 @@ void kfree(const void *block)
 
 	sp = virt_to_folio(block);
 	if (folio_test_slab(sp)) {
-		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
+		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
 		unsigned int *m = (unsigned int *)(block - align);
 		slob_free(m, *m + align);
 	} else {
@@ -584,7 +584,7 @@ size_t __ksize(const void *block)
 	if (unlikely(!folio_test_slab(folio)))
 		return folio_size(folio);
 
-	align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
+	align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
 	m = (unsigned int *)(block - align);
 	return SLOB_UNITS(*m) * SLOB_UNIT;
 }
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426203231.2107365-2-pcc%40google.com.
