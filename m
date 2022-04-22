Return-Path: <kasan-dev+bncBD52JJ7JXILRBIU3RSJQMGQEVDQBMVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CF5F50C0A2
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 22:18:43 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id x23-20020a170902b41700b0015906c1ea31sf5332945plr.20
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 13:18:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650658722; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ht+g1IBUGk40O28aWykpFrYAAUZDHVUQ7TVcbWRJz6xaiPiwJ1uf0tmSjlRxdIclOe
         1LtMqoY3KZNLOrlC8yyr3JFErJDn+B3Iq+s8jZSn+ZIp8+UhkDAuECtpQFlV1qHO4jJ3
         95M5BJyvrM1wNZ/q3/Ryh3ad50hvg2NLK+PCoxBwxyTH5KGg/YZAlmBXxRkc9jepWjhK
         JMmOr27iE42ycWk9H9d4ko33t/HxY3mDeCGkqVGJV4PAeBeQmrOgUN14BxD6ouZk6y/d
         IAZCZ6+YOzwzyrIRtfwQvJM7BIkFLKjjBrta56eg4bOK76KsiVPNAWj2gGNCorldx17j
         WZ4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=crcmiJ+wwRjnYW92ECaxqcN7Hld6R6O6Cw54vgMY3JI=;
        b=h9uDfgZJsL1ZTNT9+8DJtpr0DnuA81NztrQnnhX5sMZEA8x3neSUOiSSV6wegqL1vw
         rilb0M4pgqPAE2VpQUJNdJ644CnnnAQYA17kGxmVLGysSnrhn8EH5VYfyUmVS+gMiGgo
         WW4jSFJl0mzqFllHYZzzM7qpM3UvDpdDgurotRHVUE+o+n9T7O0ZfO5H0G+nZ6QUyh8Z
         Ew+qoNWkTe5o1DUtzxO690eHmzGcSc6q2x5g/wF87a/dDoJplBqLOS5Hp/PJdLiCjC6K
         yOITZlVK+fgYMCke1YLqzyxVormJ0W4ULkXq6MRCINn4GWHgbYvaZG3NCFBTdeJFm0QP
         4hqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F83iESBW;
       spf=pass (google.com: domain of 3oa1jygmkcweobbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oA1jYgMKCWEOBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=crcmiJ+wwRjnYW92ECaxqcN7Hld6R6O6Cw54vgMY3JI=;
        b=DnRkr6/L/a7WqAlaHqbJRnbplHTyFeZL5IXuP1hGsNdiybff1mVa5I68K290o9cgHd
         mt8dbxclSGy3AFvZsbh/s192Ht9WZNp/B0LCi0BTIgwMMtxSPA6XwOOV7VDF+an3KgLT
         RkF4j1lvS+jVb1fD7lQD6TwenOcaJgnenw0jakTstbsx9r2+OLAnAtHxAnHRYBkyB+rv
         uIjK6gRZiZEpCTd4yqU0GRfbhV3vJ4axUK+r69kvHMhz94y52bKa9gWRnZ+01EMOrqgM
         VgzlwSgy1cHyTzn/4sgfMFaIT3N6GiqVBrLjyfCjCY3RXp+AQ7lBf1z2NykY5hyJVal/
         xi9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=crcmiJ+wwRjnYW92ECaxqcN7Hld6R6O6Cw54vgMY3JI=;
        b=FW32IwaChVIstnU6bl0icSgFbYqZ2KY53u6uDtcXKe5QK9UrjBpaAKbCDNlKBgqgdA
         RBiwsbAMXv5zmD7v8M9Pay+w7lU8qQh/rgFWfhwI/Ey1LsZAkdE+Dvr/oGsbrSEeqSdO
         DO9K6XA5rfiNqB01LgbrgIIWsO1IQN6hZPo94VJJgcOvsIx1a0CjELxSZ2UEzKNNxQco
         30W8lD5y1hJutGjrOUBdYK802hP7+bsXu6VI4PLEOdbdhBnaFxpJs6MRh2MQ/kGl4Ie2
         O0EXV+fzB6/v8Tou6OxxZme3N8QpA3dgEaOiHl7ctqwbeKLslxNHubQ6YO13avuEBBEh
         qz/A==
X-Gm-Message-State: AOAM5331nNVDGhox+9JJw3pCA7hlCPCbxdjpXJ6wrsbjied/hqHA5kad
	oydxPJlrkvZyqsZaELMJlZU=
X-Google-Smtp-Source: ABdhPJzfu9ZGwxgHJUWx1QsuDLOl3sUV6aGbI4pHkR5lWI4AKU5Usw/El0QDhCwdQTdmKOjd7aMwQg==
X-Received: by 2002:a17:902:e812:b0:15c:5458:d1db with SMTP id u18-20020a170902e81200b0015c5458d1dbmr3807067plg.5.1650658722158;
        Fri, 22 Apr 2022 13:18:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1250:b0:50a:cb82:10ea with SMTP id
 u16-20020a056a00125000b0050acb8210eals584919pfi.4.gmail; Fri, 22 Apr 2022
 13:18:41 -0700 (PDT)
X-Received: by 2002:a65:5a8e:0:b0:365:3b6:47fb with SMTP id c14-20020a655a8e000000b0036503b647fbmr5334966pgt.147.1650658721399;
        Fri, 22 Apr 2022 13:18:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650658721; cv=none;
        d=google.com; s=arc-20160816;
        b=GwyH7w9I84zjYnmj0TnHDHwB4XnOGWD4lbuNNi+MW4sE2+dCYIMrSU6A2KLendOMKL
         x9nKjkB47uD0Y9K9VTOaXkstRcqJGr4+0DznhKNelJaM80HmuN60d8cDBhzwG6E/6Ll/
         TCm1AKsHU1PdKdyjTkGxvitlrAwfLFdgXq88VRxgeqG1DILwKe7efWP1M7ecmKf2SjTu
         L2rSUTf2weZLtSupE+Ypbko4pKbhAtkYd5M7b3nZ4Cr3GQ3BWNJKDWFhxjFiCBK/bIeS
         3VwGvSFY98RG+p/wYEU6n1Q1J/29ZX4JrW4bPSsSTwSADe63QkOHvD0E/treyPQs5XXa
         K4rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=eMAERF62YTPWtGAsO2YVmQloDH5oUr4o6LySCLx0+Cc=;
        b=felgynb2PhggB9bVV4svVj6vB3o8fMKbWny96K8wJtNcwPbQnBjbxdP6kG5OZR8Yxu
         ndnMBzq/x7tqJUMNyqOldB1wKC9IYinPPG3Q+vlJeYh5LkJ6B1C+c7NCOk/X7nj19jJf
         ZLDt7YOiZL8H9WopPz4ZTAC4zzh+/8yuJCyai/jnYSjIUx08f+b/pToxR9NKkV4z2DHo
         HZEbBvDRrfqx0C8bv3ENIBsN9+Vt/oGH5JfXCK9p0TnQTsHfBKebNcQx6sxV7mm3entp
         4eXRNkrrrHxwtMbI+Fh6w1vCJuuaWXDVrU9oh92pxar41GXMp+D+UGxvONQVeH/Ri0dW
         5pBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F83iESBW;
       spf=pass (google.com: domain of 3oa1jygmkcweobbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oA1jYgMKCWEOBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q20-20020a170902edd400b0014f3d55ede2si648475plk.2.2022.04.22.13.18.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 13:18:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oa1jygmkcweobbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id d129-20020a254f87000000b006411bf3f331so8076617ybb.4
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 13:18:41 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:b874:60b4:62b:9c7a])
 (user=pcc job=sendgmr) by 2002:a81:2654:0:b0:2f7:c5f4:a486 with SMTP id
 m81-20020a812654000000b002f7c5f4a486mr265675ywm.141.1650658720646; Fri, 22
 Apr 2022 13:18:40 -0700 (PDT)
Date: Fri, 22 Apr 2022 13:18:30 -0700
Message-Id: <20220422201830.288018-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3] mm: make minimum slab alignment a runtime property
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
 header.i=@google.com header.s=20210112 header.b=F83iESBW;       spf=pass
 (google.com: domain of 3oa1jygmkcweobbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oA1jYgMKCWEOBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
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
---
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220422201830.288018-1-pcc%40google.com.
