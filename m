Return-Path: <kasan-dev+bncBD52JJ7JXILRBZGAU2JQMGQEHS3O5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id F3DBE512331
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 21:58:29 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id l5-20020a170902ec0500b0015cf1cfa4eesf1495746pld.17
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 12:58:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651089508; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzR1C1Z4+K98GgrnPZUznsQcrITCHMrnn+z2CxxSPgT6wgitpe1GD4fBP/8CpeYTj4
         VUrfT3Hvo0qpi0cHp107ARE4g1kuAzSw1gnDKRdVhsNYkIkew1uiXel/VIDay5vJ2VHT
         bpGa8JDvyT/5U+4dSJVKQ9FiGc/e9s5psBs7+8s+JojILBJYqL0fYaBkojhtL2g9Vveg
         EWXYHM9kZ2hSedU4o3XoXzja8b2nD01hgmHkwV9FPj981Sg4co1icQN1DxSlk5YPmUFX
         OJ9bWOIxFCm3pZTI9ptj8nQyyyltL7b80W+YaFUBBrMGzwYOBnnZOs1Pz8H4L1n1MzQN
         T3/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=EB6E7fP9bwrsqgGYYvyfgDttoeJUQfEvL5DstWeF6cg=;
        b=RMM7g7sdCMOywXwWnjyBJcAGkUMGyAcxagO318alNNl8fUSCNs4W4xJUyjX4cOED2d
         O9NoVcl3RyVDRnROQqr7jvKkY1zebv4xyV1dqUOLhokOGMIwbBnmrtgCnmIGGYdN4e7K
         lNiHuPsa5MBQ09ySFM3UimSvM84hgEFNhJkL/GM6EdeJ1OA2xib1Shxf43xqjRNay+0C
         Dnl1L0EZZa02BJmTF3XpuFuz5FhttBkH7tL0QsU+JY4tq81hUL2j27UoUAOD+wG5vliz
         H5Xpl5Djr2zhX2So0OGqkeOEux1dx6umt/U6XX62ZE4uJwbopjF+JrOTx0PX0n1vAFgr
         lxoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ybb+mu0N;
       spf=pass (google.com: domain of 3y6bpygmkcwqreeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Y6BpYgMKCWQREEIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EB6E7fP9bwrsqgGYYvyfgDttoeJUQfEvL5DstWeF6cg=;
        b=cOhddeadbM0un7EUk7wf28IutshHXTB91uEAtJbb693onXYa97lCGO2xgcTfIHcpZp
         I4Op4EN3taint/j9mNyDht1SZKSuKpZ2R9tvICC1eAsd3nt1zyebICSExvf1I+dnuil0
         Wg709QGq2mjmNxA+IOoTx9oxzWDJoK89tNGSS9Yfu9Qc/eImAqldKVL2lSpge1eESK7z
         Ylxn6fhxGrXFaulfAd0OzAUiJhUXym5lme54loFdhx7iWolt/Vtv4rGfeWRtUNMPULeS
         ngtkmcHufVrDrXMl433KLt0I8HEU7Cz/N16KLa28UDV3RpV4TQ5JG7TXjsm2K0qFO8R3
         /jaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EB6E7fP9bwrsqgGYYvyfgDttoeJUQfEvL5DstWeF6cg=;
        b=a8D5ySshMA53tAC5/rcmMxSnNIwrO7KOwymMQdLBslfFB+Jf7fbZvn21nLm7wWB96q
         V/q0EVnQ5ZMexeOadJUAOwrIHdXrX/EsiJNoHXq5o/bnH4kKPShX3fTL4+OawZnaZoGN
         nYqUTg7H/34/LPJ1/KuntsUN0ax5saBcy+NJVuEu50AAxb/N5mGw42KWvgQTy04rS92S
         SL1t8CnZrHvdy5FZbfwu980p+J/xv76JGEcPVWcHkiZgg6XLGb2busEXnb6sa/UIymI8
         W2vWVkCRfnioLlD1YAtmTPCspkNQ5aEVMD+ba0vHgvvKl/tEjSQoQRQ+XnhjlcU3gRQg
         TJ9Q==
X-Gm-Message-State: AOAM533aJ3Ke2LhTUfF60S40iPnlVpuCw0yg5lwnzssjToFlr4Wl0GxV
	QE85PoXEFs8BBx9RZ5C6B0Y=
X-Google-Smtp-Source: ABdhPJy5LWQW2UvBLvLSjfwUeTHcB46f4X1l9C2w85/OK+tKLK5xKhAZn6jzc9kMjMx5v9tHMY5VxQ==
X-Received: by 2002:a17:90b:4b84:b0:1d2:ae96:6c27 with SMTP id lr4-20020a17090b4b8400b001d2ae966c27mr45874442pjb.70.1651089508675;
        Wed, 27 Apr 2022 12:58:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f82:b0:1db:302d:bc3e with SMTP id
 q2-20020a17090a4f8200b001db302dbc3els880956pjh.1.gmail; Wed, 27 Apr 2022
 12:58:28 -0700 (PDT)
X-Received: by 2002:a17:90b:38ca:b0:1da:4df6:a000 with SMTP id nn10-20020a17090b38ca00b001da4df6a000mr3227138pjb.188.1651089507889;
        Wed, 27 Apr 2022 12:58:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651089507; cv=none;
        d=google.com; s=arc-20160816;
        b=CKuG0ffYArRKEfrygtit3oCXrRnNcI42oGA2RdjP/botKeLukvsXn7y0pIiuCa0z7U
         8/rfVwuTcYw0ZSJIVy+cPADvpAz2vib0Is0nn390Sisn95RTF0NZmSw6Fi1SWtj1i2t7
         l2D+plovzhIwFE3+XNQiUDcNRKNZSFxElwxele2JMx26+5Jb1cCqMF0RC5/uyT1XwTRu
         M6wXh84AWas19XQ9a5N7P0s3snTomA8rZ5q0Y72ZpQpe+is/BaVNYveC7v3oHnCWmgJG
         A0uJ5RKRVatvROd44CoMBXRhQpVC7eQSYxiGDJ+XFvGAjnF97MpxLmGB8G7kZlNDJyan
         WmqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=KO6mnAXGVtsbAsRrqxqkdvUTskd4INz5fQ2/DuC94GY=;
        b=DWhE9fliHItSOU1Ay8rS1kJahBbjoAy5iq18EGQy68lXdkx4SIlc46L8VMFERaOEqj
         aw/kRLTkQowKWHnGV+6hTS53CqZNvWs0AReMV3t2Ix/CFxh5VazlzNqy4+qeKFpgHAux
         FR3cp9OOdPp2FT/gic1T96+yVXK7TFdKhOiPoWfJmfGZA4XukBlIQTpNme8rV+uCA33f
         LaNVSUWuTcTzUcrpSeoRmSwLDUb1B/3VbsZInNYyzUYPqyB5VIg1YQDRnJbkuO3VS6of
         G0wYd7VNYdSHiegz90y/5nY6DMeGIi/M4d9FIVVCUWV8Y7e/gzXrOLkkCc8OJmdDXnkl
         ltlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ybb+mu0N;
       spf=pass (google.com: domain of 3y6bpygmkcwqreeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Y6BpYgMKCWQREEIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id pi2-20020a17090b1e4200b001c62073e04asi237095pjb.2.2022.04.27.12.58.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 12:58:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y6bpygmkcwqreeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id b6-20020a253406000000b006484c081280so2632189yba.5
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 12:58:27 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:7bf6:862b:86da:9ce1])
 (user=pcc job=sendgmr) by 2002:a25:7796:0:b0:645:7353:637a with SMTP id
 s144-20020a257796000000b006457353637amr26817851ybc.446.1651089507164; Wed, 27
 Apr 2022 12:58:27 -0700 (PDT)
Date: Wed, 27 Apr 2022 12:58:20 -0700
In-Reply-To: <20220427195820.1716975-1-pcc@google.com>
Message-Id: <20220427195820.1716975-2-pcc@google.com>
Mime-Version: 1.0
References: <20220427195820.1716975-1-pcc@google.com>
X-Mailer: git-send-email 2.36.0.464.gb9c8b46e94-goog
Subject: [PATCH v5 2/2] mm: make minimum slab alignment a runtime property
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
 header.i=@google.com header.s=20210112 header.b=Ybb+mu0N;       spf=pass
 (google.com: domain of 3y6bpygmkcwqreeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Y6BpYgMKCWQREEIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--pcc.bounces.google.com;
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
2.36.0.464.gb9c8b46e94-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427195820.1716975-2-pcc%40google.com.
