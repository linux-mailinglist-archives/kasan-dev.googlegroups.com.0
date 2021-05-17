Return-Path: <kasan-dev+bncBCJZXCHARQJRBCMFRSCQMGQEZP7AB5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id DBEEF386DF4
	for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 01:55:54 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id g14-20020a056a00078eb02902d7e2fb2c06sf4757944pfu.13
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 16:55:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621295753; cv=pass;
        d=google.com; s=arc-20160816;
        b=lUMjA4x9eJ5fU8tuMqktFiRtIGG/fXfW+nJPDJDroLXbS5ggQ1NBs/t7yr0/J0hdbQ
         bWuZZ6ZL82dyi54MaN8zpFcrR9VUYvjpLHmXq7B+7TKg/JD9Qs9r+saavghRG3ofOKmb
         XQK9D9cRST166zUm6zrRNmtN7/L42hAqBwnCLiRMTz+NfQOBRCrZH/jvsRQ4xc/IajpH
         SCcHA1GWpH+0iCx15bTyFSF36lULKy67Tqd+mvuHLVQlwLtOO10hmuXshyoLbAzc+Wd0
         Bj6bK66pRIlHnIkbo8zEFmJ72BUlfvi5o/b5cS03+uLzbMKOooOIpQ60N1Gv0dW1RO5F
         MuqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=bhjmHV0CrXAMOCrPflL63ifJoO/2q53jGosjDIIEvIU=;
        b=mFLgg7SJe0xguPDkt2qDy6RgTe/UUi8fSXEXlyoiud8v1sTUXyazQuGlrkVzFE+MTe
         caaGAsop69O6K6qdvuhFHDfYBSLw7ISIU/7jTp+bJaIkDKZCzRTI/mpeMx3cH95NCWra
         JQ9A8cVZQgbwKgGuFTx16EgrkB/4zU1b8TzxNdJi4GJEiNqCk/m20sQ4725pUVdXfyci
         H5XiKe1ZwJWiSxIidzBpRxJmLfElOMXRN3SKh82zTyx2+OjKPeElXGHQxfPyE2sCY4bo
         BLdWFMe1L94OkXHiW7lNQTvfoMqTn9C8XFvbqSHzg8VN769asIeECIDJF1pX7/4mLd8z
         G/fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f7J+W6v+;
       spf=pass (google.com: domain of 3iakjyackcsufvhfojthpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3iAKjYAcKCSUFVHFOJTHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=bhjmHV0CrXAMOCrPflL63ifJoO/2q53jGosjDIIEvIU=;
        b=BhWFgWcixeZaTjgpw6j7f1bBZNCwQ5CLcZbNhKh/pJvRSLDUaMAVBZlKiyvRbJnfno
         +1gyCCTLiYcLiSAiaWyTkz6MZ1pRTbkMspAX+T8tlPRhcdceC1CcdDdh5+BN1Sqqwuvx
         7a2l2fg9udTUdwctgiLQDc0JjQSPIcUHvR9e1GjecRD8QqwmzjinIAef6J8AS43d+32H
         CM7IAgr6y4uEUmeZWamFwSkauNQFRqlr51nVM/CAj6SqhBaepRWI+LOqKxDHD9bqW6la
         5yGI7N6oHXN8VD3lDW7BCwK2WSQ/q/oAbPTn5ppCTkln6kc9lgTUX2ys01Dps5LoffJL
         exZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bhjmHV0CrXAMOCrPflL63ifJoO/2q53jGosjDIIEvIU=;
        b=ju326yqy2BkV3czlTfWz2R1VqBo0VQEkp1Sb366/tAiimk4F+ITPWngm7OhiSsSrCf
         cYLU47hvrg7MMOtrIrusaehRURhNheUD1uZVC7dL7YYjwL18ASY8Y6F07z0a8qVSYmSC
         SpSgUCKOgcreWGmUT7ETz3qv6Q+ent+SaNu2NJz7yj4/AqVVIvDIwJ8ykzREZpZBaOsN
         C+kazcw46/88SMJouenIjTe+2pZ+p3fLpu7sQ5zMUTNuGHkzLl3H98HNN2X45NW2LtO0
         vNXmxHl49AK75RHG0EdF2jTOdvMMb7HKh2ZY9LpUzztf49C3pJZsDg7yREvbE17VlOmd
         5h3Q==
X-Gm-Message-State: AOAM531agwQRaVJnq9kOe4pprN/3GaSkaaZTvUykuJFNTz8AYhhV/Kzi
	jyqC6DEmkEHg9B5WPc+XuHA=
X-Google-Smtp-Source: ABdhPJwWFunDBhsFHsG5qTCOsa0bjSKMAZS3coHtmblbozyrHdsndZMc1l3hU9Cyv/3ir8Gp8lBVRw==
X-Received: by 2002:a63:7d12:: with SMTP id y18mr2033903pgc.130.1621295753653;
        Mon, 17 May 2021 16:55:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c401:: with SMTP id i1ls467291pjt.0.canary-gmail;
 Mon, 17 May 2021 16:55:53 -0700 (PDT)
X-Received: by 2002:a17:902:dcce:b029:ef:339:fa6a with SMTP id t14-20020a170902dcceb02900ef0339fa6amr1228936pll.24.1621295753173;
        Mon, 17 May 2021 16:55:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621295753; cv=none;
        d=google.com; s=arc-20160816;
        b=yIRa9lRD7u96T6k5KoShrNU3nM04OEImoXcmHvEc7LJHv8ZSv/v96v03XkLPKV+zIj
         pOzhFmLMyxB6Xhw1P3CIfimK/W77PMpIIpzXu1b0bT4cwxU0UFFKkpBgUS/V53JKIg9e
         JggIji1i+VnZfFgKcYq0ADhp6oGNP94MtGAiTY2sJl1mWuBka8kou8FYNnTOsnzKuPyI
         UCXTY25O3ps0yx42zKz7CVr9LnzMM5yWAZ65I2rdUTWkCl1QStYEahNFLjlUDvuOLbbN
         CrZOp3hxXpe8487Gw2qeF+AEdzyXG3tWX8NlYPvXZT4EGgZXMvewgLAG8EcfObOBkab7
         WbzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=pJYdEWZccGedi7sOusNpe9uQTsCIvJdO8bX0ACEO4b0=;
        b=l/wxj00bVJxsqO/ZlIhdodyV/eytfjqUSb7Sn/ErCgBRA1EhtN6B3/ETY4GZZGU52S
         e3Fg0Zk1l4qxp2ZtkkejD2371oSwv91D+gBvIBww+Dds7eBvPitW/qC6Q2MAreN5moTu
         fOJSpYQ11BxyYsPcIBY1fHB+YX7CA5bbbzHEEghjJc5RTb9MoltIHha4x9c6IRwTE5p7
         egbGEBWGoW4c9OLJSdk9xQirGfHF+Q1oNLBSwl+6PEg36FSwN53NjF2MS1prOMFBP0hK
         LNOCVGIf/zDq8NNkYzKXB1O6eJGi1tbgIXsREX9khrm8/fOOA0LYp2IJ2SI9AC+Xvhvl
         TpaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f7J+W6v+;
       spf=pass (google.com: domain of 3iakjyackcsufvhfojthpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3iAKjYAcKCSUFVHFOJTHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id z1si1294104pju.0.2021.05.17.16.55.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 May 2021 16:55:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iakjyackcsufvhfojthpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id w4-20020a0c8e440000b02901f0640ffdafso1138962qvb.13
        for <kasan-dev@googlegroups.com>; Mon, 17 May 2021 16:55:53 -0700 (PDT)
X-Received: from eugenis.svl.corp.google.com ([2620:15c:2ce:200:c60e:2f76:b979:5cae])
 (user=eugenis job=sendgmr) by 2002:a0c:e6c5:: with SMTP id
 l5mr2636123qvn.2.1621295752535; Mon, 17 May 2021 16:55:52 -0700 (PDT)
Date: Mon, 17 May 2021 16:55:46 -0700
Message-Id: <20210517235546.3038875-1-eugenis@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.751.gd2f1c929bd-goog
Subject: [PATCH v3] kasan: speed up mte_set_mem_tag_range
From: "'Evgenii Stepanov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Steven Price <steven.price@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: eugenis@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f7J+W6v+;       spf=pass
 (google.com: domain of 3iakjyackcsufvhfojthpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--eugenis.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3iAKjYAcKCSUFVHFOJTHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Evgenii Stepanov <eugenis@google.com>
Reply-To: Evgenii Stepanov <eugenis@google.com>
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

Use DC GVA / DC GZVA to speed up KASan memory tagging in HW tags mode.

The first cacheline is always tagged using STG/STZG even if the address is
cacheline-aligned, as benchmarks show it is faster than a conditional
branch.

Signed-off-by: Evgenii Stepanov <eugenis@google.com>
Co-developed-by: Peter Collingbourne <pcc@google.com>
Signed-off-by: Peter Collingbourne <pcc@google.com>
---
Changelog since v1:
- Added Co-developed-by.

Changelog since v2:
- Added Signed-off-by.

 arch/arm64/include/asm/mte-kasan.h | 40 +------------------
 arch/arm64/lib/Makefile            |  2 +
 arch/arm64/lib/mte-kasan.S         | 63 ++++++++++++++++++++++++++++++
 3 files changed, 66 insertions(+), 39 deletions(-)
 create mode 100644 arch/arm64/lib/mte-kasan.S

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index ddd4d17cf9a0..e29a0e2ab35c 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -48,45 +48,7 @@ static inline u8 mte_get_random_tag(void)
 	return mte_get_ptr_tag(addr);
 }
 
-/*
- * Assign allocation tags for a region of memory based on the pointer tag.
- * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
- * size must be non-zero and MTE_GRANULE_SIZE aligned.
- */
-static inline void mte_set_mem_tag_range(void *addr, size_t size,
-						u8 tag, bool init)
-{
-	u64 curr, end;
-
-	if (!size)
-		return;
-
-	curr = (u64)__tag_set(addr, tag);
-	end = curr + size;
-
-	/*
-	 * 'asm volatile' is required to prevent the compiler to move
-	 * the statement outside of the loop.
-	 */
-	if (init) {
-		do {
-			asm volatile(__MTE_PREAMBLE "stzg %0, [%0]"
-				     :
-				     : "r" (curr)
-				     : "memory");
-			curr += MTE_GRANULE_SIZE;
-		} while (curr != end);
-	} else {
-		do {
-			asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
-				     :
-				     : "r" (curr)
-				     : "memory");
-			curr += MTE_GRANULE_SIZE;
-		} while (curr != end);
-	}
-}
-
+void mte_set_mem_tag_range(void *addr, size_t size, u8 tag, bool init);
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
 void mte_init_tags(u64 max_tag);
diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
index d31e1169d9b8..c06ada79a437 100644
--- a/arch/arm64/lib/Makefile
+++ b/arch/arm64/lib/Makefile
@@ -18,3 +18,5 @@ obj-$(CONFIG_CRC32) += crc32.o
 obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 
 obj-$(CONFIG_ARM64_MTE) += mte.o
+
+obj-$(CONFIG_KASAN_HW_TAGS) += mte-kasan.o
diff --git a/arch/arm64/lib/mte-kasan.S b/arch/arm64/lib/mte-kasan.S
new file mode 100644
index 000000000000..9f6975e2af60
--- /dev/null
+++ b/arch/arm64/lib/mte-kasan.S
@@ -0,0 +1,63 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+/*
+ * Copyright (C) 2021 Google Inc.
+ */
+#include <linux/const.h>
+#include <linux/linkage.h>
+
+#include <asm/mte-def.h>
+
+	.arch	armv8.5-a+memtag
+
+	.macro  __set_mem_tag_range, stg, gva, start, size, linesize, tmp1, tmp2, tmp3
+	add	\tmp3, \start, \size
+	cmp	\size, \linesize, lsl #1
+	b.lt	.Lsmtr3_\@
+
+	sub	\tmp1, \linesize, #1
+	bic	\tmp2, \tmp3, \tmp1
+	orr	\tmp1, \start, \tmp1
+
+.Lsmtr1_\@:
+	\stg	\start, [\start], #MTE_GRANULE_SIZE
+	cmp	\start, \tmp1
+	b.lt	.Lsmtr1_\@
+
+.Lsmtr2_\@:
+	dc	\gva, \start
+	add	\start, \start, \linesize
+	cmp	\start, \tmp2
+	b.lt	.Lsmtr2_\@
+
+.Lsmtr3_\@:
+	cmp	\start, \tmp3
+	b.ge	.Lsmtr4_\@
+	\stg	\start, [\start], #MTE_GRANULE_SIZE
+	b	.Lsmtr3_\@
+.Lsmtr4_\@:
+	.endm
+
+/*
+ * Assign allocation tags for a region of memory based on the pointer tag.
+ * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
+ * size must be non-zero and MTE_GRANULE_SIZE aligned.
+ *   x0 - start address
+ *   x1 - region size
+ *   x2 - tag
+ *   x3 - bool init
+ */
+SYM_FUNC_START(mte_set_mem_tag_range)
+	mrs	x4, dczid_el0
+	and	w4, w4, #0xf
+	mov	x5, #4
+	lsl	x4, x5, x4
+
+	bfi	x0, x2, #56, #8
+
+	cbz	x3, .Lnoinit
+	__set_mem_tag_range stzg, gzva, x0, x1, x4, x2, x3, x5
+	ret
+.Lnoinit:
+	__set_mem_tag_range stg, gva, x0, x1, x4, x2, x3, x5
+	ret
+SYM_FUNC_END(mte_set_mem_tag_range)
-- 
2.31.1.751.gd2f1c929bd-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517235546.3038875-1-eugenis%40google.com.
