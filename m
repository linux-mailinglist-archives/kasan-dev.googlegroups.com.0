Return-Path: <kasan-dev+bncBCJZXCHARQJRB4X5ROCQMGQEBJLZCAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D2DDA386DCF
	for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 01:40:35 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id k9-20020a63d1090000b029021091ebb84csf5238662pgg.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 16:40:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621294834; cv=pass;
        d=google.com; s=arc-20160816;
        b=NNTNpOgNw9uKMMMRMD11qMIrMVugDGjhdHJaJUxyvcH4VslyljCLk5xyOcKEtmeRnZ
         nw5wVy1JnOpgB4g2X+r0TjXBGW4Z13XX+phJ1ufxcM463BpPb1dX9JkD9dct0BuF2run
         ovmLSkAtDvnLqClyhhHhKVedfwRWipc+cR+POVdRojDjG04d5uqdwWPzdEbZTGQxjXVu
         5aVNrIGvJgI6oZc+dthetYM3gcocXSUmWDtEkrCGBIO0VbE9QbnCbsNic1YfHk1BWeXG
         KWmxYrQmoRhAT64XpE8fgjpMhx86u+0+6UeNbzEQ/Cre2BL402PLz4C7zGcMDiTm1Cxs
         kcuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=a2L4dsiN6MBX0a1zZl1DuSdgCbf3SQ0z20pJ/vHEJ68=;
        b=RqRs0obsSC7plxZXqdASS6kwFItsjktzDj0k5DK6sbmjUJVtwlJEOho0gk9j/dPKJO
         cKrxjo5gv168g1Fg03VP+ELFQAQVqkeKVBHgBkdHOXFRDIa2Nlc0tb6cpqCB//yRRmbG
         S6G6jt7cZEXsgFtjUJzgOFBSZ5lkw3JJzaTx99KZlezKa4fBKER2pBNPAuxRbEiG1WWs
         plede55hqyHqMtXPksrrJBD11AYN9or2YLUdTTfAhS0xz+TexBT2HE6RbGJO+H2YEtlc
         RkPFUp7AtJu5Rm+PJCMj29wtsx61covrsN0B6hL0T2da+EUv7rUERbVtgqWFCUhKp+tc
         kofw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ETZHVsVL;
       spf=pass (google.com: domain of 38f6iyackcyyo4qoxs2qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=38f6iYAcKCYYo4qoxs2qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=a2L4dsiN6MBX0a1zZl1DuSdgCbf3SQ0z20pJ/vHEJ68=;
        b=QlxJr8DeFldp/ooYBrSB0m/RlUyDJoZSH8Pd42WoPq2kBQy2VYY/OunqJuUQEQxK8K
         gwfXAc7nlnd/JU+K0U+QcrdbY5TkVy0psOR2OJpPeKVsEMzwX8ICoW7jn1F/CS6Se9YX
         hADhl4busfHX6QBn+vVeauzexL1pC3GBZX2LzLGnYQFiRwArB2sDm5LrArNm5xR5oJ/n
         +760PIRZKlXf6xPEA7TVrrM+8/5+P0aYq0LQlF7iVnI8LbglOylGOvO8urqbicN8bNdo
         70KJWA8Q7Ls34D5R9tSUoDxvHA3jjgW4Phe7a1DPqrSZwSqElmHoNhCsmfvUKO6AANvN
         ++bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=a2L4dsiN6MBX0a1zZl1DuSdgCbf3SQ0z20pJ/vHEJ68=;
        b=L3oUkzhfAI1BYbx9HTzKWgu4Ret5Gjjn4DOu2cLTt3FVZF+ZHjNRVMuziHqmqI1sc/
         wr7MgWBWUCVm6jw7BVVEYXv+VoNkR64lVUPwz7/HlgJE3P7POHMhuQjhieRGfDqi774d
         D44PZUaiZrg67GRHvIuqZ3hEx9G0o1oGUwDq1sJqcbNPkbqVrG3nRdeg+wPSrFQezdQ5
         x5DU+UUAUey9i2n6UBv1ahmaXjufpPGZ6V7dU00bnzySeJgE17Eb3cT3gTy0nDBcy6vI
         mkFDasXun2ZNeWHV7MW2zvfXo1WQX1dbmg818K7H7IJX4OKsXVFE+fxOwRSzyPJ0onqh
         wkvg==
X-Gm-Message-State: AOAM531w3HYCMEVZaaP+E2ReajJSMDYZhnZirHqx70C+krnDhA+bxGK1
	VRXvGCSw9gGvx1+AWSd8Pxc=
X-Google-Smtp-Source: ABdhPJwDb19+yL0fFBVu1YAeW3XNAajABrSca3K5O+PMkKh5MYeKkPISDdDzzTiSpbY+lKghGbX3mw==
X-Received: by 2002:a17:902:d491:b029:f1:6377:123f with SMTP id c17-20020a170902d491b02900f16377123fmr1092368plg.83.1621294834608;
        Mon, 17 May 2021 16:40:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e542:: with SMTP id n2ls3678864plf.2.gmail; Mon, 17
 May 2021 16:40:34 -0700 (PDT)
X-Received: by 2002:a17:90a:284a:: with SMTP id p10mr2100282pjf.198.1621294834119;
        Mon, 17 May 2021 16:40:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621294834; cv=none;
        d=google.com; s=arc-20160816;
        b=JzilTcJgzhj+y3YHyObq3g1wPbwpNoKdV3mPL9oyNzfQCVn56kfDYSLHwXrwfSE08x
         xWb01u2nT7kDPRpWdBBaEcJgJ7tMh47d4tbUeCdeZiop1Hmm4xj+1pUXk5ZagOZFa85T
         bJAZdkpxL3YdPTg0CbRC3lMEDOSIXu2Vg4Uvt39+Qnp7H5oSUtRWLeC5/6i2uGlNRKLb
         INHGc9oMS6ddT6I3pvDlwsI72yB9CLTuHcfA0hAd75fh5IXJoffcFZ4mDg6d160QmWwc
         Tdt755TZT1rraHEzCQoD2VQHlyqd+npm5p31EXzCGjOjzOHp5jez3DkiqAQaaXujalPs
         2ZZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=coDTUdE+DGzuNtOpTVsbEzy4lno8tcR+JrndAuiFaAY=;
        b=VCWEhXFdFCWhpVdQvgSjiWOtN9Txf5/abSz0y27gYN1QgOmaPKZtFAahIO4k+Z3suK
         KwiLHGaLX2Ia6k/m2KW7FxcJMuj+/eFH0/Rlh3UAxuok7J34aUsgHyqEAlcJ0vhCkNkg
         Io6OZoF8woeQIiqQB+2Ddiwmrs0mnRLAePXUL0vIEMC6U7VWL2MRKYO9lvq2ITb0NJti
         he/EiFRNbEtKyH/obXz7erFvsBY/f3GgxebcZBCXlocSbZNtINjg+7OxyH+NRGLQhuTA
         aXLVzQRyq2VUiiiA4Yo7pJ+9Dh20gUHfG1dJ4xRvNaoeKOQe7NSlOL794gZmXJDL0xEF
         8DFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ETZHVsVL;
       spf=pass (google.com: domain of 38f6iyackcyyo4qoxs2qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=38f6iYAcKCYYo4qoxs2qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id gm23si186332pjb.2.2021.05.17.16.40.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 May 2021 16:40:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38f6iyackcyyo4qoxs2qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id v184-20020a257ac10000b02904f84a5c5297so11367164ybc.16
        for <kasan-dev@googlegroups.com>; Mon, 17 May 2021 16:40:34 -0700 (PDT)
X-Received: from eugenis.svl.corp.google.com ([2620:15c:2ce:200:c60e:2f76:b979:5cae])
 (user=eugenis job=sendgmr) by 2002:a5b:84c:: with SMTP id v12mr3203460ybq.77.1621294833200;
 Mon, 17 May 2021 16:40:33 -0700 (PDT)
Date: Mon, 17 May 2021 16:40:18 -0700
Message-Id: <20210517234018.3031003-1-eugenis@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.751.gd2f1c929bd-goog
Subject: [PATCH v2] kasan: speed up mte_set_mem_tag_range
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
 header.i=@google.com header.s=20161025 header.b=ETZHVsVL;       spf=pass
 (google.com: domain of 38f6iyackcyyo4qoxs2qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--eugenis.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=38f6iYAcKCYYo4qoxs2qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--eugenis.bounces.google.com;
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
---
Changelog since v1:
- Added Co-developed-by.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517234018.3031003-1-eugenis%40google.com.
