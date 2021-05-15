Return-Path: <kasan-dev+bncBCJZXCHARQJRBKV57SCAMGQEDKQBVNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id E70803814D6
	for <lists+kasan-dev@lfdr.de>; Sat, 15 May 2021 03:06:51 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d10-20020a05622a100ab02901b8224bae03sf864588qte.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 18:06:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621040811; cv=pass;
        d=google.com; s=arc-20160816;
        b=ck/MO55BzeDeyfk/eSfZu/ocV4a6Cc4HZri4YzaSFGAv5YP9WfSqXDLVTNJ4yJys4S
         f/b++RE7eb86luQn5YoICbmFgIhilRHb6Wt/oUKfxaOzr5Nj/5On/1bJv8y6gTAdmc5k
         uAa0NyV5ikUAtBKU56H2+RvIljA8putSYhsyr5YZk2ilOH1m4vZIHqAjfBIxP97UF+U9
         G+x5Ofc+LL3+Lkhrt305Du9djy8hPlo4jU1qF2wRM7d2Lvl4+C2jlQldEvOKOg3St4KL
         1qVo7ImI9olxZBDRsPYIGe7VbAQVq+C4dyeCOyoci9VgOTOv1DNKdF7A9sAhPZnuEa2r
         1sKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=9Tb/DhPOFNJK664OP7+/r5krAdsPVy8VFgjgROEUk1U=;
        b=jdgQ2tWvZDo5V3yMcBQWUfz7cyyqiZlxjSiMdo+Fllef94f+gs44aGkLHBt0pN2wMH
         bpuj3nJl72EgTr1Hj1JfX6tDcOILmRejZlV+B8/CScfMma0MQaN4g/jhais9ZApgLyM2
         lNNcYnb8166Dpi3aBVt+stWK97yVJPtt/svugkbaiZO/38+AtYA6Xo6Kw2gDxZCw7Osp
         tSVapyFy4VQ3KCsbYID6e0Pxn4h491mHjGtNWT75G42ito8wEAJnQp3muNuE3qhFEZre
         S5RmNKcTZIYIrSpWIGECEDXBTTOOVtMl9pbQs6v3yxjPSeqm2BlVN6KYydBkXqBF/LxQ
         X0Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BpCJqUDv;
       spf=pass (google.com: domain of 3qh6fyackcw8rhtravftbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3qh6fYAcKCW8RhTRaVfTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9Tb/DhPOFNJK664OP7+/r5krAdsPVy8VFgjgROEUk1U=;
        b=Sqg02f+mCvywr9w55EbG6krurxnNt07rVzVnwF16iuRFLHoK6iCKeVxgUcWvh9VXHw
         S4H7zZoNXrebHPAIaHE6eUpw3ZLuNF708w9YYYvcRHCF/lSbl63DA99kssSs4Ey0OvQw
         is4NFYA2WXbXNI+O62fqdBb7DA50f0BqFREz4NwzElCDzTkg2dg0eGkUMQVh7++699Nt
         ZYvbmwxIzQ41eTPgZEpYENm3f4wPYgHpSwv/tZuamMkI6VJkk9oG427Ms+Fna/z0j7XM
         CpKEDrwSw8vpHL/CYRYS13Ej8QIhg8YS2oK17yNvvbTl9AYjwoeE5TP/wr0Wb8oNUi76
         jYhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9Tb/DhPOFNJK664OP7+/r5krAdsPVy8VFgjgROEUk1U=;
        b=BMNKl4YzJLzEH+DGXCCpb3f52BZzdwPTzl42hIOhVpn0ORU0Uppg7tT0rmvoL4Ql/x
         KuR51z1HlUpu4RL1wq82Gbwvsco12TGwyzTD/PgVXxB+Pm2zjGVz/DjE1WagXi7658U7
         M/DtBRlOkIhEqZDsk40aypezcBqw5s2I1Kq3BYhrARRuEJncQ4ldit6YzT7y3tgM4D0n
         ap1/k+WEdnCtn5dRI8OBXduMbCmlKDz52kgesSrTCwv9NZS6i2OSSwsFddU24MbDQ+RU
         jh6OTHAGGifnEIqu9NFpcYMGqdF4FX4Mugthsh1a+LK2keHv8jBUtXisRL/ifRN+/pmN
         tkAg==
X-Gm-Message-State: AOAM531DuZMtrMnMqD3ROwfl7lN4IPxum585FfQjXkDCJwbtvPO1LNVh
	gxHtAjozWtvPuaNJpl129zc=
X-Google-Smtp-Source: ABdhPJy161U/pj//Zr4UJrl/7L6u7P0xZcx6kjPSp4hK+8c4h88LYtV8PTeGAXkypW1WEnr+hyUHBw==
X-Received: by 2002:a37:b582:: with SMTP id e124mr42604549qkf.171.1621040811054;
        Fri, 14 May 2021 18:06:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7681:: with SMTP id r123ls6971405qkc.6.gmail; Fri, 14
 May 2021 18:06:50 -0700 (PDT)
X-Received: by 2002:a05:620a:c0e:: with SMTP id l14mr37791413qki.412.1621040810657;
        Fri, 14 May 2021 18:06:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621040810; cv=none;
        d=google.com; s=arc-20160816;
        b=VKiEBASHunBB3buMf95McArtLRP16gGcBDR9n1Cg1CG/IGbg1nbBop22GD4GC6UeoY
         l+nF1+1rtdIhSnG98wNWvmkPGaoDTW0itB+FMDYVUpWa27VKsoJ37vttm2ln36G9MZDY
         YFAm9jHS6iSRfo5+T871sagkaLdRhe8mgm1kFPbY2ZB78Pdfbx3SyROihfAraeiX7V7q
         F8fcBbKuYzNOsT3fUZNABXT8Z3LnLO9DLOQSGZb1RNZfQXVm8OZcsKNrjTRGK0tjuvjo
         CRm5PiYztvKyOG3Q/2PYnDvxVA+tSvk96EHtXiOmGhbaVIjgwiq0GfAU8h6KeNXA7wBf
         sITA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=c6kHqF9mJQYVoqbE7Z/Zt84eKpUDeq460Qh7vhm+vhE=;
        b=LsjHrXzt8uXRDfN+iuBFTxzAgm6tO9qxrjUO1+GAkxe5svBHib2atmRXtJ7N8z42E1
         IBxas6Jyb90nOgLugnvFggG8gAeiCcI3RCpZTFrl60VPv7aEHlLk/sJdFheFet3w5avz
         ahD7KiTrBS3/XQwUncNWe+REfBP2e2MRUITVNWWWtP8GXOACKv3/v59IyDNv+6aiB5Cu
         YTe93jgCe+xFdPVTsPCMY/SkrjpG/TwYfBTcZROXsZqiuuKohWlwv56C6R1rBSOGMibE
         ZdEGHyWjUDXYv6UkNcp2oYsmVV9Hll5yLSWcQ1eyJti6LzEOA5y/e40yllo6b511RQgF
         koJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BpCJqUDv;
       spf=pass (google.com: domain of 3qh6fyackcw8rhtravftbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3qh6fYAcKCW8RhTRaVfTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--eugenis.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id c64si723511qke.6.2021.05.14.18.06.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 18:06:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qh6fyackcw8rhtravftbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--eugenis.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id i8-20020a0569020688b02904ef3bd00ce7so1355242ybt.7
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 18:06:50 -0700 (PDT)
X-Received: from eugenis.svl.corp.google.com ([2620:15c:2ce:200:9c55:d7a2:8f8f:5c4e])
 (user=eugenis job=sendgmr) by 2002:a25:820e:: with SMTP id
 q14mr8001948ybk.152.1621040810242; Fri, 14 May 2021 18:06:50 -0700 (PDT)
Date: Fri, 14 May 2021 18:06:43 -0700
Message-Id: <20210515010643.2340448-1-eugenis@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.751.gd2f1c929bd-goog
Subject: [PATCH] kasan: speed up mte_set_mem_tag_range
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
 header.i=@google.com header.s=20161025 header.b=BpCJqUDv;       spf=pass
 (google.com: domain of 3qh6fyackcw8rhtravftbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--eugenis.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3qh6fYAcKCW8RhTRaVfTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--eugenis.bounces.google.com;
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
---
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210515010643.2340448-1-eugenis%40google.com.
