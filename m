Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBXO4U2AAMGQEIBJGZ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 544832FF092
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 17:39:58 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id j24sf1837744qvg.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 08:39:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611247197; cv=pass;
        d=google.com; s=arc-20160816;
        b=FoaCpDpbHBbF4PyGFx/AJAERqV7pbH11516fM2RYPrtlxKTh704p6lswUGv8/T5jVg
         bmK6wBXnGW+5nzX57j6Toob3NkYNZz1HzDiKnjZZkR2BxZUNXh98BymaZFM2Eu3MCkbZ
         OJWcBzn0rX2FLjCB7KkxJMatYHF9hOWpOIgxPmIOfB/zZVx+xjQp/mxZy8ZZXUrrLOar
         ZrcjnhEKME9SaKf/i0xLu4eKjfgYCE9jhU0OrnZ+kga9d6lHXMK9mnwFsL4rxeXBvA2a
         UAdroIOtvUe5aYyweY+VC2Ii3sTheIIcP7PaHVnMmXhXNLVd49rRbdXOA8jjofXjPW3x
         gZMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mn+0M9bGBoGLFvv57Dl0puYMyuSx33mC7wtoGRioK9k=;
        b=clbPY9X7kzB/0ZUKQM4isGF+X8IgzXVHeFP/gXU2Nd8Sn7WSOEn/k0IG9ozfNxCjNr
         B/twBzvvRyY13bsHhvl726AUItaFvjId89yl1ZoGkNDF0TM3kl8+p3AT69kbIVfI+W40
         GcNar/wq3d4VTitfK6OrcNcCthWnQc041QRKQ5irzJSSxKnz02BgCuWLzrdlBofYIspF
         xqjtSXWOsu6vdQVHQdPUQDiLFUME4VX11MCCTVfxLYnkzmZYV3m0pGMR+e0ClNfy9+bQ
         XYR9ubQm7Rof7f4/q9JzScBjvrhFzOqkwxfiXXMWN1aShO5SJkaTzCfxdWd8lGbasDSm
         44qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mn+0M9bGBoGLFvv57Dl0puYMyuSx33mC7wtoGRioK9k=;
        b=o9cheNjOMR8dokOJeLFqjPaUz/BAJggmGsIyZF2WQTAxlwhuJG5ij4UTtEnpm8O+Mx
         XbxpIhqoeZdlmjJWvnPgZqMa0nfXUKmPznb3XZy23FKEq8r7qWL7bAKuk0c0d4SSQ/+W
         mZyGvm6w4pgQsvmFwytSFW+UPsAHkMT/QarF26dQEE8IIphzDj9TMWwnPcL6ZdkZAgKB
         jN0sjN/afNKN38/V1YlVf/QudTis0Wkpyzge1YLP1Q5FCICRbFIByhj3aty0UEjgdH1a
         NWr2VNuzCNMi5ZQf288DUBg0ajXQkjWA9wSnfh9oWToI6QJbxi198equ89pcKCj5rma4
         ZSSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mn+0M9bGBoGLFvv57Dl0puYMyuSx33mC7wtoGRioK9k=;
        b=C4jRABn7sUsPI5GSVlVDjTGyNtAt5+0RpnG0yrXdWw5iElPJuDWB6zjFt8cQP+n2n1
         /6ZKW8HQRXaxsvXcWSRWa/v0cS9cUDGheGOLSubpm9yzIVtLnwMXzJgN25cS4mOhbHHt
         Jdvjz2ZDjKahpK7VEcmYktENCaMtmjlkTVmLhlSbaXRXTWskRMPvgym25drJ3ANbnrEb
         iNbB6NNY/GfmdeHY9WLO0/yd6UXAnEUf0UEDQx+bAbfiKgP7jOFf2YPf7slGtstUnzdO
         Wanhe1m7Uyv7JN308W9NExQwKnm7PKx1IYh4opzscFo+6Op6/tp85aFvKXalRBJekdzC
         hqbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZYiPjut2nNsJIBDPvOlObqcF6zD9BFIcE9xTZJpbfXombODIW
	vRT12cAtXMzNj6tnKWgH0k0=
X-Google-Smtp-Source: ABdhPJzf8IwO6vOMXnMfpdjDcPPEskMS92sbQLGGfU4k7G7/zMTS+GVRN6QQf8It6Hgqzk2GMiOH5A==
X-Received: by 2002:a37:4ecd:: with SMTP id c196mr622542qkb.264.1611247197407;
        Thu, 21 Jan 2021 08:39:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1c91:: with SMTP id f17ls1101711qtl.9.gmail; Thu, 21 Jan
 2021 08:39:57 -0800 (PST)
X-Received: by 2002:ac8:7259:: with SMTP id l25mr439309qtp.1.1611247196938;
        Thu, 21 Jan 2021 08:39:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611247196; cv=none;
        d=google.com; s=arc-20160816;
        b=WlGAEm3Ya7NBrn7hdTMX4TAcH5f4ifiuYt15kR8OXUqILxVHTwPyAsQjmg+8J4Ole2
         SX2epAGuk/WpOTSOwqVjOfeRGT2ONejDbNGZY1zuYtvpeNJi5HEPUzoMBzom47ggTBs4
         U31hwrM0Iyqtnai8Jd9btnvmgZhSjhdlJP2Ggc4F7Mg44lXcTYUeY5kmCscFKWRiETtM
         GHsJqtglKN81YGS7ttTczIHBxI5WxizvNn6M/aityKH3Ae3veQ6BZhK2HCAiIarBG3hg
         7pnYczGRKvR013IBeavQVc7rdFbIqV3KPqZXyHimJKd4d7/bs8v+r24UOJHS01kAswWT
         LmYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=OsSOeQ06nz6WAzkGtIycE06WeLFASrFNmNDzUIBkVOs=;
        b=oTMlkBZ3zMjS+wIQg8zH4w0360yEA9iztdYcsXbBeZV1XGZzlPqcRJCAU7EFCYNX0r
         l9m4Fy5jdOfj2WTtwjMxOXyD1TcoYa8v5g2whsYHldb1Nl8z2+s4j3vqIJkdaIaQClW5
         Btm1q2KCt/nTGAtiV8Fj9oDE+m2Dku45lU6O9B+b8P3sHUzntCTTqPsF05Y7QrNb0+RI
         /MUsCRE9ffNgAR0mkQ+5T/q880cXxxY/NBZ6r5HQTsKOPwRUyn6B6oj3FZ8t8yonV+vP
         1cSd5fGl5twjp3epOUzKg5nLhtWjEJqCGL5yLrV3ouG+Jv2JdBVFL3LOhLR+x3/Y467G
         auIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y12si426398qkl.1.2021.01.21.08.39.55
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 08:39:55 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BECD5139F;
	Thu, 21 Jan 2021 08:39:54 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0CDA63F68F;
	Thu, 21 Jan 2021 08:39:52 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v5 1/6] arm64: mte: Add asynchronous mode support
Date: Thu, 21 Jan 2021 16:39:38 +0000
Message-Id: <20210121163943.9889-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210121163943.9889-1-vincenzo.frascino@arm.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

MTE provides an asynchronous mode for detecting tag exceptions. In
particular instead of triggering a fault the arm64 core updates a
register which is checked by the kernel after the asynchronous tag
check fault has occurred.

Add support for MTE asynchronous mode.

The exception handling mechanism will be added with a future patch.

Note: KASAN HW activates async mode via kasan.mode kernel parameter.
The default mode is set to synchronous.
The code that verifies the status of TFSR_EL1 will be added with a
future patch.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  3 ++-
 arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
 arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
 3 files changed, 23 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index cedfc9e97bcc..df96b9c10b81 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -231,7 +231,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
+#define arch_enable_tagging_async()		mte_enable_kernel_async()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3748d5bb88c0..76b6a5988ce5 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,7 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
-void mte_enable_kernel(void);
+void mte_enable_kernel_sync(void);
+void mte_enable_kernel_async(void);
 void mte_init_tags(u64 max_tag);
 
 void mte_set_report_once(bool state);
@@ -55,7 +56,11 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel_sync(void)
+{
+}
+
+static inline void mte_enable_kernel_sync(void)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index c63b3d7a3cd9..92078e1eb627 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -153,11 +153,23 @@ void mte_init_tags(u64 max_tag)
 	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
 }
 
-void mte_enable_kernel(void)
+static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 {
 	/* Enable MTE Sync Mode for EL1. */
-	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
 	isb();
+
+	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
+}
+
+void mte_enable_kernel_sync(void)
+{
+	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
+}
+
+void mte_enable_kernel_async(void)
+{
+	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
 }
 
 void mte_set_report_once(bool state)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121163943.9889-2-vincenzo.frascino%40arm.com.
