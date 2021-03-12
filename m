Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJPSVWBAMGQEQZNVOZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F89D338FBB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:31 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id z5sf14590357pfz.19
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558950; cv=pass;
        d=google.com; s=arc-20160816;
        b=XZ09foo/+r88MaieHiToDRwja8pUWSuAA4TFRhCKBosusqm2JLBiK5+vhJWFW0QIRO
         DxHhFW5vI/9F6tZZbukWMIR9CgGQTW0NMK8esMyuUy0ozOlBEv+gtJEX9nq4L2fq3UsW
         XFuvNYHyLk+uFXJYQPbeIW6GJ50owzrPrAu5QHVCRAXAg+X6YObL9Ro2rm8pTaR1TItx
         4t1cg34Y/2vyfwvQhVhZdW8UdveFqhUAH0DxXtDY16QiX6012UeZHUw+11+gUW6Wl1w3
         3hG4pLiKUtvDpiaP4W+eP+sUXefluzljsXLsGJ9jSYNY4dKC6e6FikA/Xa+2jPgnjH9a
         VcVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=e9ltb59niPsg4e4yro7B3ImioH3dxak/hwghDwMmhbw=;
        b=nRnQ6wQlNSiLFrgyRn9+9xGYBRf5xC7zLQhWea1pR/jPyYCnboiUQgyhCm8dfsTdXt
         omEkwBJTjFF9ZE+40gyaTEamHkxyjKr/lL/dm8aBQ2fkAxsyG4PHiG3llNM4PxJ9DWa2
         5Qof1zr+sjkkpgCZSsqqXk6f78EayhXKxBgSHJcZ0aiSyiImT+z9PUQqLyYt1XcV8iAW
         jnM1YuaDiLKtCdwayGk0E/ZEiZEzFKarrd1nTQZaKsX8akK7+R5FdNvtBPGN9EpC/yq2
         /bOdzdbfacS82Qdxup7XTnXhuNPsp0FNWxs7T8Yyx6GLvX3SOf4KnkkGZc9YuIeyNDPh
         Pm0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e9ltb59niPsg4e4yro7B3ImioH3dxak/hwghDwMmhbw=;
        b=d0XnBpveeGHTau+sQU1l9FObAl5anx6iEntjEbanJ/7PP3087MwCqcrIoFm78pk+hF
         wndO0qPlP6CHifdw3w5xNPNNlb0Mks0LmJ58EgJwlUJWd9LdSSLhe2gzZ4IZvAMowcpY
         Rdf0Y3pMV59BXtups5vs5OwYYOyS6LDHYm2Bc/ao6MxtNLtiZceiri0WjrXvhDw/SQbd
         8+LZFQ9aPuGGZaEJzgC/y2uw3tjB71mYU5xqtx4iD6OdQln942JAuwMNAfgeNR3uVXwf
         EHDcthOBXEjGdsKirb9YSh3f0XIbIcLaUttgjVdfufN9zHID6HZdgf8PJQIMS4PSvRiC
         1Jfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e9ltb59niPsg4e4yro7B3ImioH3dxak/hwghDwMmhbw=;
        b=FMyqBjymv0NmOj5ByEBnKXoHtEWDgs2wdbVgxTkbFiX6+go6pfxjafj4hYDpTJlTVl
         wRjLJAgyZOfnVxfikJ3woAvNaHYCm1fXUVZoVVE/FDqHwFSZCXy31zjUZ/5+a1npIgoZ
         0eRsTpfO0BaWUraEowyseopfQPcbOlaRGJKheieR2ner5glNy4rPLLjBURRM3VHc0PxG
         mJYizgnIIHCEBk59aH4Ox3n4Z1nz5wKp/BwpJ5UpBq6O2JXzzJcb1+MQOvK9ZrQDg+tI
         FbZwHpQdEHBA9L9EREMt9iamVAbBovLbihk78a9VdRCTa1xcEqdIX6ouSbWVvdj2iE6n
         97Ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JfwUnmRkMD8j37j8mWp9J113wfpxIa51G/IoKq+uSJlRCcevb
	UJVsYrv16x2fdJdkMKHqdoc=
X-Google-Smtp-Source: ABdhPJxs4LQch1cJPl/h/uo3RPyz7AohNFerNLvW6qgh8qd/rMvtnn920dECJtMhjm/MJJAiRQYVvg==
X-Received: by 2002:a17:90a:b007:: with SMTP id x7mr13862433pjq.27.1615558950005;
        Fri, 12 Mar 2021 06:22:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:930c:: with SMTP id bc12ls948235plb.10.gmail; Fri,
 12 Mar 2021 06:22:28 -0800 (PST)
X-Received: by 2002:a17:90a:cb8c:: with SMTP id a12mr14754194pju.35.1615558948021;
        Fri, 12 Mar 2021 06:22:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558948; cv=none;
        d=google.com; s=arc-20160816;
        b=sypTJhoCMfaK87mctktM9L+HMkOwBq7rLbyShAuLfmj10ZIFBHCR/OpYE6d60ZKnLO
         b5SSXLtv2xyMomAz2L5KPyq3yJbU6iSwEZBObDcUYACk8EW6BFlwOjMkb99CPjCJ8+gy
         CU253VMaESMAIRdkWwemPuzhrFa2WQ2LMGr9EgaG43Xzk6pCk5l/dTYISloz+k2ok8fu
         hqTL0PxKkKiJjb3a/RQZxW0l2tbcfm0NAvprvwjL1YQyw16npE6lgwf0vrW6fBrQMLFg
         14PTn4XzUh5wIEMRqg6njdgoD5QqH2K88TnZj5uL3TeWcWu4joDDWGFDXqPKs5kzcO28
         HoBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=9nz3u0I5X05prozDkZnO6d/CU2yateoxfm1jXybKRHw=;
        b=evqIL/nT8LeqrjxK5R1RY3Z+2rX+Fms7onpOXNJ3MRCEEwVMUcVwScNtmU6yjF2yLM
         r+Afyrn+JHjbG/Z+U/CxSTamXWHngpG0B57Hc4jk38QKtBmq5vJIDtUH+K/wvztkIl0i
         efeDoAmEXV7rjHmpa96U81zcbhlELLbIqWvmXBKX0Sh1dRkkrs3XDXJFqTEECg+uVbO2
         P8E9rNnrcn9WXvZJWv2aqBpXSaBuODqkKlzh0mdKkCp0fyTyBBtLuaUeID+/CfC64gcL
         +rA1riiz9aSg5n3ZJ2eQcCwTx5/eK1BfWbHSPT019VQU6lzuGN1RLb4jBCxUd265V47w
         fguQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c3si356781plo.1.2021.03.12.06.22.27
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E06441063;
	Fri, 12 Mar 2021 06:22:24 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0672C3F793;
	Fri, 12 Mar 2021 06:22:22 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v15 1/8] arm64: mte: Add asynchronous mode support
Date: Fri, 12 Mar 2021 14:22:03 +0000
Message-Id: <20210312142210.21326-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210312142210.21326-1-vincenzo.frascino@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
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
 arch/arm64/include/asm/memory.h    |  4 +++-
 arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
 arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
 3 files changed, 24 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 0aabc3be9a75..8fbc8dab044f 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -243,7 +243,9 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
+#define arch_enable_tagging_async()		mte_enable_kernel_async()
+#define arch_enable_tagging()			arch_enable_tagging_sync()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 7ab500e2ad17..4acf8bf41cad 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -77,7 +77,8 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	} while (curr != end);
 }
 
-void mte_enable_kernel(void);
+void mte_enable_kernel_sync(void);
+void mte_enable_kernel_async(void);
 void mte_init_tags(u64 max_tag);
 
 void mte_set_report_once(bool state);
@@ -104,7 +105,11 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 {
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel_sync(void)
+{
+}
+
+static inline void mte_enable_kernel_async(void)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index b3c70a612c7a..fa755cf94e01 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -107,11 +107,23 @@ void mte_init_tags(u64 max_tag)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-2-vincenzo.frascino%40arm.com.
