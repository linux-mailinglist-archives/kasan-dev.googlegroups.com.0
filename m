Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQ5AVT6QKGQEKBFUG2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id F12482AE2D4
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:19 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id h11sf6170787wrq.20
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046339; cv=pass;
        d=google.com; s=arc-20160816;
        b=tUq2VPVmVRAFEFchdXHB2VqXnitops1dAUUj0l84quCGoIDe8kiDp+Zx8Hu66idHDo
         8jINX4pL6CaMFP5bcu+2f28w1Rdr5kH2RzMT0CXjT3wEx6gY73g2Qa9xW8kmU4fNwmWq
         aOBT76bclZlHWXadDXQ55vHkg5B6714wSjhIoVPLCbH8zQiUO1tyNlYuX3xWE4N9ypfS
         p0DEmrZfHn6JRPrdPKhivy52ZwWjseJqpe9SBicz/nR+39m/HkyAqFX0yxBp320oBLWu
         4SIhTCxpz81E4KmHDb4Vdftiv54nso01+8HJO5b/1i00L1MOC5NmeA+ffsIoXo/JkaLN
         IqKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FpYNHeKbp5XqXBm31kxvypZb50jcWrq+6HnFqlgTjwE=;
        b=x490b0y79qxcn2QDFpnyBy0hgyshxEMDabNQ6qoser6wxjvazJTv0nhArwMjEDF3xf
         FE+HZ7Sym8hcNstXWj2BotMK9Boc8n4sU84lYJP4pYiz0GwXKcfzK0yJ0+RrCv+JrFfQ
         e3RbYVD+ssIh3Jv/vlphQWDqzDhxsR9TQIUnMTKPcXTNJlFaOL3zqaiIt7aBPRBBi6IN
         0KCzacvf5YqS7Q4z4liAh7JJ/XLCDOOFLuoDwVUnOPwNvkBn47oz9g2ZPxRVk0UOI6Ha
         iQFB4MXclXaciQ39CS8sLNQFtDvTi/T64iCZU3o6t2INPc+vUV+jmg7nEARYpLnUn5ET
         so3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uhgZ9csZ;
       spf=pass (google.com: domain of 3qhcrxwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QhCrXwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FpYNHeKbp5XqXBm31kxvypZb50jcWrq+6HnFqlgTjwE=;
        b=qTmnYsmiM/LKZ8JRDfOnIFQxMLhuLF7KZx9kLXKYp5CGYNsdAXzc8jekVicmGSuIRQ
         7PbKHqTm9dmMkG549QrAC2yzKKibBOgCr3G9glGLQDeLWj1PN1FMQ3LfeOebmeTFNO76
         kGQnEENsCd+Pc/joMj9TdCc+p7OjYQ6LOig3SIJyT6Xvshgykw+IKwFVP9tVbtTVcZTZ
         Zd6BxRbLymAWjFFOBCn7Kw/Vn1vm5sfM+9EEReuDvs20Fc1IWslRorlGGdpGGhuuen07
         YMgAktOCy94zCAkZMgzP6GlxtECqr7NuXZgnCDy/2kXVyM75wsfkewCZzD/mJ/2lQaY7
         Sjdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FpYNHeKbp5XqXBm31kxvypZb50jcWrq+6HnFqlgTjwE=;
        b=USnibWo1nLulXZ4c4QNB/1emd19+XP/HN2PCyS9LXif9jVnYpn9RltdIq/yAIucTU+
         dVspmUQBCllAAatUPkXH3PG6+DD9BOXOregPeeQohN50tG0wNVFqnmuh5r17Fpuqdo/B
         57E9yytPiDQoNX/w50NtIaU/N38Xg9CxUAmAzymfesUxPifpTWrxRo7ORBKmps4IMvQh
         TB44HI+Eo+4MMwEWGYei13Btyd/XS1XIkd50GFxs/a3IPqjUmB+1ZXJ9xeNw5rajaJVS
         XGxR7LKgkT2yX2+KF+f4HyKTl5ivxA/Q+LET7vwWtoltCRSSoWBFpexyrlqh2Zt4uenQ
         tgWA==
X-Gm-Message-State: AOAM532Mgcl40Kf6S2JLtohgOgutw8oTAUG6Nd4clqLyZWj25Iwpe8Nz
	FPXyKR+eEh6qZZDhl49edsU=
X-Google-Smtp-Source: ABdhPJzAw36ZW/Qu369Ip2gGpLaRli6Jk1rpZHRc9ivrto8txzLbePRRkytYQwu/dvnYZtsne+DB9A==
X-Received: by 2002:a7b:c3d2:: with SMTP id t18mr279544wmj.112.1605046339722;
        Tue, 10 Nov 2020 14:12:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls461698wrp.1.gmail; Tue, 10 Nov
 2020 14:12:19 -0800 (PST)
X-Received: by 2002:a5d:60c4:: with SMTP id x4mr27948584wrt.175.1605046338994;
        Tue, 10 Nov 2020 14:12:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046338; cv=none;
        d=google.com; s=arc-20160816;
        b=N8Qiu/GbOfU2GoKnXNzj5NcDKNB5HzP7pLQ+4QLDkALM9BG2cd/DvnUpzTzbIe8f9z
         ITm/RzJGSBZAwnZGJNncqSdTaYzAiDlkhbX0N0WYcYb1UmO+E+I02EHn3Y5a8sh8jYJw
         Y+wFPl4wwUkBF4g6dXElcP4o46evwBXSFbv1RCsSy5TKm03Wgp4sEGYtLPIBSpPBp2fm
         bw0tZgCst7PtvMp/MNLqNLMKRR+wOvK+axJVuARQaJXdw0eFUSipV19p4XpHa7bwhInM
         /VTcnBNcoE2VWRxlHhNBJTV27rqnFKMfgzwpi/qBR0/IZnmv4Cv9NOHDsJSplaP3pMu1
         877w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=enYgO238HRx8fv1V28RLwo+/DGMZxgWkEarUmOvbocE=;
        b=hMiKr573TQ12+/kDgkZa5QmeirH0rdSsPyQSKQ1LumQ2vaZuG+rpbbR2YX5bM8mZLw
         xoTYrisGJsXA+SqZNTTtAIYweCBRqFsIMVpk8I2u08yWD3qnWigfjWCE1vDmEx7B95un
         ZJ6UActoH0GKcOYlAvAwldHQPYQM/Ukl1yOVRa+a3PDhDzUVl8VOuOH2AiBQUn3bbgvR
         l9I4j4y3xkQ7t9km3LepplI/oojZASVaXG9SNIpAhOZ45hoGEKNDewq2EGkZ46TbesIt
         b9DecY9i1DmkZzZty/H/jt76OvQHcqZ1f6pfGhMc8Cu8GVFct4efyy9LVs7818CerO84
         TuqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uhgZ9csZ;
       spf=pass (google.com: domain of 3qhcrxwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QhCrXwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id y187si150117wmd.1.2020.11.10.14.12.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qhcrxwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z13so240426wrm.19
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:18 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:bac1:: with SMTP id
 k184mr261891wmf.76.1605046338668; Tue, 10 Nov 2020 14:12:18 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:27 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <5ce2fc45920e59623a4a9d8d39b6c96792f1e055.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 30/44] arm64: kasan: Allow enabling in-kernel MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uhgZ9csZ;       spf=pass
 (google.com: domain of 3qhcrxwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QhCrXwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
feature and requires it to be enabled. MTE supports

This patch adds a new mte_init_tags() helper, that enables MTE in
Synchronous mode in EL1 and is intended to be called from KASAN runtime
during initialization.

The Tag Checking operation causes a synchronous data abort as
a consequence of a tag check fault when MTE is configured in
synchronous mode.

As part of this change enable match-all tag for EL1 to allow the
kernel to access user pages without faulting. This is required because
the kernel does not have knowledge of the tags set by the user in a
page.

Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
similar way as TCF0 affects EL0.

MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
enable it as part of this patch as well.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
---
 arch/arm64/include/asm/mte-kasan.h |  6 ++++++
 arch/arm64/kernel/mte.c            |  7 +++++++
 arch/arm64/mm/proc.S               | 23 ++++++++++++++++++++---
 3 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3a70fb1807fd..aa3ea2e0b3a8 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
+void mte_enable(void);
+
 #else /* CONFIG_ARM64_MTE */
 
 static inline u8 mte_get_ptr_tag(void *ptr)
@@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
+static inline void mte_enable(void)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 600b26d65b41..7f477991a6cf 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -129,6 +129,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return ptr;
 }
 
+void mte_enable(void)
+{
+	/* Enable MTE Sync Mode for EL1. */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	isb();
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 23c326a06b2d..7c3304fb15d9 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -40,9 +40,15 @@
 #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
 
 #ifdef CONFIG_KASAN_SW_TAGS
-#define TCR_KASAN_FLAGS TCR_TBI1
+#define TCR_KASAN_SW_FLAGS TCR_TBI1
 #else
-#define TCR_KASAN_FLAGS 0
+#define TCR_KASAN_SW_FLAGS 0
+#endif
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1 | TCR_TBI1
+#else
+#define TCR_KASAN_HW_FLAGS 0
 #endif
 
 /*
@@ -427,6 +433,10 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x5, MAIR_EL1_SET
 #ifdef CONFIG_ARM64_MTE
+	mte_tcr	.req	x20
+
+	mov	mte_tcr, #0
+
 	/*
 	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
 	 * (ID_AA64PFR1_EL1[11:8] > 1).
@@ -447,6 +457,9 @@ SYM_FUNC_START(__cpu_setup)
 	/* clear any pending tag check faults in TFSR*_EL1 */
 	msr_s	SYS_TFSR_EL1, xzr
 	msr_s	SYS_TFSRE0_EL1, xzr
+
+	/* set the TCR_EL1 bits */
+	mov_q	mte_tcr, TCR_KASAN_HW_FLAGS
 1:
 #endif
 	msr	mair_el1, x5
@@ -456,7 +469,11 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
 			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
-			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
+			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
+#ifdef CONFIG_ARM64_MTE
+	orr	x10, x10, mte_tcr
+	.unreq	mte_tcr
+#endif
 	tcr_clear_errata_bits x10, x9, x5
 
 #ifdef CONFIG_ARM64_VA_BITS_52
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5ce2fc45920e59623a4a9d8d39b6c96792f1e055.1605046192.git.andreyknvl%40google.com.
