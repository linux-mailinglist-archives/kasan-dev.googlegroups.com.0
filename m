Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB2FUVOAAMGQEKXLI3YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05D2F3004AC
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:00:10 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id n123sf3440151pfn.10
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:00:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324008; cv=pass;
        d=google.com; s=arc-20160816;
        b=WdGoq2+IITegKjrfn/ZdM/+RbVxckvpSmTUjE6Fq11VVVXJromindNQ5JhelwnY/ag
         LrDgMa7S6lrVzg2ri4mfIicLRcMRFjnGVkncC340sOiM7WDkVerLmOprpd3c7/bb/jA/
         bFkbfa87i2c6Ifb/6MF1XixKtwPV4Tiaz5qP286esJzDEsjKp+Uvmc5d9eIvVVvZZTVt
         7Cn2+sioRH8VaYj3T5Yyrlxbl08n19qB/l2MAKmIBOHMy0wG1PTAlvkOG6Er/oypMhfy
         6IrPPJZ0NVhIAQgkjgcmb47L1Wlnh7sG+jOpyjLx6p8o/0l3epGRwfR+yB3f4jC7fa0F
         W6DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oWE3brHJT7lSfxqmjv4HuAd8/iEN9KdUCHMfjhZ2Kxc=;
        b=AOhYloiKfgm8N8yylfMeZQrSJ2p9Y/8UaNCJnhyp7NRC9ysb1veLczJ+Snpv10XFKe
         lJNmA2M35SzDWdKOelBKsUWVSooQSKpHBdeo3v9xXb5U6Xgnfu3sVEcFa80qnYo7CthE
         cu9vZ5C6S1Aoqsk4EpXjr2y+0kdHfKUTAuDL2V+RK4ORJMvIa5084cpyLMvi9fPKSC6C
         EUtujbW+JtJ+nQQE6+il1tX7qSCpd/tYBskw2O1FJjy+BByeBU4l/Fe7D7iTW2PuZd/5
         xXUSUWPMPVWHnr7HaFpaIx239mnLIF3i7sO/glu+tSi7iAY++AqLLesjlyYW8RhoLxEM
         VZuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oWE3brHJT7lSfxqmjv4HuAd8/iEN9KdUCHMfjhZ2Kxc=;
        b=sG50xjo42FvjHJ1uPtRPARNzx+PHqK4E7S4Xwavx+oJLQHx9Fo3lMIlBQjBXerTS+S
         b/gndVmAhg2FVFpya0FV2/wxmiItShZg1t6TwkLyCb1Ju6g6bHcgyQTso1s8lHUo2rYN
         gNYh4ZZBcCfvfqFn9AfYOiizl7giIwy1M3cM6+NUD/LgbP3kCAQk1jD0GggMUl23UbnG
         oDhLQWbmsoPzViMMlLbreEaWpLu25m/e3BH12gK8KS8Ojsqio+9HQRNChXrOY/ZmbIw7
         IZedFhWZmepoH6G37TPa0t6P/lad7DchwEPHjZDQdv6Z98T7bwF6FNQf9pQgkLQTZHxP
         xQ0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oWE3brHJT7lSfxqmjv4HuAd8/iEN9KdUCHMfjhZ2Kxc=;
        b=G6jpjYGFD3l7SmbfvzYo+IlkFmlmKprKRrU18+BQPsuU0/Kpr+UWjgGPMeRgJNPdWm
         2fTTsfo7ei3BVV/ITHw/zidSNfNv+ndI3snKNCmDYbFAwws3MyT0pgTwSkYdupyxaklE
         YYOA2fnHW1xdHUK4Ihn60waetqfQzc+f+EspG3BtDtF/HfCFw1JNmpiDrQJGX44JiLwz
         ID/nuES0/Flnb99rJ2KYEF7E6knk5fhZ4BSagiiRWbjxdVONvFoNwAEsbuXN9+1wh2YV
         i5/Lap7eUdgQCL56x5e747K6kDfdjQRcnLLgDaXItXVH9P+IQ/HZ1K2LffwWoP7LPR21
         sGvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pK3BrsMB94sU71tzyWToApwjAo4NsoMfAWap9p2oiWkSKZ7qx
	fseIKR0MLohqrTF3H9VUrBk=
X-Google-Smtp-Source: ABdhPJySR0wvRLlkT8508KCslkNRmS/Ffl7GxFRV5fbNzI0L6NtNXZKE9t788AoGgWvadyvUEk1jCQ==
X-Received: by 2002:a17:90a:5d02:: with SMTP id s2mr5495195pji.149.1611324008284;
        Fri, 22 Jan 2021 06:00:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9386:: with SMTP id t6ls2212214pfe.1.gmail; Fri, 22 Jan
 2021 06:00:07 -0800 (PST)
X-Received: by 2002:a63:4923:: with SMTP id w35mr4671543pga.404.1611324007596;
        Fri, 22 Jan 2021 06:00:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324007; cv=none;
        d=google.com; s=arc-20160816;
        b=VqjBdUPbj+1OHEWo0DRnAt5uJlVbyEbYuI4cLs5hcmRisFl5OBZuuYtdG7OR4r3HlH
         yzcJKM1YhkUq/bTaBO4oIPNGnmynS0Sq8VRGgcoAkvv03jutSK2dbLVLsYRrVfrvfccC
         h+CbrFbcawMLi7S5oqIohAxKUXgztD34Btnmgc9j9I8sLVvLXTA3jZYR9wictQz5jQEQ
         F4JoaEsZwpb4wgiFvAFiBSz6tAOu7elDPN6RTUShM72uMM6PSjT5QT+91rSbfzENp2nI
         nWb3zYCLrxS/I5aBnaHfrMlc8/biSf5QfgORPFyo8nU5WCSXeE5JNvwQd2N6OxkQdFdt
         cL9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=gyVtDtDgH5mdykZqagOMclEBwdx69UTG9puaUbhvtxU=;
        b=OlyvGxLk3lEPBym6YPuX+8L31AGzIhgUTucLW/dHdmX3JU2qwzlz1JDgD7LQxk1fKp
         B6TQUZ0N8RlpiMO7PH+ihbkix3QVDdXnIMaLt1rARum42Ia/f1tgmqv21YyB8Sjfhq+v
         xlPiIF31zm3nqB5RwimDWapb6TYUqWMAPgeVaydXnRqRvfuvahaC0WWqElD+f8ZZPegS
         VcaG/zyknog+mmofP8cCBDMYHiN7j+HHtKO1sn6LqE0gnPzFUbttNZKBdm2wAF0m5JIH
         3kekrEGEFcEIBpjkPAyXb6gS5LGVJdnG5IgLLVVxuNFGeqKGg1TxwlBB56pli3OjFxgr
         r3Wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a1si417331pga.1.2021.01.22.06.00.07
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:00:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9A2961570;
	Fri, 22 Jan 2021 06:00:06 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E85603F66E;
	Fri, 22 Jan 2021 06:00:04 -0800 (PST)
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
Subject: [PATCH v6 1/4] arm64: mte: Add asynchronous mode support
Date: Fri, 22 Jan 2021 13:59:52 +0000
Message-Id: <20210122135955.30237-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122135955.30237-1-vincenzo.frascino@arm.com>
References: <20210122135955.30237-1-vincenzo.frascino@arm.com>
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
index 3748d5bb88c0..8ad981069afb 100644
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
+static inline void mte_enable_kernel_async(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122135955.30237-2-vincenzo.frascino%40arm.com.
