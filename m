Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKF6XWBAMGQEJATGNQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A12A033B3B6
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:45 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id 64sf4774326vsy.9
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814444; cv=pass;
        d=google.com; s=arc-20160816;
        b=dOHh9ziC/Dak8Hbu0ADIUu+Hcll5mY74BanqGRx31S9zM/RNeCteMGL01ClbJooATl
         pM6OZcrnofFQu1v76/p2hXQrcVFG8UFXyEUdDb9uZWl8fLTi2cfS5Gcx+Vo8pmEANQ8W
         8IxcHjyv3QPjnLMjZBlJa5lX0HIRd22Q7H/mz9x30v30uLIehfLItHAbJ/ZccMh9Onep
         3qYmBE19kPlgGhVOjs0GPecUil1ouiy0VYfYrrvN0C/v1egDMNK5nFFxtfYwj9Wm23Yo
         yQWvLWT4d4rt92G1/gH9lqE0yHYEpjZ5i2ZUv5BV/SIZC97zyPvm4HAm9QERXyy/jHgS
         aDCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=W8GGel9xZ9XYewAlKZTVZtByBFQEHOds3SnVhSpVEwY=;
        b=pfq2dJLL4IhDvGJ4rZNsiJUDfnvaYAN3P9ThnaMF1deD8XgqoJwR5F3J1ThcXBxz5E
         FW4QqQd6ZW+qh2LYTaPa4iiJ590JjWtraQuygNxgyTBIbWxeu/kCwXXihUSjpZZxzgE9
         L57vapMgdapSEWmGv0BYl0AJQw2TSgc8yOw6Ru8FtjIJdd0ZvXBIuVJtwvo5PwcWw7q5
         bUjjnnhFAaKSOCA+uhbUhn07D5osmFrbqbKSntoNMXuk8JZ75b63JtcSMAscaslbHUOe
         PYYx8pY+rIEZdFZ6Y4CsW/ywsXOADsj25NGM0wzi/fDWJycSVXT93JkplQ2I1Rl59r0M
         bteQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W8GGel9xZ9XYewAlKZTVZtByBFQEHOds3SnVhSpVEwY=;
        b=Hm0CHa7YTBWDPk6cvGIIPe++p2+T5caX+Xjj3X/m+rWFXi3mRZl3hhVJYHJzhSAcFm
         hlCCW//mAnY4glziiFnOi6rpxcSX9cPJkDVI8CjI2oclx8dGHxDVLq2IbMAfhCO90ctK
         s3SCOPrlXTcKhkrAqwUPKFvnLKto1PQCauLDFX47n0OSJAf7ppeOJJ1kxhdlWxOTi56o
         HzR7yKmsdQlsCJudDLeZ6Gb6PV7bgcqhMX3l9BVV1JkVp30SxsN24hFKpE/n5wpEgMgy
         ROeCOw2HvyBpjfb137tKG8u/wRk53+nn+LsO/cq+bjHuIzbO6KaCkV7mNchAxGVIwAU5
         LkpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W8GGel9xZ9XYewAlKZTVZtByBFQEHOds3SnVhSpVEwY=;
        b=gWhzzjTaHyESYTmMf9AaJgrMQFx307HlBTwIQierAQhycal2Ombqu8aD2cUCMQb7pw
         8v2cF83LhmiJaSiC06hESPDBiP1ItuFCxKSQcchtV9wTwinCAfCMKki0IdB5AIPXx66d
         9rwno/TBDMDAPcndKDo/6Lt3E21/PPkc/FItny4GdlR602lZzFb4TrXyIvA5lc41tIV4
         ZDb2kHU/wWVA5Bu3Y8qgw3SRQFd3YB3c3hQ+O8LEQpmr6fx91RXtTbp2nFQ2Thl/66Az
         ytZyXMQ2bszoiHKLsk+95R8S1AXc1eiONfuoWh6AJi/CInvAhOQmm7q4BDrGXtPnsYrX
         WmLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mbyYcCH6nJics9Qcevu7SFBRb8H9zDQC7UojzM/+Z8zTTfoPO
	HKz5qrydQ5Ac8+L9wN8l4WU=
X-Google-Smtp-Source: ABdhPJwT+pZiMBBKCDnyBQ+UoG574fLOQ3HPR+cZoVbk/6PAv8wQkTLd/9jmGBOEFAvfd0XzoP9qMg==
X-Received: by 2002:a05:6102:6c5:: with SMTP id m5mr4535534vsg.59.1615814440978;
        Mon, 15 Mar 2021 06:20:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5932:: with SMTP id n47ls338422uad.10.gmail; Mon, 15 Mar
 2021 06:20:40 -0700 (PDT)
X-Received: by 2002:ab0:1c4e:: with SMTP id o14mr4857001uaj.14.1615814440448;
        Mon, 15 Mar 2021 06:20:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814440; cv=none;
        d=google.com; s=arc-20160816;
        b=u3zPeUp2aED+joTdS5U8pjH/IKxiuA+D3slaxZJEQjiwbvWFUcMmpWzZOZgL89xtjU
         XKE/kzI62UUJuehCg+foeIy1MkzQanjIRMtgSsj2TMMNj7McjxYyGQS4/4btY+nJhRVs
         kLGO8alsDly1laeWlE4HjlKfAJCsMk/PFwIUPYtuNBD35iq9qip/bQq9kDfAV+cyQXrw
         g2nTMquw0OwXu1m9cS9nwF6psrVL4agDc6gu2zArsP9cOeDX7C+PM1Evq4x90++jqCBZ
         FSFZstVIzoyy5GPXYBdqaalcBVbhAdQpn6DWf/3jWGY1ZUTv5F0Fw2Z0K1an/ci62RUm
         dMUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=k6eyMOBSr/5Wd7/D3QL9P1+w7p2OeH/6mpYEpYIHK14=;
        b=OgSLVZPaDEirl2eSRu827phxLQ7PEx5rh+aboOkZlWJ0Y9lSsz7z3SCGcEXN13QgHT
         xE6Jg9vGkFJQNVsjNrorDvFRh0yWNNR8BCTPLquW4MKAP1aVuToaoUG8w6ycoTgiKTvr
         EZdAi4WPEgF/fR1cTQyXQ1KvHBtxC5qvQcO+uF3iTwVVP9ZSKos8DfX6I7LaaZhpGogH
         TvhDSuyuUELZADVvL26tXXaqotYC4ePT9z4+ybyb++fh85uDYhrhZyagt/TpSdfkuoA8
         OitLnwvv7mttO70aA3Gi7EfXNhFIdNETPrGv0nH84FvRbN/+g2dLvN0rEcp0SJkxr4ze
         vuwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d23si791618vsq.1.2021.03.15.06.20.40
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BFB8B1396;
	Mon, 15 Mar 2021 06:20:39 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D9DD13F792;
	Mon, 15 Mar 2021 06:20:37 -0700 (PDT)
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
Subject: [PATCH v16 5/9] arm64: mte: Enable TCO in functions that can read beyond buffer limits
Date: Mon, 15 Mar 2021 13:20:15 +0000
Message-Id: <20210315132019.33202-6-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
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

load_unaligned_zeropad() and __get/put_kernel_nofault() functions can
read past some buffer limits which may include some MTE granule with a
different tag.

When MTE async mode is enabled, the load operation crosses the boundaries
and the next granule has a different tag the PE sets the TFSR_EL1.TF1 bit
as if an asynchronous tag fault is happened.

Enable Tag Check Override (TCO) in these functions  before the load and
disable it afterwards to prevent this to happen.

Note: The same condition can be hit in MTE sync mode but we deal with it
through the exception handling.
In the current implementation, mte_async_mode flag is set only at boot
time but in future kasan might acquire some runtime features that
that change the mode dynamically, hence we disable it when sync mode is
selected for future proof.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reported-by: Branislav Rankov <Branislav.Rankov@arm.com>
Tested-by: Branislav Rankov <Branislav.Rankov@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h            | 15 +++++++++++++++
 arch/arm64/include/asm/uaccess.h        | 22 ++++++++++++++++++++++
 arch/arm64/include/asm/word-at-a-time.h |  4 ++++
 arch/arm64/kernel/mte.c                 | 22 ++++++++++++++++++++++
 4 files changed, 63 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 9b557a457f24..8603c6636a7d 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -90,5 +90,20 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
 
 #endif /* CONFIG_ARM64_MTE */
 
+#ifdef CONFIG_KASAN_HW_TAGS
+/* Whether the MTE asynchronous mode is enabled. */
+DECLARE_STATIC_KEY_FALSE(mte_async_mode);
+
+static inline bool system_uses_mte_async_mode(void)
+{
+	return static_branch_unlikely(&mte_async_mode);
+}
+#else
+static inline bool system_uses_mte_async_mode(void)
+{
+	return false;
+}
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #endif /* __ASSEMBLY__ */
 #endif /* __ASM_MTE_H  */
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 0deb88467111..b5f08621fa29 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -20,6 +20,7 @@
 
 #include <asm/cpufeature.h>
 #include <asm/mmu.h>
+#include <asm/mte.h>
 #include <asm/ptrace.h>
 #include <asm/memory.h>
 #include <asm/extable.h>
@@ -188,6 +189,23 @@ static inline void __uaccess_enable_tco(void)
 				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
 }
 
+/*
+ * These functions disable tag checking only if in MTE async mode
+ * since the sync mode generates exceptions synchronously and the
+ * nofault or load_unaligned_zeropad can handle them.
+ */
+static inline void __uaccess_disable_tco_async(void)
+{
+	if (system_uses_mte_async_mode())
+		 __uaccess_disable_tco();
+}
+
+static inline void __uaccess_enable_tco_async(void)
+{
+	if (system_uses_mte_async_mode())
+		__uaccess_enable_tco();
+}
+
 static inline void uaccess_disable_privileged(void)
 {
 	__uaccess_disable_tco();
@@ -307,8 +325,10 @@ do {									\
 do {									\
 	int __gkn_err = 0;						\
 									\
+	__uaccess_enable_tco_async();					\
 	__raw_get_mem("ldr", *((type *)(dst)),				\
 		      (__force type *)(src), __gkn_err);		\
+	__uaccess_disable_tco_async();					\
 	if (unlikely(__gkn_err))					\
 		goto err_label;						\
 } while (0)
@@ -380,8 +400,10 @@ do {									\
 do {									\
 	int __pkn_err = 0;						\
 									\
+	__uaccess_enable_tco_async();					\
 	__raw_put_mem("str", *((type *)(src)),				\
 		      (__force type *)(dst), __pkn_err);		\
+	__uaccess_disable_tco_async();					\
 	if (unlikely(__pkn_err))					\
 		goto err_label;						\
 } while(0)
diff --git a/arch/arm64/include/asm/word-at-a-time.h b/arch/arm64/include/asm/word-at-a-time.h
index 3333950b5909..c62d9fa791aa 100644
--- a/arch/arm64/include/asm/word-at-a-time.h
+++ b/arch/arm64/include/asm/word-at-a-time.h
@@ -55,6 +55,8 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
 {
 	unsigned long ret, offset;
 
+	__uaccess_enable_tco_async();
+
 	/* Load word from unaligned pointer addr */
 	asm(
 	"1:	ldr	%0, %3\n"
@@ -76,6 +78,8 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
 	: "=&r" (ret), "=&r" (offset)
 	: "r" (addr), "Q" (*(unsigned long *)addr));
 
+	__uaccess_disable_tco_async();
+
 	return ret;
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index fa755cf94e01..9362928ba0d5 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -26,6 +26,10 @@ u64 gcr_kernel_excl __ro_after_init;
 
 static bool report_fault_once = true;
 
+/* Whether the MTE asynchronous mode is enabled. */
+DEFINE_STATIC_KEY_FALSE(mte_async_mode);
+EXPORT_SYMBOL_GPL(mte_async_mode);
+
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
 	pte_t old_pte = READ_ONCE(*ptep);
@@ -118,12 +122,30 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 
 void mte_enable_kernel_sync(void)
 {
+	/*
+	 * Make sure we enter this function when no PE has set
+	 * async mode previously.
+	 */
+	WARN_ONCE(system_uses_mte_async_mode(),
+			"MTE async mode enabled system wide!");
+
 	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
 }
 
 void mte_enable_kernel_async(void)
 {
 	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
+
+	/*
+	 * MTE async mode is set system wide by the first PE that
+	 * executes this function.
+	 *
+	 * Note: If in future KASAN acquires a runtime switching
+	 * mode in between sync and async, this strategy needs
+	 * to be reviewed.
+	 */
+	if (!system_uses_mte_async_mode())
+		static_branch_enable(&mte_async_mode);
 }
 
 void mte_set_report_once(bool state)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-6-vincenzo.frascino%40arm.com.
