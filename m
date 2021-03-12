Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKXSVWBAMGQE3K3MMCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 01B05338FBF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:38 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id iy2sf17576036qvb.22
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558954; cv=pass;
        d=google.com; s=arc-20160816;
        b=c5XfB5mD8NCUHs79iAvOV0rlEaI637Hj5Jic0FIrj7o7SPovvI1xad1iPjTGrdG/KC
         Xl6cS2qS7HfLGiLk0zOq1fli04iiwG79uV3rYNLBwwDsL5lKFEE9kDGwiL+EF8pG8hAN
         pNwf0ccKRkHZwSacUa5k6rhyrNVP0n+7LGpVsaAwRwo0QhJBXtjIdpgWY7fXlWXbXA+g
         XXpoNayXlWbx+hJZP/wvlR4KaerAqQDhnqf4SDXJqPP4ATXuJtS2a5Pr0vxid685RgoF
         i6D9Q2NonuSskIsSrF9cl+9VBYV0v6dSA/9qT/CTiBeoIxzSpGJNbevwEVYs0Ntr863m
         yUDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kzMwEhnn0L5+/ktgClpb+Jvw+ty5lwmPb4aHVlLAIV8=;
        b=TCmsUdAjg9ETsmSYZ67bLnKPwQrBHcur6T0YnwYk3RFOv8mTrW9fWkqgwAadSV9Ia3
         Rz7RWKQcfUlWLd/QcyxO/rbleED4OPab4zxZ99EEUKUCVLNT13koorgwbnxNyxzRKxQY
         rG9H3Vuk8JEi9K672iojYS2IiW07o9OWS4T0xJY38ZmqAtWJ+qJ0JaAawUQlpi5swcHU
         mnJO7LDQiGxIYTNbld1V1rFOSLrl2qVkUwDg1vjDeO8wBxywENfLfXIDzTBITI4Ymsfq
         PJflITy0r/YodAtFd8+05lReowrAKywFmKxbRqEOE8Hi3tYUiPPschQ+euicWPQj4XKP
         qrfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kzMwEhnn0L5+/ktgClpb+Jvw+ty5lwmPb4aHVlLAIV8=;
        b=VT3QQA9Fh+dg3xUerJR3D/Akr9me0NNzFFO3pQPK+soRL8Zo8SuhNMkaerXcuBlk3Z
         clF5NdUFkmQJB17epfOL1i8HKMBgeqJ5+3uWAigtYb82xrBzlzopk30Ng1Ni7LIk4Es5
         fRQatDBcTBcFSeX9ueyDYFonOh6GtnwkZUMJz/FxPw07/+NPfdhy2Fal8OVDJbhaO8dK
         LTYvj25RdXDsCa8U0oXk6rV7hGe9aH/p7x7i63KJo1uUnbwuL4w7ZascMKqoGYF9/A0B
         ytk/cRsOjsokodjbHDmecLYtD47jpgfkLSa/lhSsck5b4AZR4tm9mRgcbItGcoZ/l+HQ
         3VpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kzMwEhnn0L5+/ktgClpb+Jvw+ty5lwmPb4aHVlLAIV8=;
        b=LqfFlax9HX3I0kNUE97BiFY/o5K52G2rUgiXW6Hw/mYusKUkCdMHZX3M06eiyzC7jE
         Tk9O9ONcmmGCtFW7wyvR+aflkr11NaUZYAlpPAY3rdR1LSBCO4A07ilTvi6On2hncmGB
         Wxiquj3QID3mauNOdSgsmJLX1g4+PrrtxFI56yasYf0on+c/reDgGrJjAYCL20AXzFQZ
         /xBkSg3J2jvuH/e+3Iq8uEYIOBHgAtwT7BVH1g4Ro7nTXz3G7fy4oSYqZwQdQR52UBAh
         7hfzH3LclP2LwmDQuwndWHhRW7nLuVqHPikotf19foJxMbe64ZjABmPFEZ7IV9MBEtfY
         HsWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532gXRJSNzSrXaZca5tqqrunc983sINzEBtDVyFQbv7OSaCXWFgJ
	2rZn15oIYBH/pJDOueextnE=
X-Google-Smtp-Source: ABdhPJyuuxFFYo+nChImPgT0XTmF5iWTCZ5hSBu90VCVLpm0x8aoMtOeuI10DruSZpZ+wrV/i8oeXg==
X-Received: by 2002:ac8:7b8d:: with SMTP id p13mr11881512qtu.367.1615558954509;
        Fri, 12 Mar 2021 06:22:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7508:: with SMTP id u8ls3524395qtq.0.gmail; Fri, 12 Mar
 2021 06:22:34 -0800 (PST)
X-Received: by 2002:aed:3104:: with SMTP id 4mr12000244qtg.341.1615558954077;
        Fri, 12 Mar 2021 06:22:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558954; cv=none;
        d=google.com; s=arc-20160816;
        b=hFZKWxQablNC/xTP9B5m/0wykhLPYz2RAMPp3v5YvJeyLueZu/zJ6Jcj0zp1NZ9Oud
         3PWKIhNW8BfeFKsHWx7d1HcQhhCmNk5MZJMIcyM8ET1cCj8JmDgGdQynolIg3aMhW/YM
         3i8W0E00H6wifa6OeQIytDAI0J+Lu8+q7DXPGLDv7059Ajq1RQEIPTcrBhaEiO/RYScO
         xGYTO/MngK1+RY/RqOViH4KN4cD+iRmU/mIRujZdMsfrQYBdutrZod3wI5IAgkQ4LGgd
         JS3P6bDQg7/GkyAz2D7UZIS7G+lzjqbv+fPaS6GjK8JaS5Qz0WeM0tnepUtvRSonTfmY
         Z5ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=wpOiVM7sxd0lKhHwVyz+fnSjyIvE1EUjOSq5BO0SsHk=;
        b=bdP81176UcqE0nI7TUBLCjfbZP0uodjIKIlkD1LQ4LlmoqIbf0CDEt2yTIBH5OdW7B
         v7cX8LvxXw4iAO8uTOg2eED1a5WQTYW5Wlqddj2qywLOvnULX/JYuNHvt2I929476YSG
         g2YgMQLLTdCp/dXPEgaqaAN+LaIAxBcBUI66OfZJ+yyMrL6jXgOk8OR/PGYDxWZPF4u2
         UF62UP9a1KNjLCRpeOCYHCJ6Ft8xl9wvfTjBYT2kNe39+mOFeKLnIpx21sut+pLrBCty
         38lRm+FGd4x96WGsn9je/BCgS+XWisejWf6yzinEZlmDpV37VA6gukVNnwkcVRoMHuT9
         VFHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b56si346191qtc.5.2021.03.12.06.22.33
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:34 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 693151FB;
	Fri, 12 Mar 2021 06:22:33 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 85EB03F793;
	Fri, 12 Mar 2021 06:22:31 -0800 (PST)
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
Subject: [PATCH v15 5/8] arm64: mte: Enable TCO in functions that can read beyond buffer limits
Date: Fri, 12 Mar 2021 14:22:07 +0000
Message-Id: <20210312142210.21326-6-vincenzo.frascino@arm.com>
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
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-6-vincenzo.frascino%40arm.com.
