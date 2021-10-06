Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBPEK66FAMGQED4FZ66Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D9724241C5
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 17:48:12 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id a10-20020a5d508a000000b00160723ce588sf2398665wrt.23
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 08:48:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633535292; cv=pass;
        d=google.com; s=arc-20160816;
        b=QpjWR12YoF2o/Ca5urye0kecgkSmYdSMXhu7/uY2swmgcZ0i4CzzZhJQ633lKAkHTE
         HSqLU7sBdKyPx9whWKCN3V+KOpf6j4J8OtiAP8DGUkIaAdWK2rM5s86HgiMML5VBBd+o
         S6nv9ULOXASCrPg0oqaFeRl68o/haNy1cBPRtqPoSkUx+Vc7TQ2h3EFdIX68xAYzVp0K
         RCFvyBH0VEEIHHWGhKOGmk533tOPNBQWkwM2X3w8m/zLJhKoJPJ2MbYObI6HoVJqo03i
         IkzOy3/ykVDeauwD6Sh8kRo86vg3Rt4+0N9Ca0zTyqnoubu1UioCGucxbVg/ZE/HUWIl
         nyzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1Wf33hRTxeg3rC/wCxeAwAcjXllyfgGL2P6pisMP7Dw=;
        b=DbguSWaO1GxTkFmQ/0q+F8lnmAMEht8SUFAq+sWFOr7oThMH3ps3XvIKhIrDPPaci+
         K3yUgteKrJALiSBswtx2Zt95I8wNalYKl0i0XMRMkFvdNPte660n24zmwogjCEpbqWqd
         ksTw79iOA3WK4S3i7YgizwWrZy7QAJZaSHQGvXfWi+WO8XvePVDUElHVWoYLjp0lRp45
         rsrGRyX87ytEhPpuDG5ce+VFtrQnnPaJ7obH38qrVlM9DN35aPqn4ZJj8PaziteKls+w
         sxsCV6VvxT5JREzl3fZRG/yHP/tQs7SWivBS0GhWSy2Z4qveZ4LidldgXKpTVtM0k33Q
         5yrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Wf33hRTxeg3rC/wCxeAwAcjXllyfgGL2P6pisMP7Dw=;
        b=otEzk2Rh/cmy/wpUoZTWT2VbmXe3UvArYvs4p+BaxmaoI+lujmd7H/sTBUocuxKa2i
         iwuOcoeVczlWgjs95YjnIJYqWVk833AyzZBG5K5CJkqMXwpvTyFvxs+XQtfT1W05HJQ3
         42sAEGwOU6kWHGE1uNl36ac7b/zFFmYJEgas9vtqUtttnroTR/18uZZ4tUDEhQQqsc9Y
         IWRPE/AG5W1s1xs71Lhhp0Od0VTGOCOddxsQAvPmprIeO39tRHEhc3val2JWP8aQnlXy
         2WHdehhN2INUFyEfUjKGP5zYQKVhLZEM5wU3+ui5RA+OUuOyr2xCtOKQRCgEFcQGGxwK
         DRAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Wf33hRTxeg3rC/wCxeAwAcjXllyfgGL2P6pisMP7Dw=;
        b=0slBuXkLlflTzMijKUe0Nz5MVfkyff6+hjnUweY6LcbdW1V5MCQR9vy4RNVKoo0D5T
         DCcnWzCAvYeWdTOCLzAw8cad5bzMIMoczPk/7dURiVPI734uOa5k78CfJuh7pwJFGHfN
         r542Y5NouVCj//6DP5B25tuiaVfuA+4o3ejs53MLFxe1zqKS4lqjvSmGCV9QJnjIYIgj
         1oc1YFIZSnKPDV3Zzq/zVRdFtWH+tzOO+uxwcCVuAfoGkIYgMV+79V7BvAv9v/RWL3kC
         38yK1I4vlZo7AFkgUZN2hUqqB3E2ioZUbUvMf7d8ruruI5wnZLlYkJXZpaGnjdsoE3Yg
         P1kQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531I9Ko4kBZyZVOkYuifDnh0NL5QwWeLD8+uJVTVZ5L1xCYWHgFl
	bCRmHknpW0o+IAgW9CHLbGg=
X-Google-Smtp-Source: ABdhPJwjOmuodVPdiES1B56aIIraIowgtoo+prsq810wrEv7b6LNwhHH9Fi1+1TLV3SkKXJ8hRUfcA==
X-Received: by 2002:a1c:19c6:: with SMTP id 189mr10614668wmz.121.1633535292189;
        Wed, 06 Oct 2021 08:48:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c782:: with SMTP id l2ls702039wrg.2.gmail; Wed, 06 Oct
 2021 08:48:11 -0700 (PDT)
X-Received: by 2002:adf:b7c1:: with SMTP id t1mr29279059wre.387.1633535291331;
        Wed, 06 Oct 2021 08:48:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633535291; cv=none;
        d=google.com; s=arc-20160816;
        b=iRbLHo1DMMwNnvfjx6PBmysJZFVMo+qcPjDO9Pa8SSl0AWVbWc7UDRxhhV4+Pe0Mqz
         lfGvHy1SjH52L9eO9lm8ApdVA6tkcuYkbOOrnUDYCsDgT7WSIBUgatUlmUVUsDIe97FK
         SssB+pk1runDhyeQQROUD4YgEcVLEL4WSuD83FERXjV8HllNK1wkHToEsA6vph1qFesV
         ON23NFSmUU/chOhxqyfnipboNbl7KYxdgLyFdusZPAUCP6KVPt1FJmdddJU+oaOlX1e2
         1lFKS0fqwb7hVp87TPueZ5I7lNySAc+5a2NCLKSUj/QQvMSIlyfv6XmBKbDs1scX1aMz
         r0qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=JljOD24oXEEVbfNXZJPmgkz/GDK9kRPEfogjuHQ0ypk=;
        b=rEvqxQDyeVytzkJk3IdWkl4d0fPOzvR6tszjSeJ26CIeirDluRyiO/KcGCvv92kXRA
         Igq4AnjO3VzJ7i86H7s1/lmRtMgVEyuBYVREi4qGCgw5vM7jkReFJpRwuLnxVhOzGIdk
         IUdk4VOKO6Gqb7ZwNUC40GcnmQRR0U0DytTZ3hKvZZDfTspS5ZFLsHE+8a8/Rnw09g13
         yxIEhTqjSJpKSBVqOMWTUIDA9Q+Meqy7cpStGKSKyF2SSmSFGLJ8p7M1zkchIfOfzi0P
         IOsrTTu271xKtGU1juUCCAA4cQUjtDR63MBo+fkAQ8xLWJRY6oOMiNBZF7npsO2EJgJH
         iddA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l3si371929wml.2.2021.10.06.08.48.11
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 08:48:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 85F5BED1;
	Wed,  6 Oct 2021 08:48:10 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A53DC3F70D;
	Wed,  6 Oct 2021 08:48:08 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v3 4/5] arm64: mte: Add asymmetric mode support
Date: Wed,  6 Oct 2021 16:47:50 +0100
Message-Id: <20211006154751.4463-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211006154751.4463-1-vincenzo.frascino@arm.com>
References: <20211006154751.4463-1-vincenzo.frascino@arm.com>
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

MTE provides an asymmetric mode for detecting tag exceptions. In
particular, when such a mode is present, the CPU triggers a fault
on a tag mismatch during a load operation and asynchronously updates
a register when a tag mismatch is detected during a store operation.

Add support for MTE asymmetric mode.

Note: If the CPU does not support MTE asymmetric mode the kernel falls
back on synchronous mode which is the default for kasan=on.

Cc: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  5 ++++
 arch/arm64/include/asm/mte.h       |  8 +++---
 arch/arm64/include/asm/uaccess.h   |  4 +--
 arch/arm64/kernel/mte.c            | 43 +++++++++++++++++++++++++-----
 5 files changed, 49 insertions(+), 12 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index f1745a843414..1b9a1e242612 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -243,6 +243,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #ifdef CONFIG_KASAN_HW_TAGS
 #define arch_enable_tagging_sync()		mte_enable_kernel_sync()
 #define arch_enable_tagging_async()		mte_enable_kernel_async()
+#define arch_enable_tagging_asymm()		mte_enable_kernel_asymm()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 22420e1f8c03..478b9bcf69ad 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -130,6 +130,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
 
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
+void mte_enable_kernel_asymm(void);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -161,6 +162,10 @@ static inline void mte_enable_kernel_async(void)
 {
 }
 
+static inline void mte_enable_kernel_asymm(void)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 02511650cffe..075539f5f1c8 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -88,11 +88,11 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
 
 #ifdef CONFIG_KASAN_HW_TAGS
 /* Whether the MTE asynchronous mode is enabled. */
-DECLARE_STATIC_KEY_FALSE(mte_async_mode);
+DECLARE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
 
-static inline bool system_uses_mte_async_mode(void)
+static inline bool system_uses_mte_async_or_asymm_mode(void)
 {
-	return static_branch_unlikely(&mte_async_mode);
+	return static_branch_unlikely(&mte_async_or_asymm_mode);
 }
 
 void mte_check_tfsr_el1(void);
@@ -121,7 +121,7 @@ static inline void mte_check_tfsr_exit(void)
 	mte_check_tfsr_el1();
 }
 #else
-static inline bool system_uses_mte_async_mode(void)
+static inline bool system_uses_mte_async_or_asymm_mode(void)
 {
 	return false;
 }
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 190b494e22ab..315354047d69 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -196,13 +196,13 @@ static inline void __uaccess_enable_tco(void)
  */
 static inline void __uaccess_disable_tco_async(void)
 {
-	if (system_uses_mte_async_mode())
+	if (system_uses_mte_async_or_asymm_mode())
 		 __uaccess_disable_tco();
 }
 
 static inline void __uaccess_enable_tco_async(void)
 {
-	if (system_uses_mte_async_mode())
+	if (system_uses_mte_async_or_asymm_mode())
 		__uaccess_enable_tco();
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index e5e801bc5312..d7da4e3924c4 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -26,9 +26,14 @@
 static DEFINE_PER_CPU_READ_MOSTLY(u64, mte_tcf_preferred);
 
 #ifdef CONFIG_KASAN_HW_TAGS
-/* Whether the MTE asynchronous mode is enabled. */
-DEFINE_STATIC_KEY_FALSE(mte_async_mode);
-EXPORT_SYMBOL_GPL(mte_async_mode);
+/*
+ * The MTE asynchronous and asymmetric mode have the same
+ * behavior for the store operations.
+ *
+ * Whether the MTE asynchronous or asymmetric mode is enabled.
+ */
+DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
+EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
 #endif
 
 static void mte_sync_page_tags(struct page *page, pte_t old_pte,
@@ -116,7 +121,7 @@ void mte_enable_kernel_sync(void)
 	 * Make sure we enter this function when no PE has set
 	 * async mode previously.
 	 */
-	WARN_ONCE(system_uses_mte_async_mode(),
+	WARN_ONCE(system_uses_mte_async_or_asymm_mode(),
 			"MTE async mode enabled system wide!");
 
 	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
@@ -134,8 +139,34 @@ void mte_enable_kernel_async(void)
 	 * mode in between sync and async, this strategy needs
 	 * to be reviewed.
 	 */
-	if (!system_uses_mte_async_mode())
-		static_branch_enable(&mte_async_mode);
+	if (!system_uses_mte_async_or_asymm_mode())
+		static_branch_enable(&mte_async_or_asymm_mode);
+}
+
+void mte_enable_kernel_asymm(void)
+{
+	if (cpus_have_cap(ARM64_MTE_ASYMM)) {
+		__mte_enable_kernel("asymmetric", SCTLR_ELx_TCF_ASYMM);
+
+		/*
+		 * MTE asymm mode behaves as async mode for store
+		 * operations. The mode is set system wide by the
+		 * first PE that executes this function.
+		 *
+		 * Note: If in future KASAN acquires a runtime switching
+		 * mode in between sync and async, this strategy needs
+		 * to be reviewed.
+		 */
+		if (!system_uses_mte_async_or_asymm_mode())
+			static_branch_enable(&mte_async_or_asymm_mode);
+	} else {
+		/*
+		 * If the CPU does not support MTE asymmetric mode the
+		 * kernel falls back on synchronous mode which is the
+		 * default for kasan=on.
+		 */
+		mte_enable_kernel_sync();
+	}
 }
 #endif
 
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006154751.4463-5-vincenzo.frascino%40arm.com.
