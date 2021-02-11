Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6E4SWAQMGQEOFMB7AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 51150318EB6
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:34:19 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id t6sf4279945pje.9
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:34:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613057658; cv=pass;
        d=google.com; s=arc-20160816;
        b=aibr7/zYpZ39MVL+S2zrBIpbgfXWOITRH/ylGe/xwd6IjCLUp80pgF+sCvXuQKCnTr
         1UImZla+E2uewXgT2zxhIoGmx67kU56WbP+reT01xsqx8Rmkrp7A5DLR6nmLOwRlb4U3
         EftyrA/qHSB04z18CX5kmJHOcb0JyajaxGF1zqvWVYeyxClxTVBkCP+HaVggTCmTpfEs
         3CNbp4D2DgdFsfSUpF07/DY/fMfgfLPlhANHk3bDCVGSqUhSdcdqnoq6AeXr7NIbnBZz
         0bOQSEVSpK2N4rP1VQvdPyWqe1P4gYy24mgzZly1jSUFOG8QAHcWeRejGzqfKOIe7tou
         7Bhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QjOZv9px9Yss7Yv7lQYQO9g/TYx4UANLvvPO97hXt3A=;
        b=CJauGrm2nB5DiRR8HjjzGxRPDJJdprczOeI0/D9RUym0JedwxulKtCwZY7AZFgewlG
         pKo5BhDvUA5Huq1CuXNHxv/YBcpO3uGDAHOiHBbqInZFFRxbnTJefVz05Co/om2InfC9
         TwPc3Y36qoGsfW0HsUIBfjrmkD2oApntj1vS9+bkEKTrd4KSKcoiuYCatAqxERPX+bko
         Keforw3AwG2Y89hxcb7mZQBFJmPl4gqesGs5NzS4u9h/yBFZmMyw4rg79ecYFYv2cLHB
         wjfMIfTStUiT4ft6E69uTHWUnUxOXJSm29ltrTsFUE3rBo9EsQiscBcj/WDolpW2iEGB
         zmPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QjOZv9px9Yss7Yv7lQYQO9g/TYx4UANLvvPO97hXt3A=;
        b=jYuHL34lYM1wECWQ93DmkaI0LOQFtIQ5vAp07vruXACHCBvbk4CdX7GjroepeczHQb
         J/K2jbiY8D1HLPG3Z/i65nOGgl4ybkObd/5KknJEgytPAY55PyKr5qQv5FcKtTyGWY/6
         DkC3bP2vWAmZLXC8+RXJiCkRR94cjHuXD6M7FNjQB3MZQzHTIOqkc0piR5QAJMoOP29W
         fY67r6AQ66iyLljHADEtg4Gw0UBPwAPE4dZaWb9UfeJgSk+usFH4gwAyZcHSaq/Zld/Y
         d5hNHRMhUpHs1Nyb1CnN5vR6dwLiz35Oi8fBv+E/2UK3S9FVuA0wqMiQU9GVfGB9PtRz
         q0iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QjOZv9px9Yss7Yv7lQYQO9g/TYx4UANLvvPO97hXt3A=;
        b=Qz/E3a7J9978YC5/9kxiVIg3/W+qxvqy8PlmGHp1/AoSWKAAc4Q9zz2SwVuIQwBtxc
         g74/XVEXexsfWDKA2NR2fLLYx5N5k77nMRY8lSFUsenT1H7hMzxY2NSFOFkmDnBVAqfk
         D8SVF0YkDLkZiinPe9+i9+5rDKFGnCHTREoN2+q5WGUv4V26orcHKW5cK+2C4SfqvEOj
         UINS8g0g+goc3QRg3W71/sweVRkIRmqRuw4/eYZcJjMDeLriSo/su3XC+SLB8Z32OgjJ
         0EXl3Dzs4v8kg0gTXeQ7CUoFd3rWp+Fo8AZ9ca2tGo4lmK7bDovl1n1WAmAo8UpEHuME
         uKtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336aC6jm6TP2F8LqVvGrRFDwUqhPrfrv8RLJlqgXV8nld3Idpg4
	f+r10e091PWXYKg6QjAYM3Y=
X-Google-Smtp-Source: ABdhPJwYkQV2DxvteiMM1HkJfRbOrcVOrXHnGPGCKMWwlJCczQ/Y9iRs+kpC0vqE7GNrTMf2lO8uZQ==
X-Received: by 2002:a17:90a:9a97:: with SMTP id e23mr4548885pjp.144.1613057656735;
        Thu, 11 Feb 2021 07:34:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2dcd:: with SMTP id q13ls2847099pjm.0.gmail; Thu, 11
 Feb 2021 07:34:16 -0800 (PST)
X-Received: by 2002:a17:902:6b87:b029:dc:3402:18af with SMTP id p7-20020a1709026b87b02900dc340218afmr8231928plk.29.1613057656049;
        Thu, 11 Feb 2021 07:34:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613057656; cv=none;
        d=google.com; s=arc-20160816;
        b=qXLlRKsGWERTHrr86jnTArveBiuXGQhUN2nuB3gHI8hL717amEzk4oxB72t7JQu5PG
         jaCuDlp7kMQxyOTtVoizK9daxTS9TURYa0wn/88EjGMcHvMdIAH/QsIkM4HXohRcTu2D
         dWhCwGhVsSaI3Mj+Cq0MsQOAxy4brpWSPfN1GHseSIFkWgWCbjGBK2UVbrPANwNbl56k
         +Bbw/UUT2K4+zuq+lHhgV6IBRIP9d2AQRcaaExMkQYlZc0JAsq15Ur8oqmN1U3pVruMv
         RA+bQ+mmcYYplQlbu+jWcefK8pdc0/iEJVXAma2mLDYzcVTD3tDuSq/pAxfFn3Y9+OX/
         qryg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6/P+v4uXIy7+d/wE7uBEoQOSkky24KjQhAUssibQuyo=;
        b=H24ysSah4HtUCTw7TTjXKn3m5mJ7n2qB6a0ZxcHEHtDof2WG+YwmEgmTL4RFMqhXej
         oWTBry2Kqs2pS4Da/un7b2z5vr8Ujb+uO4tuTQNJP4qE7ZTeqPK9lPCAe3b9ENbbpQ3f
         90toWhndBCpSVlWBe4iVeQeLmQJIfYpKpJV3V4FbHyWPYOLoakxlgN6QBBJT8tFiw6zb
         xUO8aDgPWc4gdAHUyeM6ctKNnYCVrNnnb/b9qqV10DBL9r1zLMW3IkAGPUFJ/fUXuJVQ
         ATGTGyjN5gT0wcBF8jnafB4lLmsYyYh+W7dcApv1IQqm3HgfYwHQy+MDA9lGu5dshDVf
         mtDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si334192pfr.4.2021.02.11.07.34.15
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:34:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 078891424;
	Thu, 11 Feb 2021 07:34:15 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2182C3F73D;
	Thu, 11 Feb 2021 07:34:13 -0800 (PST)
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
Subject: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can read beyond buffer limits
Date: Thu, 11 Feb 2021 15:33:50 +0000
Message-Id: <20210211153353.29094-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210211153353.29094-1-vincenzo.frascino@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
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
read passed some buffer limits which may include some MTE granule with a
different tag.

When MTE async mode is enable, the load operation crosses the boundaries
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
 arch/arm64/include/asm/uaccess.h        | 24 ++++++++++++++++++++++++
 arch/arm64/include/asm/word-at-a-time.h |  4 ++++
 arch/arm64/kernel/mte.c                 | 16 ++++++++++++++++
 3 files changed, 44 insertions(+)

diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 0deb88467111..a857f8f82aeb 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -188,6 +188,26 @@ static inline void __uaccess_enable_tco(void)
 				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
 }
 
+/* Whether the MTE asynchronous mode is enabled. */
+DECLARE_STATIC_KEY_FALSE(mte_async_mode);
+
+/*
+ * These functions disable tag checking only if in MTE async mode
+ * since the sync mode generates exceptions synchronously and the
+ * nofault or load_unaligned_zeropad can handle them.
+ */
+static inline void __uaccess_disable_tco_async(void)
+{
+	if (static_branch_unlikely(&mte_async_mode))
+		 __uaccess_disable_tco();
+}
+
+static inline void __uaccess_enable_tco_async(void)
+{
+	if (static_branch_unlikely(&mte_async_mode))
+		__uaccess_enable_tco();
+}
+
 static inline void uaccess_disable_privileged(void)
 {
 	__uaccess_disable_tco();
@@ -307,8 +327,10 @@ do {									\
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
@@ -380,8 +402,10 @@ do {									\
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
index 706b7ab75f31..65ecb86dd886 100644
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
@@ -119,12 +123,24 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 void mte_enable_kernel_sync(void)
 {
 	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
+
+	/*
+	 * This function is called on each active smp core at boot
+	 * time, hence we do not need to take cpu_hotplug_lock again.
+	 */
+	static_branch_disable_cpuslocked(&mte_async_mode);
 }
 EXPORT_SYMBOL_GPL(mte_enable_kernel_sync);
 
 void mte_enable_kernel_async(void)
 {
 	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
+
+	/*
+	 * This function is called on each active smp core at boot
+	 * time, hence we do not need to take cpu_hotplug_lock again.
+	 */
+	static_branch_enable_cpuslocked(&mte_async_mode);
 }
 EXPORT_SYMBOL_GPL(mte_enable_kernel_async);
 
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211153353.29094-5-vincenzo.frascino%40arm.com.
