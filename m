Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYW4U2AAMGQEMOKZQLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id BA5FB2FF097
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 17:40:03 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id j25sf1070893oie.12
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 08:40:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611247202; cv=pass;
        d=google.com; s=arc-20160816;
        b=hXZgSOMafcD6KNaL0d1xDBgZlg7a1fFUBBUPRptg87m8IRwmJFPWk/nINIUHfhYJzc
         cpgthK5ULH4QXSbs+5WOMezLsr0TDhHfpZne3KM+oheBzNp1URB7TLKHkP3HlkRLLo93
         ncxnZrRQbsF8jDxhAv21S9aYcj7C4tltZYyoLLDuBbtVepk4DdCAs1VvLSokfjcAmwRm
         lnX/0RdP82kIrox0E98jaPN0he4c471dnr3xsGJxg0lIDD4ofQQwwPstJncdaEoBL2Ir
         3IJV/qHIA8Sae/aumgXyNZqXXIz4yTXUMZPamTW6/JCPG5ojjLzYAILnMCNfKi7nIXIq
         Vyew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qzuZLbnyzVzQnfBVyajMgfh0OE7Zl7U5lDCV43U2oJo=;
        b=pCs4Bt71HPd+CyDqq3LOec6pd8Ys8xchoq9FHEEc8dFDIPd44nHYkaxlapOTsH1lly
         OMrEySQ2UP3KEw21uoIbjkKZ12mVzQNdE7653UdUcw4cClIlDKQadqR8KnkXPZ+5eubR
         DJ/zxNM6hKz71LaY6v2hi/jBL4iy8T6OxuY4jMUNI0T9sEufGqb1Csuqh2Fad+w1tNnz
         CjD/TllkiP2hP2dK5UgQXFePH21NoIp/kZUX6A+Bh7nL2JLqIhEkoaI84je7Os6OlsuE
         10vQsffxPCCL3daNoYbda/6auFg2J2XxPuYDvB3mlbrkX/eN/yUV+dydQrbQqjzrG8Er
         K1CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzuZLbnyzVzQnfBVyajMgfh0OE7Zl7U5lDCV43U2oJo=;
        b=VGe3XkjTdjfpxgMqKo99z0tpSTpzgIQ8mkNHZf5ffDGW+7pZgZHTWQIv2ouR1Tuh5y
         fgBspfCNaoEi6KhsocGIy48Sw6iBfTj37gfox427nGpALbju0c2ISvBcP3ykDf9zfp+1
         yBstiRqQ+fP4xbSXwIwidu4wHxZHJEVacamXew5go1Hh/IhbgG9LryuJWROS5zn8WgY9
         eKHRQo0LCmyMaU3xjkqTlTnRz2xF3a069SbiNreAm2M8mCPDOvfHStuhcsWG8RzBQtvn
         3r4r0KuGDoiSpwI0Ay/AxNZElVSSmzTzCt/XZ87GJBvSuApM0Dz7f8RyZIRQin/+/T/c
         9taw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzuZLbnyzVzQnfBVyajMgfh0OE7Zl7U5lDCV43U2oJo=;
        b=hJb+3FIsMih8SRvZjN3HUMFg+0dKV/NFq9bhlLfaH8GIlLW1SxIKMryKWhJwuiQ9bz
         +C+CanjaHTOvlksEe6af1zcabz81dUirYMlWpxFZlQP/WZitQbvTF9hH325hKXIkUVYK
         HeeeDct65p/FIiPHyXIg3Dvc0QlJQpeyqOmgeZyMFlhl+xA2Ey8wpvxp6so/9Mq6e2Lh
         Fjj7CXt+xj6/EyCkACK8XKSG+ul+EOC/5zkElBwwnxqdX1ocNulkBDtQOZ8NFQNHgFCr
         EvMuT1og+Jyameo8g4gIZ/+rGYT6hAYEKcQ25PCCtL9ZPVSAzY85u8IolRj3noWn1TZx
         PRsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HOC8y/kfXPQZwEBSci+HzUIhoRSeJQR7+x8521FBc0XJb7ewl
	+aOXWvNP61fDq4v0BvGzd4A=
X-Google-Smtp-Source: ABdhPJwO3DjncW5xXNurTlYFkR6oVAPdo2VVdeVCNSwG+qKn1eRaIFiZ4c6ueUZFXxa4YT/J23b2IA==
X-Received: by 2002:a05:6830:1bce:: with SMTP id v14mr11146093ota.154.1611247202777;
        Thu, 21 Jan 2021 08:40:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1592:: with SMTP id i18ls73486otr.10.gmail; Thu, 21
 Jan 2021 08:40:02 -0800 (PST)
X-Received: by 2002:a9d:1284:: with SMTP id g4mr4580847otg.128.1611247202415;
        Thu, 21 Jan 2021 08:40:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611247202; cv=none;
        d=google.com; s=arc-20160816;
        b=pafXUBBiOFBPMCrNm/p2peieUAzNK6rAg7zh9quB1NQfpzNysFpzCVQ1BxylyyBclU
         XE8LLAsfWv7FecqhbDeqLnzf+LMzYGCtQGAkZjyi40QiCTNJB1TogtmBBJd3iT9vNnjm
         mfW0lb6hUvdEoNemUA0SRD9VNIvFuWBEeYHpqqjWagOlVJvfxVeKwb0W2iWhDh/zwS/k
         0LWcGEj0KUPyAvgJ1kx3r9+GyonjIdui9DT+/aT8q17osMLMNHhZ1qtMPS8RsOt7nfBS
         glKSnx8G3s5gV3j1r9O6lDena0C8i6LgqAnkuOjZGnRfUWC1M0MW0Ii++VsimLziA85V
         SuLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=9K33l0AArJFvIEbx+WR8uCSkBC8AAA84rc/I5FNE/J8=;
        b=rS3j4SG3r947VE940aUgnu5wSAkgNRa4NVShUzRGMdnm3VrhwnuvZYMOZ9aj7cfJcD
         6LdCWuoiQIP5dj0H/XGlIjq+m3ZS1ZyjbG4G6y+heh+3U9LHHFkUqhXozzhtToVDS5RL
         a8AUiWDQioGFwJCm4L54n7dUL5e6uDYkRYrd6QiloJ7psNrOMypaWruKJVXUkZqVqr2P
         H2Hcpv/oXl3UaZmBqZTPDnvwgw827PjFyUTgpI1b6dnD237H2qbpmz8rbXWDfpKIvE5Y
         0n7E8JeUVMkhx68OiXbz9SP8jawi86/LokzBlFwnk7pkODC2Tiy5+beepMSkLc+3h5wx
         KoKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t22si256207otr.0.2021.01.21.08.40.02
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 08:40:02 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 37E9F1595;
	Thu, 21 Jan 2021 08:40:02 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8C92A3F68F;
	Thu, 21 Jan 2021 08:40:00 -0800 (PST)
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
Subject: [PATCH v5 5/6] arm64: mte: Expose execution mode
Date: Thu, 21 Jan 2021 16:39:42 +0000
Message-Id: <20210121163943.9889-6-vincenzo.frascino@arm.com>
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

MTE enabled arm64 HW can be configured in synchronous or asynchronous
tagging mode of execution.
In synchronous mode, an exception is triggered if a tag check fault
occurs.
In asynchronous mode, if a tag check fault occurs, the TFSR_EL1 register
is updated asynchronously. The kernel checks the corresponding bits
periodically.

Introduce an API that exposes the mode of execution to the kernel.

Note: This API will be used by KASAN KUNIT tests to forbid the execution
when async mode is enable.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    | 1 +
 arch/arm64/include/asm/mte-kasan.h | 6 ++++++
 arch/arm64/kernel/mte.c            | 8 ++++++++
 3 files changed, 15 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index df96b9c10b81..1d4eef519fa6 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -233,6 +233,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #ifdef CONFIG_KASAN_HW_TAGS
 #define arch_enable_tagging_sync()		mte_enable_kernel_sync()
 #define arch_enable_tagging_async()		mte_enable_kernel_async()
+#define arch_is_mode_sync()			mte_is_mode_sync()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 76b6a5988ce5..c216160e805c 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -31,6 +31,7 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
+bool mte_is_mode_sync(void);
 void mte_init_tags(u64 max_tag);
 
 void mte_set_report_once(bool state);
@@ -64,6 +65,11 @@ static inline void mte_enable_kernel_sync(void)
 {
 }
 
+static inline bool mte_is_mode_sync(void)
+{
+	return false;
+}
+
 static inline void mte_init_tags(u64 max_tag)
 {
 }
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 7763ac1f2917..1cc3fc173b97 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -26,6 +26,7 @@
 u64 gcr_kernel_excl __ro_after_init;
 
 static bool report_fault_once = true;
+static bool __mte_mode_sync = true;
 
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
@@ -169,9 +170,16 @@ void mte_enable_kernel_sync(void)
 
 void mte_enable_kernel_async(void)
 {
+	__mte_mode_sync = false;
+
 	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
 }
 
+bool mte_is_mode_sync(void)
+{
+	return __mte_mode_sync;
+}
+
 void mte_set_report_once(bool state)
 {
 	WRITE_ONCE(report_fault_once, state);
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121163943.9889-6-vincenzo.frascino%40arm.com.
