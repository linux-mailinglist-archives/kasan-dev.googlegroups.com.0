Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBAG7VOAAMGQEIZ25MQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id DE1E7300742
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:30:14 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id n18sf9283362ioo.10
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:30:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611329409; cv=pass;
        d=google.com; s=arc-20160816;
        b=PiN3XcLGPlleSq+bI7nNtIVE1TR+GBdfEGB5F8cXcaXbACpvSLlzlBQuABAdl60Ea4
         zQ8mOkblRPcPwsfd6SvLyVJ+AOGGZGM2eLxfhOxH01eN9l/QMmrrSsZLea7+ll6kFn3G
         5IfM6YsIuXaA1dj/jcsrUu8nIweQKD1OcSmuFBQRI+JIk2iwQvEUlPM2GIHNbUGf4HMR
         LMIawbtfeEEIQONpLo5F3iSyrg9tr/hk/cZHEiHztWVc/aM38TD/vp4kSJ5LMLCT3LR/
         nDMOnX74fzedYK8G9ec1doywOkMyi7/fJCf/IL1fzrfdh6BRt9jdN6fLQo8vzq8eA5xu
         rpZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GLt+FhrSCkGoXwuo/5/+V3XtfFGA9w9i5pgd10G16NQ=;
        b=JcktjExVeUiHcc7xq/sM3HQNpfQCmh8bOPk9pD53/uFBZSRHOWcxowEpNj238rj7MN
         qNDPZr2wcM8kL3gan8FIizJ++XYzpYP/Xk+a+J9p9V81ZEnvpbbfK7PIRO1pFLzY7d4E
         Z5cPTMSNgh/Sy87te/wh3/DJjLZy1NhcP8DUuz5PrswUds34W5wbngSUO1lCc5JvPVXA
         FlmsjCy5M7ZWAnoj+bmex6pBdUC6kqJp58jaUlFQUopVTagvc30JJoBDOscYEACaJ/IU
         uTgYrJ+JoA8UTXH2QzYS3YnbBXI9aWykAI4HLaK/4hU9tT1Iw6zQr2CsBC15UwBzzkYa
         dHLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GLt+FhrSCkGoXwuo/5/+V3XtfFGA9w9i5pgd10G16NQ=;
        b=H4J6T/CN+BfavUoTbKksdu2/LeAdNbuJu6mugbkZkt551RJFf36oskhBB20NXYaf3W
         fJCFtaVNnZioharFP/RHbSfsGMHiZ0RaOYRxA9gGK6PQevD3cPawm3Fo2ipsvqcXJ5Kg
         LrqIEZeRVpFVnJf+LDbqDT9CxlvAvkWv7HeDYCl7ez759SceBiRfRjZ7qMmyK0XHfi5V
         bQxvJyq+sPdlSMoDeHbsYm9AXAKCUWqan8UvdnxXPLksQpmQiD71ao3s2VJ+0SV/iXai
         kZ6LSYk3dTItQ7P44nw6KpbUBBjcWGbqAOfWTX8bS/2rQdC8i000vRnvabKI2bOa9iyx
         coBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GLt+FhrSCkGoXwuo/5/+V3XtfFGA9w9i5pgd10G16NQ=;
        b=mwr9mVuB0SSPNtOu+Rl04ssSkwaMwhQOooJHXyzsrwC7eUqE6BokWsC1gQo3f90pIo
         5HJrzymDJanlesSlCZeqV5Dzv5ScdMUtJz87n7L45NdNWahvXZYuqCeTpqDiQiibbxp9
         O+MGDh4p7ttt5Sm6mxtkUdFvFmQKb9sO5UIRBKk+dp6XR3q3IOX/nv7ghxKW+T3Hbv95
         oc4I/4hR38JdCgzWX/K39urmKRqfAUBGgRje15bC+bWe0ved9seEcrwqWTGI3QiPqpY6
         uPdBuk+MbNSo7ga6PCyQ4xbnkDgMfKgzR2mfp7XdDhTfPFOpF4uML4oVWBExfqx1LN+G
         zLOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328nIj3zPmftWx/IXEQhkOWMewwpSdAKUa5JfNSp63mE6tH6Hy0
	EloSuzRMhj9UeOoTOTQnFoc=
X-Google-Smtp-Source: ABdhPJx+l0mLkt3oFgPdts+Dt89LXIS6WFvnh+wTKOLizAeiarde2dvaPa2r6Q/0iV4V+bU8AEq+qA==
X-Received: by 2002:a92:510:: with SMTP id q16mr811825ile.136.1611329408895;
        Fri, 22 Jan 2021 07:30:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9ed0:: with SMTP id a16ls859368ioe.5.gmail; Fri, 22 Jan
 2021 07:30:08 -0800 (PST)
X-Received: by 2002:a5e:8d03:: with SMTP id m3mr3955173ioj.130.1611329408494;
        Fri, 22 Jan 2021 07:30:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611329408; cv=none;
        d=google.com; s=arc-20160816;
        b=P3JuuQ/b00ohk2RHvJJ+0wnjmbZ4MGYTxtsuee9pgAJ5cgg0e9yzBPPXLBCsQ9rtTS
         UpAscc90dxMWed6lMV6CgkmCaY0JkPdwxUeY+cTa6m/PNd6dUMFb6LwR2ZtvPFF+k0eg
         nB+gxm53Fxx4u2p5XaKwtfDbo5sQkyKwXcgqbMq7L3qdgb+Ag19SIRgjpt0LpVINIo75
         sX1FeHp8l7TMNQlk+cIISIRXeEVQFzheQ8Y6rTJHSbfyaT4AKPLVm8whveWATWisxZLx
         yrgt19DyeYVbZOBdX6LNfVcjoxAC38ixD506YafxwoXM5GYeX1qXh8v5OSO20i4bZAvt
         WkdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=gyVtDtDgH5mdykZqagOMclEBwdx69UTG9puaUbhvtxU=;
        b=vV5vI0VbOoitwP6oHb2eTXcgB5tMQegXq1Jti6Bh1xxyhoPnRWFCl/bxozGIgrsigP
         uwzahR9aXyDQHNfRIBfugpB2Q2OA1lBBrNr49Arh4XST7DyNxV9l1i4LmpMfMym+eelJ
         gxPFtSsSlOPEM+wukZat5+X3+Y7apjBFYWmxTCdcEz+z7EaGuPqY/RkpzOJMa5Vs1J6o
         diPmNQyNOZcLoRLZnGIcrFfZZEzfWeDXDiZ7ho2zCoeYq+q/MXAUfGErxmVGTtJCRrrv
         swjvJB0teo6isFt7w7XCXdkjEQgAB/WMQAq3zmxLekhutrZHMlcCxMYSzlyp232UQa39
         jCaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y6si54962ill.1.2021.01.22.07.30.08
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:30:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BD5AB1509;
	Fri, 22 Jan 2021 07:30:07 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 10C073F66E;
	Fri, 22 Jan 2021 07:30:05 -0800 (PST)
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
Subject: [PATCH v8 1/4] arm64: mte: Add asynchronous mode support
Date: Fri, 22 Jan 2021 15:29:53 +0000
Message-Id: <20210122152956.9896-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122152956.9896-1-vincenzo.frascino@arm.com>
References: <20210122152956.9896-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122152956.9896-2-vincenzo.frascino%40arm.com.
