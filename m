Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBAU3TGBAMGQEYTD5J3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DFF8331319
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:14:59 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id r18sf6311168pfc.17
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:14:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220098; cv=pass;
        d=google.com; s=arc-20160816;
        b=zzYMSFyzLCLcn3pl7KOQH0vfZ3JMQ4ID5BCEsgvL1kJQMtFDcc8dw9zc8RSNGcSJF7
         5TFiqLJKMMk9DUwM15omcHxJzbo0FSeMMntIqlACckY7CTBTlKEDvffqeOoe57GRFdma
         W75hMPxIC96GlIs/srt+r1BOdYs6PDCQakkS00xJd+gfRDz9Eb2lcSnt6HSmlrziN/yw
         PcA/uDAE+hcpihLf2KzwyKe51JwXA6eBUKlTo1osE3Du/BHYPYyBDfwAxXZrQD+GEG1v
         ux3+NWp0Y1vKAP1eHERHUKJaNJuumbnYLQNWUaqEfR8WzuJk4MZ92AZ3kH8WX6UC9XSB
         b0uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UMYjfOc1l/L0jQ9RG8rgNRGEl7XnFALdpeBeH9xMtCI=;
        b=RKjhXDbf3cQ3vwvr6P7pdeQ0IcnbIkPU794EURC1p6mZv2aHMXBsF4KaCP4vjZiWVR
         yoGtRrXmZOQMvYcZtgUS6zAsWKdCcDPz0iL/oSjsvoAZjJmUnmtOUx1QajCFduClSteh
         sUYfbOlUOVPL8yXR35SyOT/VNzQMdBgk31z7sMzPlwrGBgJNnk37BIr23d232KbTXc6K
         nstm4tRcwj1t9z8y3U6iQVDiGTRevVGe1c2Qzvue864oHTBqrCwI1BiStPV9Lfm01dHh
         UIiJLBCaZX6wHhdbksjM0vBy46BZmodpy1ldVJXju7OFphtc3ZF0qi43yu9Z8gjTqUaS
         3iUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UMYjfOc1l/L0jQ9RG8rgNRGEl7XnFALdpeBeH9xMtCI=;
        b=sHUeM7w+BsluxnLiubkczNK9BWpaEDYZBDY6xytox+E2bR2HPdwvGqRuWBttewLU6+
         ca1HwG73FW4IDm+fyy+rAjMFgnmrqoOU/ktmMuCQ4TTaXBJu+hzc9KQ1OiQpN6kMCIj1
         CoZ9OLkNLqL28Fv+4X9A761P0h8/foW7wZCpI/l8fWjdgMOMLBxjRWNTeh3HODgPPuwR
         BCBQ1GWiZ7+/+GNmhdOJDggnklXBbDgrhs05rYX8fI75UIswBCY7aDEFIHP84vcYR3ZD
         eK/4Gc35Okis2adlPWv41hCWVHR++vT8oYNoBFnAWrdogOEe7N4nmXOnoVQ2jWbMRrZo
         QDFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UMYjfOc1l/L0jQ9RG8rgNRGEl7XnFALdpeBeH9xMtCI=;
        b=UuMwp5tPK3uLK/X7zb0p8VBS9UzNYFnBpS3CbFy4ghf65E+uEKCr7x15604hcJvh3e
         Yqdf9xJhSnwuRsMpWkXSywCCqydFnvdiTpi5Bqj75dIe2pKK8kKCuf1OZ19ZNb2wN6HP
         otMDd7J628FMf7JTBIkWAMeL63cnwBb97z9nWp3fUPa3EiSGafPCJRvNR7wz8iFAY/IM
         sA80ciVNVNeESoEGn0rmKCRV/wSVAlNjlyatYAWfnruqsXfhqif6L6++h5+1PO4a/fud
         Ym8fYpIngIiYoaajgD5wK272AwQ5/vb55bRhqE7z1nzin26yv+Usk+N7ZdB55FSHyTCV
         q5TA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jXfRobcDHhfYEhdOe8EGtOXlSe5ijsLg/OnrRdEdzNXw8JO8d
	2qvvpbxcB5+hxw2m73SUkyw=
X-Google-Smtp-Source: ABdhPJxeAoeKUN/kX8YgUDYQ+SlmHr0PoXAQpLsMKQ/B4QSJ6c34sGspQ/9UCEU4UCQuWkHz4Q5f6w==
X-Received: by 2002:a17:902:8204:b029:e3:b425:762e with SMTP id x4-20020a1709028204b02900e3b425762emr21915613pln.13.1615220098170;
        Mon, 08 Mar 2021 08:14:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d43:: with SMTP id j3ls6930971pgt.1.gmail; Mon, 08 Mar
 2021 08:14:57 -0800 (PST)
X-Received: by 2002:a62:2e83:0:b029:1db:8bd9:b8ad with SMTP id u125-20020a622e830000b02901db8bd9b8admr22124448pfu.74.1615220097641;
        Mon, 08 Mar 2021 08:14:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220097; cv=none;
        d=google.com; s=arc-20160816;
        b=ex4s+7zHjTqr44e4m8vsqg9BxD81+dNEi7NCt3QxEfVJn/quSGwKoly4DUYv3iS+yM
         XitsgCoBglxu3BoZHLKMMESr8xNYSklZygrexfula9IR315afhdXdkiX8nqMmBENi0eD
         Z5YtSBjFcl9tZDwpdu8np9YTkBDGIcCCykcVJIfXNy52ty8xzRe6teQrY6e7CpRsVnpY
         zUctIeqYRjFOaznn2r14NggzUmjJ5/0pcnGS818RFQM3EeS2RIhyIUlN/a9XPdhvUIjh
         F0HyXwjbpwirwksyl7dtj5O/v7tucvoHFRbXEWLgZulI0Dy09ta23shj1DukWFmw935w
         P5QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=nbPgiFIBeKcwk5nAlgWiXTf2rhVIdyYLOtp0ptC2UYs=;
        b=ViONdmpCcyEnezWNtQXgMLcTDYK3YIfNP1M5dVNICIMyZWV3Y19ZGaul/76xeWBKcv
         dfpf1z5AMhht8j+pRjJmrf68iSfN4WCmrGlc9snSZYBEqbbfvEgMNVkq30RI/Ssy17nD
         uUfjNK94rqUA7R8wqKIDuMso1Fweaghobv3KFdAMJoezrMAjRdMn4FUQHXrMZT7kt1SJ
         6VN+qVFfzKt/M67jFRgM37K6i96usJAfox2RsUW/NVKP8IKqu0uWSpj+scvCkdBCYwKi
         JrGxjXridqmCWGLuGB7GW4w2EYCDScFJd95s3PWYQpibZAMbQUfh2AT9+xBW/p/FfzfP
         4TgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c3si367964plo.1.2021.03.08.08.14.57
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:14:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EDD9E1042;
	Mon,  8 Mar 2021 08:14:56 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 176893F73C;
	Mon,  8 Mar 2021 08:14:54 -0800 (PST)
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
Subject: [PATCH v14 1/8] arm64: mte: Add asynchronous mode support
Date: Mon,  8 Mar 2021 16:14:27 +0000
Message-Id: <20210308161434.33424-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
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
index c759faf7a1ff..076b913caa65 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-2-vincenzo.frascino%40arm.com.
