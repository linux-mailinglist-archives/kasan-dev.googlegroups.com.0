Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGV2VOAAMGQEQXGHGNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CAC9A3004F1
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:11:39 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id 138sf585444vky.13
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:11:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324698; cv=pass;
        d=google.com; s=arc-20160816;
        b=GCGPKNwSwYwCscb4Ob/lc9SHgDsFs4CASqOPZC7+WJg/IQYyOHw2o1pQTKLsIgeIq6
         4qk/38zWqYbkXnvpuNgnn7Ew8puwnNk39F+3BYXsaZj8xemmfB+MLdXi1wBaLDBKduEy
         UZwFHEz6pNvc9ia1wTGGZ2lVkyjbMn9wNs+fhB/T4k/IThh+Lyjm+ghaYqdCPbh6S5Up
         My51CGLxk8Fy+oxVXdKataRwNBNKJctxH68f3KvU5wJ/KGS/T1DEPkmYJKmIyHy78H59
         GM8SnyQwVlGAZwQC6iKexZgRrrZbxzjA7XeYBXFl0PqUDQ5Mn0CBssKXfx+o+lV+fuRh
         vqZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q6gKNKF43PyQROA3LpbJ7HRkj2qnQ3+uM7cICAzzHl0=;
        b=RlYHPvsjUZYCxspoBNYf0/D04vml3z17vRdnTdTjsGCRIbB0k2IBd8K+mOE6h91q0m
         4r57hbW6IqHZLdhoxrNg4vQPtb1uIur7/yJu1bgRZObadzabg86NIc/k2W3AonGZ8ZYt
         7rZxGTUk8+6jMsZnjRxmctGu6ck5nfPYJ7n0bXxhpsMZ/0HN6yINQIQB/zZCI4TxTGSF
         PwH846J48TQUlSHO6brJiY3FpUaHwOF/GBeiqNrbzqlVufoq02TPSDpfuJT1RDQl3Xcm
         k6tPZ/gVlGQJ0DuaLoZMGQBKhhkxI3XqT885bW7lflcgMpwCIE9F8q4woPnTFP2sDRLt
         MTYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q6gKNKF43PyQROA3LpbJ7HRkj2qnQ3+uM7cICAzzHl0=;
        b=euDGWAVa/gIpckTJTQ474fN2UJaNzIoc3UcfHVOK5WqduU2Z2CJ2QgztCcNJhfY0y5
         0B93FaOs3Kpnzw+xVFNzXHTv8IJJZ9Aw442KAPo7YAASH7nRgUsXkIw7ptFTmsEsCKEl
         I4bj8SMFUbPt0WnY8WrkIjt9HJbFZczkWCrZlCpE4EY3czEsHmGTmXuDHDn5+0EqNgnQ
         pQdxYqU/IRw4qo6nSlwlpx+CrE0CIaInYppx34hbc5KEeVj3T3+iG3tB9DxzTM7rr6oQ
         ijqkC9mxDTWOYXCXcicB8jMt9+M55y8pUe5XdyV6BLVg4k/BaOU1uAf4f3LhyCi+DAwo
         7I+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q6gKNKF43PyQROA3LpbJ7HRkj2qnQ3+uM7cICAzzHl0=;
        b=pbk/GUFAmKWBXMRTw8Asi7xxfwmNyfytxJ0lzfgV34FcYM1v8hetCI4yj3nrNAJ9Yb
         mH1Y2agLSJsLI3+BBiW8aypjaVUXEi8JFhhXQZyxwmt5ymRt1QpcbaAQ7lD2E1CThC77
         wTKnK4HcHRWRJPa0Bi39PH9cvJr6X9jj93fFzEO2eL5FWLvdm6eXHXTljdB4qmGahhIa
         5XcAlqP7YNOi/UsyW+u/CuheOydvqrVtO8P4MOnT22h3xYNKJ/tQNG6DJSEM9UcBn8S6
         EInsM+oQk92q4Q/xPrhiLTjLaKeE91pHcHWUUsHMIknunoPS/rWrKLzuoe/U68azjQ+d
         NshA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QjVsFtJ2DVYQMUcTKsujj1PwtO/pUqozAHcLRGsrmjAzu2csg
	MtfeC+RSoJO7Sef4eg7kiyY=
X-Google-Smtp-Source: ABdhPJxqNi92pp6QGPHktoIRCswFoH0x2A817zp6PZvxY6IScZtFEMR+XcioytgZyzE5WMQnXDp56g==
X-Received: by 2002:a9f:364c:: with SMTP id s12mr1065839uad.19.1611324698754;
        Fri, 22 Jan 2021 06:11:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8d45:: with SMTP id p66ls780313vsd.11.gmail; Fri, 22 Jan
 2021 06:11:38 -0800 (PST)
X-Received: by 2002:a67:fb52:: with SMTP id e18mr1074872vsr.40.1611324698258;
        Fri, 22 Jan 2021 06:11:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324698; cv=none;
        d=google.com; s=arc-20160816;
        b=mxbwczv3PLTa1GBmAdKAQ470KiOUXCD2vufqrR8bCXylncH7IDn0FtMTnOJYYPYvDq
         nIaghmEnjJDFUFErs3HhPXN6CmTUSVnL984MHgq1+mkGaiHagrF1dfNbekUWJsQ9yVKv
         kKABwQ0fo22x5esqEnn3hkYygCuRlIDgOHOjeWcL49bDzyqaa857rhcivR4ojq9vWKnX
         nwi4PNxYfmWb5jc5EPy0km6OhwxAtU+kZzfC5tmFJZhqZezJ7QwdQJUDwx/Fku4bcq5o
         dv4WhDCdGvpb5xs+W/tQQSCpgj8HA0ec/71flbtjxJstgN18tM32+7ogWrJqYGJ2MwT4
         Z82g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=gyVtDtDgH5mdykZqagOMclEBwdx69UTG9puaUbhvtxU=;
        b=c5oO3Sk6sXEqBxtdmmeFLblVzhSDKhvVk2r0DiVkBILNo1FtSEUEZ3vFOKcqSwoBb4
         rYFbdeGIopPGF50z3wnHLt0/7G2SUE9JL8C4C8A98h+qfXtgWGfDjHNoR3k6VYIA5ghT
         NgclqV4fdtSBnhtNSDgCo7o0ccZLCaybL8IykNbNjwhWgrWt8MCOfd0K+BNg3AvBcc7Y
         xUB6MbVHtcy/JDKIWZ33q11rJblBhPCfvSGEiHkV02fP0P97BqiG/weQ1b4T5qrCFlC0
         ZAi2/drvb3gqE3y1Hn+G4G68THlInk8xTFsCcQehdZgBrCjzT9oK+LKxP5dfclwl7UqX
         PhhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d25si359589vsk.2.2021.01.22.06.11.38
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:11:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 701DD139F;
	Fri, 22 Jan 2021 06:11:37 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C33203F66E;
	Fri, 22 Jan 2021 06:11:35 -0800 (PST)
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
Subject: [PATCH v7 1/4] arm64: mte: Add asynchronous mode support
Date: Fri, 22 Jan 2021 14:11:22 +0000
Message-Id: <20210122141125.36166-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122141125.36166-1-vincenzo.frascino@arm.com>
References: <20210122141125.36166-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122141125.36166-2-vincenzo.frascino%40arm.com.
