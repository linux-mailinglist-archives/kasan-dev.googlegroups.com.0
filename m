Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLVR2GAAMGQEKQ6BBYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7196E308CBB
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:49:20 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id s17sf7109275pgv.14
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:49:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611946159; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mh3LZOBf5ZFychTtlRrv+3BudwDykx0mgqB5YxdU/J8O3nKzw4Xcs7OqmrL2tyymQ1
         VYqXZlMAg/s7vOP/8foX9BlVb5v5O/vIHz4zL99+R3E8g+FlBO8r8+GCb1yFSsGMeRr4
         BTNhCYbh33aoR3t0e96ZRbspNrWvX8JUmK0oWEnwFeyhhV4RUrDD0QnPV3eQKrXkNern
         8vTHLjTaxzLNUxhq4ZiUX+3AE+dZdJn2fpAWcTlawnxsFmUN9WD2F8VGF8qN9W+H66bc
         0oJOy2EDO2YWZw8j7ZOuZRlY6PAx0Ow+QEFa5mXHu4CbaYOQCKbF3rSfAP84aho+J5hl
         Cpcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=whrdtaEiBB0k7bBx37lGq7g0FaKRmgZvgvaM4IVgpIo=;
        b=b2oPdv5qrsqeG+4czYgmer0A+gAqo4M5ZuFrMEzmuG437y+AhOxt3I3BkiDKpYASsX
         mdcMkQ+LbIeX2I2H/NL5HZkZpnU68/+Vq8/bfGsdMXX8LELgfKt43mZWir1sC/TDAfXj
         C7pFdnCLjJjbhYy2RPJUy6WELZZWnKB8aaxKHPL55BE6qg3pkaykqNHj3jtFD613zuS/
         n/wNVYzXbKhhm64tu61COm5Aubhyt4AVsyICeAh/a0xGHp5jmUdC0XawMP5WA51PcYOq
         Je9QfX4wUGSzhc6XxBPWlrn5dxv9hqXhnp/HodiyJ63PxJhX6c8su9raWj60tYZpu1y8
         cp8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=whrdtaEiBB0k7bBx37lGq7g0FaKRmgZvgvaM4IVgpIo=;
        b=MC/QosijFb2yT+fh2q50kUCEBPSVWfKDzLwEJ8pGityTYOIR3YbdhUr1CBVp4k1Dl1
         YIvS+m4JWIilf8VQCNQOlQLUlg8Y53M56+ePOyCtQgivguSC7NenwQ6/4uwLDc1hV+u7
         eVJqU+WkVVuZPm2wtn1YYTeDWTlPpvaU3icJXQNDJNcPROKwXcVxL7vTqMJaIVR2u08m
         ZLq6urugCCnOcgu4DcYYTV0L2ax2DUJZti7ozwS/TlHMS3mxgT/gYymj6gE4CEO6A2Dz
         yigs1aNRxXFNVLNODafWo+SkBD7yEHzrLzwj6t4Hrirzgga3nRYRrE3aDpyk9o+8UdWz
         98rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=whrdtaEiBB0k7bBx37lGq7g0FaKRmgZvgvaM4IVgpIo=;
        b=XuXpUXK3Ju6+NzAMK/XoRGykQyhbUJntVsw6dH4q2UgMb6s2f4KYDS0UmmE49ftmml
         s6C/mhNAq47RbC67kOPfxXc4kZJrEiqn+UgFCq26eEKFEI/U2z9BHtZ+HFAV177n4969
         3cS2rGMkRGMqf09Z0YOVw1X8k8QblwbpWeM3GFiH9OYBP7pAjBHQFSLnbt++7wCl5nd4
         M2KJetPHKVOOGEL68KDlnYDUleE3tLJKkSfX3ajCrKHSQSf5T/YNl44j2IcPpVycM3oo
         L7xp4StP+ZRPQFNIr9snc0PIBPLKki6WZOhr0Dp5Jx9Aap4ZN3S0T/9NOgC0zAs41Hah
         Z1Jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kNejMR8tmuC3Nr/Mk42h6I9gwA1si1bW23XnUbenzV5eicJYQ
	JNalw57zdSVfvtpksZzEZ+E=
X-Google-Smtp-Source: ABdhPJzWqYJ8XB4Wxp9PA0/M9au9vCB2uIch0uJzkyLYOqo8pw1Ay1mpfWaY+6AoMg0pAU8u5F5NDQ==
X-Received: by 2002:a63:1f54:: with SMTP id q20mr6228376pgm.135.1611946158868;
        Fri, 29 Jan 2021 10:49:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ce54:: with SMTP id r20ls3950569pgi.2.gmail; Fri, 29 Jan
 2021 10:49:18 -0800 (PST)
X-Received: by 2002:aa7:978e:0:b029:1bd:f965:66dd with SMTP id o14-20020aa7978e0000b02901bdf96566ddmr5654731pfp.46.1611946158262;
        Fri, 29 Jan 2021 10:49:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611946158; cv=none;
        d=google.com; s=arc-20160816;
        b=GrOUyjP/MXca6I9e/GfK9N4OvK1krXjEHRrDckqnQn99E3C1AyhLTTkihtLEc63iKU
         tXIzxRifUhRbuI3eNXoGjsyYzh2WCJ8xhRaRHrD/TYLVNmbQRQPaublppI89U9rdNWqx
         m76a6cjik9w9vXiamUkNpheJI/fsDJ5W18PCkEB4EHeD/XDSDJkcJo2/wz68k3yNB/iv
         8M/zMHC9bZr1fb3fQuwvnI8D7pypLZQ+lWKIHikCFLJnA0iRHAPwGlA2m17opkMs2i4V
         8tkDXH/lfx1sM0IfXMte8kG1N8DwnEqWDdfn7T2aRWUYvXbG7SazF8FDZgCrXeXLQxyX
         Clug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=l6Fqqnxj2W22kFYsq2pf76Ftb0zDm0LC9ZaR0r0+xHY=;
        b=q1YiiD70QO0LF3uct1Xwy/K8u3tjbqo+m78fca/6CX8YFbvSmclmNGVXdvLB1BO202
         gG5U2VDfYvLHVfzK3WytuKmmEfXQvduOwdtCHb8S1fn7Kmgsi7pJ1xOJaSt4jyFyOK1+
         CSPxpDZVNyk0w0Na5kBjx5YQzhIFamxMBA2gej+1WQObYh0SVJSrtBUjVGPRLUkCOK6y
         bw+qfsqS8PC1u7UwS8Zwv7tDc/czBl/08v0lr5M2As2Xe0DE16JeVEWRBrnS01Fx4Tdf
         ibI/KZ8DX0uFphHn1WzPJ54Q/rD4WEsn1XOcF1QHLpqN0GUvhpfzHddr3O61nMH9FZTa
         18ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ci6si678713pjb.1.2021.01.29.10.49.18
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 10:49:18 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 519581424;
	Fri, 29 Jan 2021 10:49:17 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8A4893F885;
	Fri, 29 Jan 2021 10:49:15 -0800 (PST)
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
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v10 1/4] arm64: mte: Add asynchronous mode support
Date: Fri, 29 Jan 2021 18:49:02 +0000
Message-Id: <20210129184905.29760-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210129184905.29760-1-vincenzo.frascino@arm.com>
References: <20210129184905.29760-1-vincenzo.frascino@arm.com>
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
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  3 ++-
 arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
 arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
 3 files changed, 23 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 71a6e36cfe85..8ef409d4a18c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210129184905.29760-2-vincenzo.frascino%40arm.com.
