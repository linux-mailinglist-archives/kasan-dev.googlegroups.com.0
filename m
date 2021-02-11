Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB4M4SWAQMGQEXBAELGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id CD52F318EB2
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:34:10 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id b62sf1603570vkh.19
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:34:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613057649; cv=pass;
        d=google.com; s=arc-20160816;
        b=ceOrpN7eoqC5aHhyNtllUjH4Brw5wowP21m9YHztVWlQyV2DGuN5Fk8dcpf86dqjhh
         UroGK+ztXGKVSOtxpiyqVmyO394YYH/efA7ZaFh/HWED1CHO3joLNx0PkJv2iVkg5ms8
         VFMaehNXA0QBNG6Qd85p7MKZ/6rD40+3im9su0YR8jytieYEK6bJo7tsI0CKESUmwKf9
         sAlgFf67AieGF8j/AYkYU0r2p91S9d0Qk6qfSPHW6DP/ej7879w0IUuaBf8ndBn3jWRu
         NofxZLFHBGygpTJ4JwS6cr2f9A5W+WgpF9J5mDHdobvZCojkIT2JUY2kerwZs/YhhIu9
         u6oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JuUW6Q2WhrMODlRck6/hkRbVaZO3Jy64QdN4tCPPwX0=;
        b=UHi3RZSA4K9nDpIuy7eQDoHTZe5WF+rYJi9rJBEtK0ZGb7O2Bs6ZAcpqHNuYz9Oqy5
         MuA7QjryuQMWY5XGFzx4BO1zHjFQh4s5WedsmiBc2d1sQhQq6u3Lrt3v5F+ZdOT/0Q1z
         OtCHkzCfb/rGotuW4iup1xYghBI//EfMGdLkyvT57i1tyikBu+cgvlANS4oRhhzGqkIE
         mYV7WNe47AZ0UjMsvH8UVajTjVM1QXYhzMTgdzEHkYzQjEXwQ3zuvWi+HXuGOfHdb4pF
         7cm6ickEuG8Fm4tibFUh5c7WvvofkDIDhsgicUYRLYVpPLKT4vo0xOj1efDLz9pivjIq
         ftQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JuUW6Q2WhrMODlRck6/hkRbVaZO3Jy64QdN4tCPPwX0=;
        b=aQhmIhNjDZrIHZXD/arDcJNBtoPZ2J1vOv7U80B0ot75QXCibkaDdFh9FsOZ0Io5Mu
         shGH7vQKdKgvX5pVu2XO7E22DwRHM9hhCSsumtmyheweWJuMcqsWkdVPt7VhEqAB8Wsw
         QGKUvJgt7nEoH5BFUm8V9+s++PMt5ddGJ1YG0PXzQ1mFbtk/ZfdZtvUtga0DXJbnYiyG
         xpxrXm78Hg/VFyNeEzf1t9OC/BHAXmdMUixMYfHGyWwW03JOTfuDNKnCQmfEdMhlyaaf
         mCxnI0dg9OQZbPBx3Dx2q3+Q+ekZo7rlvMRleV/FQEXEPzBdfkHq9YN//lcPl5gYqVjV
         AT4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JuUW6Q2WhrMODlRck6/hkRbVaZO3Jy64QdN4tCPPwX0=;
        b=M1Z69GSQ+yVbkDG5uisbS2gH2DTKxb6lDOquJzt27a1QA7hRX0H64t6b8Kk3WohVUQ
         E3dE7JbWcOMVSHaY/xj1yt0twDaZy00ePzpJ32Eg+uHjkhVBDfT8nSHpxpWqebptOLPc
         yqEsN6Ej9cETUOh1z0GBLDXIxRSf5jXhbJb9P2Scz9Sx4IwPFp7jqEOF8ykhjuRCwynK
         HyuJQMiCulh1Kl8dvv8je2piG9AXmckHsXmuAu4zISawhYudqTeQLl6IilkjuH4ka95S
         j4hFBnaRVsiOo1hyrWZsPnLyULoK95PYVEtcZks5UgePgM9dXCBx/4yWXAdCCzJR+XLs
         G+3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OU4Sz4SQFGF5j13UqhX1XJ7RjOwz9WUlEnd4ldiOZmvLneXVS
	vDVQQc4NE2ZoCt9l+ZlFtUU=
X-Google-Smtp-Source: ABdhPJzYx0Uub9h2EVxsHNUZLwd1ygNO7q93m7BJhW1Y3bzYS1BxdrHgHUZ6rh6BcNe3MGq9dDqjVQ==
X-Received: by 2002:a67:c992:: with SMTP id y18mr5869769vsk.7.1613057649729;
        Thu, 11 Feb 2021 07:34:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6182:: with SMTP id h2ls426142uan.1.gmail; Thu, 11 Feb
 2021 07:34:09 -0800 (PST)
X-Received: by 2002:ab0:2bc3:: with SMTP id s3mr5460647uar.74.1613057649344;
        Thu, 11 Feb 2021 07:34:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613057649; cv=none;
        d=google.com; s=arc-20160816;
        b=P/8UhMPNZZmD9qJTcTGtoERIBZw+Aill73ynUW+P4tk4nP/gHujB6qSFRtLSCqHEP1
         luZM3kpQJ7fgc9dX4toHf86yEqPuj8f+k0QIcMgd6eFk8EJyJ6yilVGnIDeri8ukAmfz
         124D+/TwQe3ifccpKO0PoM/nX/8xGKLRwxg3N2G1ZoBwyc6p6/TeFJiSLn9WKE9FvAMp
         xGv497qrpXbVC/mIJO7ZsWu9CSEp/3KFVjmDCuMYRJ/CvXj0POFPIcbU9cE3fm1BzBkN
         T9rK/rUi4ZteJ+Iu7E2bTw92LO6uskPN0W5eC2CveR2h6V9rQs35I5zjWIRZnjnFhmIu
         0J/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=oolWmrpVYPySsTT4nJoi1MYKxRgFPOly5i4Sg9gcoMg=;
        b=r8gybniez7ujQwiiwrnNcoox2/Yl1Z7Okphh+ItnoBs2AazmJHoYeQgleFbRtYL70m
         6m/VIP8fsKkLEtqOSsFx9BCFeenCvNOMSXqnDus3RBUI4SE2W83FGk/sJGcNJPs2f76W
         JMq0KEcrW3qBoklso/FUzaSe00mymO7523Cc3p5KLcGOjE4yf0ieZc53+6ObxJhGFH1O
         DuNVGLhtanZwhoKTOGqtmyv1A2F6AUPqQdWk9bcxsZYNXLDj38oAN2rUr27WCaQ7Q4P2
         kBflsdyQmvl9T4/8VGg0ceMSckXJv4XALOSfjj9ffENMfe6NRBmMLoNTnOd1P4Zlp3AD
         hFZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p12si279481vkf.2.2021.02.11.07.34.09
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:34:09 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9B5F111B3;
	Thu, 11 Feb 2021 07:34:08 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B620D3F73D;
	Thu, 11 Feb 2021 07:34:06 -0800 (PST)
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
Subject: [PATCH v13 1/7] arm64: mte: Add asynchronous mode support
Date: Thu, 11 Feb 2021 15:33:47 +0000
Message-Id: <20210211153353.29094-2-vincenzo.frascino@arm.com>
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
 arch/arm64/kernel/mte.c            | 19 ++++++++++++++++---
 3 files changed, 25 insertions(+), 6 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index c759faf7a1ff..91515383d763 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -243,7 +243,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
+#define arch_enable_tagging_async()		mte_enable_kernel_async()
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
index a66c2806fc4d..706b7ab75f31 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -107,13 +107,26 @@ void mte_init_tags(u64 max_tag)
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
+EXPORT_SYMBOL_GPL(mte_enable_kernel_sync);
+
+void mte_enable_kernel_async(void)
+{
+	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
 }
-EXPORT_SYMBOL_GPL(mte_enable_kernel);
+EXPORT_SYMBOL_GPL(mte_enable_kernel_async);
 
 void mte_set_report_once(bool state)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211153353.29094-2-vincenzo.frascino%40arm.com.
