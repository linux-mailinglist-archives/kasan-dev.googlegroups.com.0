Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFHORT6QKGQELIMHVDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DE0F2A7129
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:49 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id v5sf52058wrr.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531989; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZmN4jmn3V50/GxCJ1D7FgVm3qaSJDYCO3D1qXmRVepR7KFzb/KXJ5SMXvQMS/V3R7u
         a6p/Jrr+x5SPwfaJ6sKcHoewUvuLcw14jcrx/q841hou20kBTuobQgL1697kyLOPk/Da
         mIZUNJz3NJu3V0g5ruAHXSSfW0aJ6NgKBJG/foSvgfOuq8ORsWbnvdZKR9pfkRZg8r1N
         ZWYNs5e9SZRLlFQ55JKfxUJTG73ZDhaeHDup0nCyZdlchhMqPjQeAk4fOIXQbxBZvRXB
         HXOsZodp9JJ77l1A0Yqycz3rh/4QVetph2Yau7JgPOIoSEnUi1wRc85AU1ogqOZK5F1d
         7s2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fbhHIgoh1v3qHKfWy6Fa/oyaNAcScBP1Ar1M6EXC9XE=;
        b=eBYHJAq/vaqWG5ZUGSu/npNl3+qVVNa0iDDNDqGakpx9njsAnFT27aStEgMhOLLkPS
         0Y9nc34NT+m98x2P9TPDMN2sR9iZL23gqpqLqm2oQB+W7TVwh1JaswA6X3mJfOTKE1rx
         4EP9D7ibyrmzn6t4GxRHuK5mBzTtRga8+6x2rwTK+jy1gnXggYvXtRKbKlRL+cb4W9E8
         FVNsq9hwCkObJTE5Ea74DVMNeS0uS5epTDaCJm+WnefQy5ZgdUIrvSFOMJkywVN2oBIP
         eAEbA4i39Jq4grEDK830KLVHiPQlAvsOvxAt6Cq1N9ZIcmCQuVdFzeiQ5aJ6w7t7xAme
         daWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wU1V8lsO;
       spf=pass (google.com: domain of 3ezejxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3EzejXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fbhHIgoh1v3qHKfWy6Fa/oyaNAcScBP1Ar1M6EXC9XE=;
        b=NzHdfzdbwoQhmrNqiWKEQ9IT09OdWhsdvQV+75u4EQwUfZZkWLPpl2x1CPy25gCJ50
         Ig+xXnHRV63NMBRgkqIoBtVUL12D9/6MVhxjyvehilpBJwMf8ZJVsaZAj6x5cNJBPBKB
         ES/01FuGP9ngNWKdwmQikO+4ujbYP9U7LQGqMWgk6rFT4gvdr+/Gy3OiRoFah3CRRIqt
         D/HRXeNJiotNP9WOhOPaEgWtstcOkjwaDQvTt1ioyXXOwzE1a7V+Us1BpiWvqKg+/iYn
         gm1ptWQxu3FZbXBHXsxAJrXVx+4YgxEA0spKovOY3lcnDnv2jqLpw73R2cFUGeRxTbHT
         rUYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fbhHIgoh1v3qHKfWy6Fa/oyaNAcScBP1Ar1M6EXC9XE=;
        b=loULEw+RtALUSKpCrvIzJ9s3rvsVEZpqejuEOmsG9o7NWIJYru0geX+IKVooX1I7oI
         bPI04qyQahigBHJYE0DZOSUSwTYR5907M6usn2owVlY80/rF2TMg5ob9Nbv+Um6xUkUG
         Za1WtSuigTeoYBVl55WBVPWXnoRG5Fsq6FMmp6qkQjjcybkN5twjX/lbsCZthd0Nur/M
         IKYur9z2Eym1RD7UcDf7aNprdFt+IguD3dQ892ZX5339zgcNLqdtb1ru88GrWBBj5QtP
         9i738y9MqnI0aI2mrmHRmIjItAQWj1hCqc8xJE2ZLbemHMP+Y6VEdZPiXRPkGgmoR4xd
         kaBw==
X-Gm-Message-State: AOAM5325HReoW2asIlLvbbVB/kGhWDUcNyyEwKTyzxC0sTdT6UcPP4Do
	ZOJ8a52cFF30lM5iAXYKFuI=
X-Google-Smtp-Source: ABdhPJzUtENpxFOXTCyOBnVdnqdlRuZuKzk9Jx9HacnHWwQ1q3eQCpdWTICgfBU4+d23UG+rLjeKVA==
X-Received: by 2002:a1c:e3d4:: with SMTP id a203mr38171wmh.177.1604531989014;
        Wed, 04 Nov 2020 15:19:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2348:: with SMTP id j69ls1889405wmj.0.gmail; Wed, 04 Nov
 2020 15:19:48 -0800 (PST)
X-Received: by 2002:a7b:c14f:: with SMTP id z15mr83209wmi.174.1604531988186;
        Wed, 04 Nov 2020 15:19:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531988; cv=none;
        d=google.com; s=arc-20160816;
        b=G9D3KQvepyzNPf9cqDXSRMxzq9F2afym0LTo+8R564cOuKZiNVSQGn5rm37IIv+7cE
         77bL3lSLJ2Jed/IOXehWzhfPW4gT4bYFRZDBRJIcnDu/aCBRZTpXzdQxBpypsIgM8xgr
         LIRJcsv3T2sHQZsfnpZr0VsDeNkG1RRNdJZJIPsGLJElc2loha1lF46zjeXc3PX8OcLo
         Ki0Euu/dwc1nlZPdlI7LXt8dbaSRKRwlt5lNG5yRnHRclYylmhT8j3fdfwxoVfdVNbhf
         Nx5gNz5A6mhpdBl2U/TGrOwpFnpIEL6+109Vk/AcGsXHSoTEYXFx8mG6X4o2nmJDd7IO
         5Ayg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NNpPR5seN/69hYJxiJpAYFp3W8/rjpHZNnZx8Fjl6mI=;
        b=rLfeBmAONAvS4Z26VAfrEXMDdtDYRvdN2DEV1uh1X7iApyB9fBfNO9S5E3ppQGSb3Z
         VBW7VthhJxUOadG5XXkoMe/LoUBwVtnGRposzp4PAQMPiilHSsCRGohKS59o/d7Xe6CR
         CJrBO6kkSO+gfSNlijIPn/Pa7jrLNfKtJ3BkoGA2RHvOS8srDr03xF5DHo3AMZ8DPLl4
         1Tu3E33KYRhebUT9JL+yKf60R5JrgJ8LzR5BrPexgsAcRkucJzJ9ppgvXXXNGywIraDc
         /ttFd+Z4AZq4zJs5ZxXh3cYa5GDKjrDMDgAHBy3PwnIre2v5NGXqJTBt4O2Z6GODtGHC
         rAzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wU1V8lsO;
       spf=pass (google.com: domain of 3ezejxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3EzejXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id e5si143380wrj.3.2020.11.04.15.19.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ezejxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id t14so50257wrs.2
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:48 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6405:: with SMTP id
 y5mr82984wmb.150.1604531987731; Wed, 04 Nov 2020 15:19:47 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:32 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <eb6ecc9ca7d4dfa653fce0012bd1651e157638e8.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 17/43] kasan, arm64: move initialization message
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wU1V8lsO;       spf=pass
 (google.com: domain of 3ezejxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3EzejXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Software tag-based KASAN mode is fully initialized with kasan_init_tags(),
while the generic mode only requires kasan_init(). Move the
initialization message for tag-based mode into kasan_init_tags().

Also fix pr_fmt() usage for KASAN code: generic.c doesn't need it as it
doesn't use any printing functions; tag-based mode should use "kasan:"
instead of KBUILD_MODNAME (which stands for file name).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: Iddca9764b30ff0fab1922f26ca9d4f39b6f22673
---
 arch/arm64/include/asm/kasan.h |  9 +++------
 arch/arm64/mm/kasan_init.c     | 13 +++++--------
 mm/kasan/generic.c             |  2 --
 mm/kasan/sw_tags.c             |  4 +++-
 4 files changed, 11 insertions(+), 17 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index f7ea70d02cab..0aaf9044cd6a 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -12,14 +12,10 @@
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
 
-#ifdef CONFIG_KASAN
-void kasan_init(void);
-#else
-static inline void kasan_init(void) { }
-#endif
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
+void kasan_init(void);
+
 /*
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
  * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresses,
@@ -43,6 +39,7 @@ void kasan_copy_shadow(pgd_t *pgdir);
 asmlinkage void kasan_early_init(void);
 
 #else
+static inline void kasan_init(void) { }
 static inline void kasan_copy_shadow(pgd_t *pgdir) { }
 #endif
 
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 5172799f831f..e35ce04beed1 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -278,17 +278,14 @@ static void __init kasan_init_depth(void)
 	init_task.kasan_depth = 0;
 }
 
-#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
-
-static inline void __init kasan_init_shadow(void) { }
-
-static inline void __init kasan_init_depth(void) { }
-
-#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-
 void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
+#if defined(CONFIG_KASAN_GENERIC)
+	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
 	pr_info("KernelAddressSanitizer initialized\n");
+#endif
 }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index e1af3b6c53b8..adb254df1b1d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -9,8 +9,6 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b2638c2cd58a..d25f8641b7cd 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -6,7 +6,7 @@
  * Author: Andrey Konovalov <andreyknvl@google.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+#define pr_fmt(fmt) "kasan: " fmt
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
@@ -41,6 +41,8 @@ void kasan_init_tags(void)
 
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
+
+	pr_info("KernelAddressSanitizer initialized\n");
 }
 
 /*
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eb6ecc9ca7d4dfa653fce0012bd1651e157638e8.1604531793.git.andreyknvl%40google.com.
