Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUMLXT6QKGQE2UHXSFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 983852B280A
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:49 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id t4sf5493307edv.7
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305809; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wt8iDHsuo3xC6k0GOq6tvMOlvnD9LVs3VEhrGmaow/cdr+oWVNEZ4FktorL8ExJNuc
         NtGIlRY/Q6EaubahaNOdQKawoFpWg3vFGksrJYJB2KIacZsvqjphYBC9cfYF7/n3icQD
         cBU+JkOQSmqOZguSQwuWR99av1uEWQqfIJB5sOiez0VbvGFMurPYSR17VNkGBBv19ffx
         WenscgDbIIaBgvRSOeGWW1Qrz/7GFcdACROOSTwXm0FCmHV93P40ZRsE8fVou3K92Pd6
         Mm69ZLspFA+OmN3ZZzrX2Uosp+8GrBw1p4uWN9JNL4XhVdsjFhbYNSMQQiN5MsP0c9x9
         CbXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZAZnYRDk3AGjLxeSi3abBeTI1/e1XuTWIHGcgtvgJ5c=;
        b=CWNhJGUAE7gW0X5CHKMtfDpPtX2DBz9CgluZxR0UqNtbcyGnfHZD694xUz4Ds13epm
         idwgWOlNx3hdvOMEY5i5U3Q5UrViqzv/9Bh/ii/jLq7Cf+mMwDIiLkiWuKbkMfqgiimP
         kipefPWgGcEl5VzXFGXCZ5gv1s5K7xc8THHwMJ/UrvVlIGEE1+RIuUBR5PBLrEYFdY+d
         gE4Cfz6WXr+pRZybEd62U3e18i0QMgYxSSKRxh48UHenRD0/t9SzQvFq0t1nAueXVduq
         mKP27O362+bOcNfS2MeSrLjOpEuiQH73Jf6Vn7s7XHuUkziXBMgCZOIzEPGEwFUuE1Rb
         pxvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jtDCsSAS;
       spf=pass (google.com: domain of 30awvxwokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30AWvXwoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZAZnYRDk3AGjLxeSi3abBeTI1/e1XuTWIHGcgtvgJ5c=;
        b=pmmhH3oAjTdUnykDPOQ0AVE6SJ1z4PgC8pnWO+WZ82nSuDAGDkYIstofisKF4RnSqW
         sKnYro1RhQhSHXLeou5OEnykmkZh7Rfy00k4Pk+lU0TquDKzq1A+iaZWywYQP2doQWQE
         SUa3LHnxpfyG9XzrMJVbR7ec4psVVI8UGiMXF0+K5UV7wz1PS/99aZ1EM4qK/vqb1v4b
         4zVLV/VCdZULiYCE3NxYikg0kp+xIi2iJHualnyZRxuujbbkH6PSx8je45Pu6UOdOx6K
         t/quCj6KLZyvBEEUuzE6/phwh/6fYSSeqvCsEPxzeobEZrkviD3WHM1X/9YYgsszClsQ
         v7xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZAZnYRDk3AGjLxeSi3abBeTI1/e1XuTWIHGcgtvgJ5c=;
        b=RYJZKChg/pLTtTCBuKO2gU1x2FWdyvqpIGJGn/yJntfkSwJCEAzPLvrk2evlPoZcWn
         +9klQGOpfOP6sHrB4TsJ6WOf55FzXz+p4cwTX8XAn7zh/eaEp/JjDZkSOHXSUdcPbnDa
         CjtXj2ad4YfqwF/E07LLVtCO3zYwDx7hwDqCGRmYNEG5KJiY6QRRvLVLOXOxvVzUVHlE
         3xqZMdIOglvpZS5BGKutjrJ6ye+OZ+4tJRxsJ9GczhaPF2rycw0w7oikRAuxMB3qOWyZ
         SQOMEApIlIAGT/kFc2iVIAHKvt8glRKWfQuYPUXz9ekB8kqMon8gz4Z5q2gReetv/I/l
         mPnA==
X-Gm-Message-State: AOAM532yn/WEdw1CInVA7qhXJYthcD/cX5teQuT0zSfn33xTdYUr1G/j
	eYyCCpYqVSdSgqkZqHDrhI0=
X-Google-Smtp-Source: ABdhPJzP0SZEDZbCfZRp9iferJyZCtmBxb6gltDzZoJlais+JxQf8efyfGheoTPWe1jqX7FO1KgyCw==
X-Received: by 2002:a17:906:19c3:: with SMTP id h3mr4147863ejd.395.1605305809373;
        Fri, 13 Nov 2020 14:16:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c050:: with SMTP id bm16ls442153ejb.6.gmail; Fri, 13
 Nov 2020 14:16:48 -0800 (PST)
X-Received: by 2002:a17:906:680c:: with SMTP id k12mr4587720ejr.368.1605305808429;
        Fri, 13 Nov 2020 14:16:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305808; cv=none;
        d=google.com; s=arc-20160816;
        b=i1uqpuyud2kRiV9LZjFPIdssfgO98ngGjPHRXF8TD3l0zQ1UUktxzGTjZjBjm3oi9q
         0X3CqHQy9RMWjS+bkhVpj+YtY6fTJecXIs/llRjDmOux8vlYEfBftQo5gq+pTdskCmxq
         dMR6lnRCHFa6uDKNHjhXM5GNbH68lAvRh2ftRxdwFvAOQ04/DzEhPEoNTXP8qIaQLFFk
         2vCR2LF8uRxI5H+zJH+48ZOsjcW2IYfSWTVEMPc7TLR54ldhocLjUWYfuCqAcwyWo+AE
         9BuPv05VvAoXUkUBmcq6loBpHsS/9LIlSZSYM0BHkEF7pmhbiKWhMs0VwDCfkHNLREDk
         F/6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=AsJkOJ42mgBB/RpOeNzMBcOw45undU7MsCeikCxw0wY=;
        b=0q9ZzbwAqfWWWctzRrsDdX6t8X77WFSawimAjb4XuyTW+fNATQPCr4mEWP6nCnAECa
         GHAxoQHq/N1/nFGwohukPzKoh9R4p79cqHUenH+HyFEO+bLqeu+tI+KFZzjUQ+kgcu/q
         YkwS8MxK/9RMEgyhP5UwVmD59Pfp/7aR89Ezs9maw2wphJUEHB5NGDBE5Yc/crHdpskp
         z1N4UqozDNOwV4gEA4zTcpiQBBJP908ZeP9VT+02nxmlTku4qPRKeWFtivWfNT8IRQnu
         NM89dPV1P9YMeehFmeAK8QD5ZxmZ1/XNxVrTeILlEGhVO7F4PZ49EfSIcP36ftIl7oA3
         YbHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jtDCsSAS;
       spf=pass (google.com: domain of 30awvxwokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30AWvXwoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id bm8si361014edb.2.2020.11.13.14.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 30awvxwokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g3so3987920wmh.9
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:48 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f9c5:: with SMTP id
 w5mr5786688wrr.69.1605305808039; Fri, 13 Nov 2020 14:16:48 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:42 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <3d5b13c846573540ba224405f3f9c6ca6ef98e89.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 14/42] kasan, arm64: only init shadow for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jtDCsSAS;       spf=pass
 (google.com: domain of 30awvxwokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30AWvXwoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory. Only initialize
it when one of the software KASAN modes are enabled.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I055e0651369b14d3e54cdaa8c48e6329b2e8952d
---
 arch/arm64/include/asm/kasan.h |  8 ++++++--
 arch/arm64/mm/kasan_init.c     | 15 ++++++++++++++-
 2 files changed, 20 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index b0dc4abc3589..f7ea70d02cab 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -13,6 +13,12 @@
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
 
 #ifdef CONFIG_KASAN
+void kasan_init(void);
+#else
+static inline void kasan_init(void) { }
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 /*
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
@@ -33,12 +39,10 @@
 #define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (1UL << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
 #define KASAN_SHADOW_START      _KASAN_SHADOW_START(vabits_actual)
 
-void kasan_init(void);
 void kasan_copy_shadow(pgd_t *pgdir);
 asmlinkage void kasan_early_init(void);
 
 #else
-static inline void kasan_init(void) { }
 static inline void kasan_copy_shadow(pgd_t *pgdir) { }
 #endif
 
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b24e43d20667..ffeb80d5aa8d 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -21,6 +21,8 @@
 #include <asm/sections.h>
 #include <asm/tlbflush.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
 
 /*
@@ -208,7 +210,7 @@ static void __init clear_pgds(unsigned long start,
 		set_pgd(pgd_offset_k(start), __pgd(0));
 }
 
-void __init kasan_init(void)
+static void __init kasan_init_shadow(void)
 {
 	u64 kimg_shadow_start, kimg_shadow_end;
 	u64 mod_shadow_start, mod_shadow_end;
@@ -269,6 +271,17 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+}
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
+
+static inline void __init kasan_init_shadow(void) { }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+void __init kasan_init(void)
+{
+	kasan_init_shadow();
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3d5b13c846573540ba224405f3f9c6ca6ef98e89.1605305705.git.andreyknvl%40google.com.
