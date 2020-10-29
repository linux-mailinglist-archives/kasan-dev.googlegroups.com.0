Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCFP5T6AKGQEHRK3DJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6385329F4FE
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:05 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id l17sf2671049iol.17
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999624; cv=pass;
        d=google.com; s=arc-20160816;
        b=MZaqXN/7b3Ox8zZ37Maal8DakJoDz8yl1j85CzAlB4OMh370FHgXYqNvQPtrhp837y
         fOKflBFJgMsYRS/YPBYqjtJAaxuNa/+ZGaN/nDBrbDZ84QX1VPkRlp1XyWYwso1C3oMR
         1not1xsRR+/05rWqC3QJnWffq2FQKI1C4c4uzLScEAta5xN2o1Hu47LPV1NvALiCmRTi
         TDk+TmCYf7t9QufFC5nOtxxmgH/p6ptap7K0TpM4xu/W/R/61WhclitKoKUrnq4lzMm6
         lHUP5GroQFOCVmBSXc6+MDgmjsMjYAI7DCXB9BhU1451SDRqAZUeJz+mixvfTU14YrcQ
         /JWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OqvxCVal4oT3IERC8xJC/xW55VsYgfWI+QaNW4lUzcI=;
        b=Pt/ULuZUzljcuFhsoOtxacVNnFN0tuHCYAoE0HvuVNxFw6hn7i1lVS4GkwSMMff7vf
         lpKIDaoY/DO9RIYQcczkicH5Ahjf5u04Q1PKGTGubHrIuMof/Z2YWWDV46r1CQOByO35
         lXLI52GIMBcGWYBMUA7rVgu8UhRDKamvOhHEAio6RgHupE/fblnjoS3ekSFM4wpIVJDK
         IuHaf3n8yP+/9OGtMmnD8CX1PQxpluWfy9+DL3GijPLiJ0nY2QHtUXZXLw6JDg7mqSqk
         g7z500e1bZJkkqtHMmpyKzP8dvZ+kZ+2nULcYexw7njpGHMAR4HYayrxTR/qaLfvfd8M
         Rcyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O74FrK2B;
       spf=pass (google.com: domain of 3hxebxwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3hxebXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OqvxCVal4oT3IERC8xJC/xW55VsYgfWI+QaNW4lUzcI=;
        b=cj4lTRLb9v2AaYa7t7HvL5+KYmOxYke1NHNwJqxdu4MUfk1LODsbdz6m1AjN7GdjQQ
         5ZxFjgKLWqbs2th1nIWcjee7ba4yAdwwx+9QMY/czi93EWr+UCaJlxxeTTG5clFMq3ME
         hYwrRBh+OJfBsxL9NP+QgZV6f9VBWEx3/bNSmkXsr/+DwV9cgxIUO29lGmFbUtaiNADg
         hVTKxV8h7mVFm6vXpb0EpsKOmiEoUiUehfpPOrDD/+Kyj6sU8shqh6q3tiFOBEDQIDf9
         p8bxASiAy3M9alfkn+nW3dPVsYfEsUnilE3Anz5HdmoVLdz6nL2KAKjzrORqsiT0GLFM
         88+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OqvxCVal4oT3IERC8xJC/xW55VsYgfWI+QaNW4lUzcI=;
        b=MwDf3V8WuW1wvT2W7yrVXEbsZ+pFOTMu/VzWBLgXNWLtTIXAOjVDol1ccym19tQMq1
         thqb2zuAkLgJ/xtinVxnL/JxXtsr1jtMyPsAoSjhMVtwrPvBVGqGBhdCOIwZgB1CUKXi
         RB63ihYZdjCXMeT3e9vsygZMaIs+5SR9sxsD7ulZwPxD71LUb3c/5jslB0Jvp6Qul05X
         67A9SCkGai7JGFTptAvieE/uDn6SDHNgOrVQQz8ma9itSKS5QJG4Rq+eiy9eoS8/PjAC
         N9F+gFsEu5BfZoYsYgqE3eDPCJqpr1UGyYBiARctItPpeXnZdIlocQBCM4DhEuGLZ9wi
         2oxA==
X-Gm-Message-State: AOAM530MqOeIUKMo52Rak2JJg/QvKvZtsfRqlhbGJtUvrxpy/kLP5UXy
	hgn+z++x5DoPdmJ9evW94rY=
X-Google-Smtp-Source: ABdhPJwIzWZ+Gcku/n+R/rhDsaUaADir9KlJLZJcsG300S/m8eUdlpK/dIj+9sA0uq0YC+b2mJyVAw==
X-Received: by 2002:a05:6638:3a7:: with SMTP id z7mr5075830jap.52.1603999624357;
        Thu, 29 Oct 2020 12:27:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:63c:: with SMTP id h28ls466438jar.6.gmail; Thu, 29
 Oct 2020 12:27:04 -0700 (PDT)
X-Received: by 2002:a05:6638:c51:: with SMTP id g17mr5069987jal.33.1603999624064;
        Thu, 29 Oct 2020 12:27:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999624; cv=none;
        d=google.com; s=arc-20160816;
        b=bHv7na6IHAhnkODwRlYofljIJLyR6RUQlm0nvGzOYugKvkaI6kn/ThlHT/Sqg7F+5F
         5uy2glJZUJyFe4/D7lX2KhhudGtaefIz/Kq03GSwTDv2uI45wu3YzmYN7BfZWxggrtyR
         C13U6ixNF/MBcnTTtRvjFZ/LjRQk5mMYkEQBQtvqg2o8aj+6x29I9M3X0dXYzBLUSM+4
         6zVE5nL0Tyc2zro0k3F0wYhRYl6ULMQE/rzeV5njMF1dBtp4SM0l0BglGnTLlcX/JSVD
         4yqQGlWU353PSssr45Sl+IGcKXecTF4l/pY0T4FXoU1YKB4EanOoIIoBksZfd4amrUk+
         iiZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d4Yc7AItymQNyKGF4tg/i8f/qZM6X5xLr7PA4bM2pG0=;
        b=SNmOCZ+A9TD8c/G+jkzwaX4C8ipSlJUvLGpgUujWMpyVUzB5G2PxNNGeHSGOL1WDYl
         AJL+5foA/hGSf8LqaKFgqBlpxGBu2el/7XdcxCm4QvFm5exwNqBu1Q2APCcseSZge5ac
         a360jqqZYN5dw1rUQQ6WjR1UPgRGd7a0S6mFI4cOsRfwrCjZcTTISK9UqH08kwCFAlAY
         PErmy2S4JqtYCuDCUpH/1bdkekU51avkM76qBNZFfxQQBhltU0A6yXlbgiIvGwo0f6ys
         rI0rWVo0FphSkUigC0FRXEE3ATKKbBZLnObWloFobF3iJaqsgudXklwreoHDyltP9OkH
         mpPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O74FrK2B;
       spf=pass (google.com: domain of 3hxebxwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3hxebXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id h8si136031iog.4.2020.10.29.12.27.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hxebxwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id s8so2360233qvv.18
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:04 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:edb1:: with SMTP id
 h17mr5423193qvr.7.1603999623483; Thu, 29 Oct 2020 12:27:03 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:44 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <1b97c0eeb401f9657e66b05c6c43621edff3bb68.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 23/40] kasan, arm64: only init shadow for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=O74FrK2B;       spf=pass
 (google.com: domain of 3hxebxwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3hxebXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1b97c0eeb401f9657e66b05c6c43621edff3bb68.1603999489.git.andreyknvl%40google.com.
