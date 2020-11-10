Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOFAVT6QKGQEBJM43SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D8EF2AE2CC
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:08 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id p16sf3571690wrx.4
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046328; cv=pass;
        d=google.com; s=arc-20160816;
        b=fCW75flvqHce5DwWP7IWSxdJAKoWEeMNIFARON/GgID3sLmnpkVN/9ruTdo2BEj8q4
         5P6FunZrcztoKDVuzHvf4OoeKRJTnfEYu5keHHJXIP7jx8xP7SbegjoJ7BOXI5ArJGyR
         S5Yk6vw+qORw/NKkopGeeXGZRMAU+MNUo0SJtXm1li3ErvQwZF7taIloLyHu+I4zy5Jz
         hec4XfKb3GdbfKR03ZdvGQLFEPS242SpWqeGw3/6t+4ymRK7XmNzQe7Dp5vG4d8ARt6/
         pQFEfEEtG7iGpaVgwujxbZ9itCqjiJ8rxB/OUuXNzl8GNI4Mtcpjb7WZ9j80KnzIa8Xp
         Dr5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pAeY3VzdY6HQvhTcsEKpv7YvCahcDOfi+pamhbxYD5M=;
        b=aCuOfWosmwI+MBIiS+NCH4mUC9uO+idBPdDA/jikFxtGey4BpAOZqGFlFVnBjf3wcF
         pKIxN9a+81BDhoS+IA2ptrbxyfRrsEDNr1NUgch4RUcwyomZTHSs517jCwipIR78EzjY
         XeVaXPz/vHbgQ6/MAgIEsi6QtXIv20Tw/jje3DhLSLlQ+7kt4RgUadtJKpKnSX8HXxe9
         E1+qCtsYVGDuW0FeaYEmKYlXtto59o+77dPoKbjr4O0uOw91WAjAn4nT/f3CJz3ALftn
         luDsxdaE7JGPWBNUESRweyCccCwZP5jwt7FOE1p3ClapQAxnWFEk2RSQzc9RagZBD/ca
         a1Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UOKpUFeF;
       spf=pass (google.com: domain of 3nxcrxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NxCrXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pAeY3VzdY6HQvhTcsEKpv7YvCahcDOfi+pamhbxYD5M=;
        b=Cqg9gzwcM8s3BvhaymvfJamikuMuEc7nSNTzCIO5qtpi10krlAX0gdeP3rDQ0EYDqh
         iNbRH5tQhYr4kgl0PEikgiFRGGvlytSSshfa7VAX2asI9UQotHGZGGoGCLq9gHoUKxGG
         yjcme9tfVlJZC8R9TtA+P/2Mx0mxPFRX6oHD0AIFx2EEoBtPW1dVn+Ao4ms27zcSU2MV
         ymcwscLL8lcuHbS8oDlUbsaCYAkkHmrHnwBzCxrcq0acxvSSJZ0+tUImTGcuN1Ilr6mm
         XvJMO/TckyvgPXpg/ysk6ANktQcXTJHgsO0bntMePlu/S7ALbwdUsX2sbmRBBb+N0KCz
         yZVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pAeY3VzdY6HQvhTcsEKpv7YvCahcDOfi+pamhbxYD5M=;
        b=Xntcjc/IplgMYSqhGjbKPE8mBM0PJiF/OUado9t1ZJuerYP70BymmipRHUDy2Tp3qA
         aE4CbgR83hKkBTmxlSLfmjVmz9zVWducJCmFB7/JcpW4G0RZVauF9TBcLn4IZly3wXKZ
         AVu84QJBalflcy6/DOqdLfmViY6Pq5dfq2sJXTHK8qZ87gkREvt2AGCxry8sjpAHN8xs
         jw83oBV1OiRuWG07eg42e0rLwJ50xLOWcoOcbf0owEPtcnCa/ccXD69vLahePth0dt9D
         cp73pHZco6PNx8ofz0r1CQ/hnHma9j4/6KpG71wV4QIYfX639SJhEX828fyw3nyMq0ts
         2/tA==
X-Gm-Message-State: AOAM533KYpxlXO4+DW8si4RlFmttKhfaYLdm4MIGQlDfZCEKgLnopR3s
	+hk7Ux0Jf+XGJURkgHDn/6c=
X-Google-Smtp-Source: ABdhPJy5rtYe2l8ni0KHIFjcBBeRayoFovavB7QIl9nnooES+BQxFnlCMXdo9+2DFnTTFs1uO73IUw==
X-Received: by 2002:adf:e787:: with SMTP id n7mr6277835wrm.153.1605046328314;
        Tue, 10 Nov 2020 14:12:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c689:: with SMTP id j9ls459241wrg.0.gmail; Tue, 10 Nov
 2020 14:12:07 -0800 (PST)
X-Received: by 2002:a5d:4dce:: with SMTP id f14mr28268668wru.25.1605046327481;
        Tue, 10 Nov 2020 14:12:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046327; cv=none;
        d=google.com; s=arc-20160816;
        b=UFYmDhkRzwKaHmWwvu4apIwqDUN6uL2d1i1rikYL0HkW8rAWiYyhwtGNPt5SB5rB/Y
         pOzWLnyW+6cUaND5byrUeI/U2bQkBquc7nBBhtMHgPsTI6UukeWBa34ZbxReReRfMWCF
         B9mrVE6jFESTiukzcW5nFqJT9aSPl6agI+R9dH10rr3CqH1us3V9ym1Om2wpUD0G6TCW
         WRSxOQc/5lWRlboQSJNOmbI8f2hVEMVWPNsxbTFygMqiRfMhVsAcErZ/ySgv6FGOU0gI
         9OwyQUoRi+YfaeM5di0y+tCKg6EiKjSEPuVvCaN4R6VlKRNYy3QqhfqLGhy+WNaJEUBk
         WnKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=b+EvmbcrIzXMPo/m/7VxFCc4Xq4JWsmqnUpW/yxxI4A=;
        b=v+x/fsoFfNUIIlpziHq5mpguEE1NZKjRvJRNBqCT/VH+UGO18fG4xrzfmVYc3LVHBd
         P4gvxxORmGaSxzvnj61e+o0ysgaFGLojyxhREyiV/jgqyeJpJmuJZC3cKxZDLnPh1UNv
         tsP9UxQdpukZDyHqMDaNdQSTLcgnSr3wLffF3F+hHhQCVZ0oV/wKzelJPR9G0KSHl9EB
         9kOVPWrCTCfB4H6hA43C3Z1F8ZEDwrcnPIrByVqSuKOKZiQrxfPEyfH3jUKU90FKmvxh
         FKX6VbPnxZ9E6E/y01O3Zya003GgZ1epKt5dvsGCvnGk+qt3tvZWmtSui/OIorG96bGe
         Q7jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UOKpUFeF;
       spf=pass (google.com: domain of 3nxcrxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NxCrXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id j199si149198wmj.0.2020.11.10.14.12.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nxcrxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id a134so1227149wmd.8
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cf1a:: with SMTP id
 l26mr287557wmg.18.1605046327072; Tue, 10 Nov 2020 14:12:07 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:22 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <55d90be0a5815917f0e1bd468ea0a257f72e7e46.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 25/44] kasan: introduce CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=UOKpUFeF;       spf=pass
 (google.com: domain of 3nxcrxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NxCrXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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

This patch adds a configuration option for a new KASAN mode called
hardware tag-based KASAN. This mode uses the memory tagging approach
like the software tag-based mode, but relies on arm64 Memory Tagging
Extension feature for tag management and access checking.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
---
 lib/Kconfig.kasan | 58 +++++++++++++++++++++++++++++++++--------------
 1 file changed, 41 insertions(+), 17 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index ec59a0e26d09..e5f27ec8b254 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
 config HAVE_ARCH_KASAN_SW_TAGS
 	bool
 
-config	HAVE_ARCH_KASAN_VMALLOC
+config HAVE_ARCH_KASAN_HW_TAGS
+	bool
+
+config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
 config CC_HAS_KASAN_GENERIC
@@ -20,11 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 
 menuconfig KASAN
 	bool "KASAN: runtime memory debugger"
-	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
-		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
+	depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
+		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
+		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
+		   HAVE_ARCH_KASAN_HW_TAGS
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
-	select CONSTRUCTORS
 	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
@@ -37,18 +40,24 @@ choice
 	prompt "KASAN mode"
 	default KASAN_GENERIC
 	help
-	  KASAN has two modes: generic KASAN (similar to userspace ASan,
-	  x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC) and
-	  software tag-based KASAN (a version based on software memory
-	  tagging, arm64 only, similar to userspace HWASan, enabled with
-	  CONFIG_KASAN_SW_TAGS).
+	  KASAN has three modes:
+	  1. generic KASAN (similar to userspace ASan,
+	     x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
+	  2. software tag-based KASAN (arm64 only, based on software
+	     memory tagging (similar to userspace HWASan), enabled with
+	     CONFIG_KASAN_SW_TAGS), and
+	  3. hardware tag-based KASAN (arm64 only, based on hardware
+	     memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
+
+	  All KASAN modes are strictly debugging features.
 
-	  Both generic and tag-based KASAN are strictly debugging features.
+	  For better error reports enable CONFIG_STACKTRACE.
 
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
 	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
 	help
 	  Enables generic KASAN mode.
 
@@ -61,8 +70,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -70,11 +77,15 @@ config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
 	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
 	help
 	  Enables software tag-based KASAN mode.
 
-	  This mode requires Top Byte Ignore support by the CPU and therefore
-	  is only supported for arm64. This mode requires Clang.
+	  This mode require software memory tagging support in the form of
+	  HWASan-like compiler instrumentation.
+
+	  Currently this mode is only implemented for arm64 CPUs and relies on
+	  Top Byte Ignore. This mode requires Clang.
 
 	  This mode consumes about 1/16th of available memory at kernel start
 	  and introduces an overhead of ~20% for the rest of the allocations.
@@ -82,15 +93,27 @@ config KASAN_SW_TAGS
 	  casting and comparison, as it embeds tags into the top byte of each
 	  pointer.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
+config KASAN_HW_TAGS
+	bool "Hardware tag-based mode"
+	depends on HAVE_ARCH_KASAN_HW_TAGS
+	depends on SLUB
+	help
+	  Enables hardware tag-based KASAN mode.
+
+	  This mode requires hardware memory tagging support, and can be used
+	  by any architecture that provides it.
+
+	  Currently this mode is only implemented for arm64 CPUs starting from
+	  ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
+
 endchoice
 
 choice
 	prompt "Instrumentation type"
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default KASAN_OUTLINE
 
 config KASAN_OUTLINE
@@ -114,6 +137,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/55d90be0a5815917f0e1bd468ea0a257f72e7e46.1605046192.git.andreyknvl%40google.com.
