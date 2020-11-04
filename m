Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKHORT6QKGQEO756IGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA602A7134
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:09 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id y9sf13985625pll.18
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532008; cv=pass;
        d=google.com; s=arc-20160816;
        b=aUd/TpolewOVjtaYxtxgpkbCHlDLvYdnyCcPSOywgJ7pmT4xKo05CdA12OVmwS9odo
         UheP0vgvQzZZaxBeDHgpyRZiLwSDIpdUDu77oQeGn0iNhQMu9psa6unR5xx5kBpUkxXp
         2ySumw1SSTPWWyzfP/VEsi3mrqBxqdmVCRVxVmFsfoGtColVh9JqC62q0UJJbBmMhd+a
         EQ3+A/ilwvZ3Z+p/wNgoZzyDBolv6bIo2OVXYCW/u7qeTzkQJoUEg6Fiv8WZwrpU+42a
         /Lthxf7cIaQdt5XxrG6GPpqt6fyO9RddHvG4HNfo8I6isdqDflf9oiy4XSqP68yJEO2m
         1azg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UR9g1vrTDzPfhEsVHteQjh57716k2QoMPQAm/jsMPZ0=;
        b=RfdKkfIS+oKbbA2U2TTDjqR28s7Os4O+qQp7PEO5Lrsc0S1d28f+InTHD/yTgyICFH
         FaNaMRfzKz3VGlku6bc291DJovAg4Jevw8qa66IZil2bCoRMK05PxPkUuItO3kWIXrof
         sJwgbdLuZgg2tFpi2Wd1BYJ54yYI/w24Dkd8y5tlsYn/NqRig9/tEhjJ6T2YStxncnP0
         XB+Nf8GhS90l/rca/vJaV3ft18FkiESROu84uDMOI7CfmRf1jkgRRlecLe3OgaB7CVa3
         5xvJl6HQ+xMwyZNoFQdvQZHQUqhaunTkuRjHcFlOEv6iqzkKkXIjxkuCq7IXW96YGhCT
         Q1RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rbdAsnkt;
       spf=pass (google.com: domain of 3jjejxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3JjejXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UR9g1vrTDzPfhEsVHteQjh57716k2QoMPQAm/jsMPZ0=;
        b=Kg3QCOiMlzOY71M0vqRCXiSXzQ/ldp8PH1F37KGPLbavhnlTJgQdMMHIddWkYYbDAg
         hK33pTz4WMslGWx43cc+9wXSz0Vf4RW26m1ajO7TZbseQSu8BP7WEBP/YQ0ECed2mUl0
         8rpjO04kaQGQcvvgpZx2tMOLOZ1Ikk2RtN+RC1eYs6Xo04rMhQuczoL6kE+/YCun2Y/g
         JWowB7b9/0Xz0CtXldH+1BB/4vzTzPAu4f40yKU4QfeqO2oaLEH7wRpxx92EhER8ubLf
         3Y8LZwgVFftKttRMYpZQm7N5UYmKGksW1rMNg4BLPsofL1a4AfI54cIK0DzMTvKm311y
         r30A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UR9g1vrTDzPfhEsVHteQjh57716k2QoMPQAm/jsMPZ0=;
        b=ScSvhr2WwaU8W2KHBRv7x5OIyzxK7BdrJ6qKK00jhQX9J2BspN0krIY9Sf/JIgzXTz
         x7Mv/ICFc8Fo3dIeqRnvUJmtBN+BCGaPre+L5UbmuoJn3RRBTWYwkHZ3i2uguTELwLvA
         ur+RLHVT++LpgmW7wEZijXFXfpv9XiYknrA4iXwkXAIDSaO80aZ1wQ0kc5WfB9qMeSTG
         CDq/2fUVANUuy997dnvrx1lKX5UcE+qmKJR+TEM5JDqF/bk8328c85iJtCxKZWveihbC
         08KRmCr6RlCYMAvPBAA5OPmHeNpPzVYiLCAtmQkDDVQfgSmipPI97mMo23XZXy3KVq+q
         j1yw==
X-Gm-Message-State: AOAM533DHPyhD1G1NVCvTxIoKDAo/lTUEd/AA0HlkDCtrVkaW59lDtSp
	vCmfXeYf5U508no1wV0Lkyo=
X-Google-Smtp-Source: ABdhPJym07a+V1SofgwGW14hyWi33p/J6ADeMKQARec7jFBwtUDKBrNsoFv+Ul4gStXzYdxixwrgfw==
X-Received: by 2002:a17:90a:fc98:: with SMTP id ci24mr217787pjb.111.1604532008137;
        Wed, 04 Nov 2020 15:20:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6815:: with SMTP id l21ls1463833pgt.11.gmail; Wed, 04
 Nov 2020 15:20:07 -0800 (PST)
X-Received: by 2002:a63:1f11:: with SMTP id f17mr310007pgf.282.1604532007477;
        Wed, 04 Nov 2020 15:20:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532007; cv=none;
        d=google.com; s=arc-20160816;
        b=nUCvQfCmcxMUcHvSDGOarxMgwPaUFExjaFks9Iz97VLItTFSqqO4SFLFjeQWG+Qr8p
         PLp9Wi9fJTtcb7neh9xDctK7g0oZ8uJLQ7JAFSfleU9O/0r+L4kGqDoTCCiJ+Ode7tLl
         J1jcqoK6MtRLnhCFpKfW+cLqDKK426igx1sMMe+2RpUFvh/5V3E+QXW8yHy9yHvEgCmO
         45Me3H9yutPKDrDLqAqOk5gZgZuAwa9ZPVTvthcK7inshWijQZqhbmV4+72/LKROeSwQ
         HB7faRPHRqn+sHtbDCu61q0PcpfMic5ZH0SVZtVi6v9MFPnT1OWq4cEakMuxSzH4E3pZ
         iCRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VDtcX23y6dPJZ06sfD07OvqXxdMGED0dxQgWlB1yXT4=;
        b=WmwdlT3GzOd3P2tOTbCr6AHRM9Z8L+Uw3sM4s5ddHZXd92Zk1+ZLdFmIpnPXevfspt
         fJGEzHgmNv0p7uSl6MpcobZdq865TtPnMCF379QQX2QjuEkSlrVi29YYBnhlcTmKO4Ee
         Cs+xENUY/SvnJdzCTP1JR3aGfvO0pD7Oj4MRgnpB4cN7aVtE6T47eyYA6vfo6uRejbbo
         l07t1IciBwxB1A9xA+44NyyBU0kt0hwr2eyiL9U/DTzziBJB7HwSbtwbwUScXzaMYHqH
         7CqBLUPVXiHgVQX/mdtxjMP3Q9hUIMQ+9enhT1Yg2O1tz+YRvg3o9Vddhi91ELvZmSmS
         U8SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rbdAsnkt;
       spf=pass (google.com: domain of 3jjejxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3JjejXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id bd7si185917plb.0.2020.11.04.15.20.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jjejxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id y14so52771qtw.19
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:560d:: with SMTP id
 ca13mr302386qvb.2.1604532006606; Wed, 04 Nov 2020 15:20:06 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:40 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <9a516c6ac375d17eb0ea1cfd4f48e6cbaacdf8eb.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 25/43] kasan: introduce CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=rbdAsnkt;       spf=pass
 (google.com: domain of 3jjejxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3JjejXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9a516c6ac375d17eb0ea1cfd4f48e6cbaacdf8eb.1604531793.git.andreyknvl%40google.com.
