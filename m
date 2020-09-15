Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWW6QT5QKGQEQEW6SJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 554E626AF60
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:15 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id m20sf247508wmg.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204635; cv=pass;
        d=google.com; s=arc-20160816;
        b=JayLIPHl1iqghSzEo7aI8umCnvu8wB15T1gKqVXV8K4pXhVUWBQ4dIEWorzBteuGKB
         zDggUDJokSMvE9GOEqV8/+Sg7ldpH1730fIzsN/QQ8kCwHruMY3a5o1YerWhJvH2rS1e
         4fHAVKAyqSud02TCMb7iwmRfFnaCWhO6OHjjzr0u0N+sXpz34gReegMYxYCKo/DQhk/k
         FdCrA62hZ0JuJkqDVCiBZRXHKXIVZyp6UORdv60t0eutV7rXGKfjIOutD/zG3kzoADI9
         E7TJoOQ5qub2eKqhhp5IMLwOfGbhDJfVcFdw2BThqpc5Gq+qDoMxnEO2sURpKugv2dnC
         zXKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Qb9O8Pvh6PTiiYk7wL7TtzQzh24QFEnLYC73CZv3rJ0=;
        b=CAAaeSlwvzKLPAe+0EE/f0Wxx6c2X7Yiy8qYcjjiwQKoik4cjnfYrn6ZW2SO3JMAYh
         dj+PNAUpSEwl9k7iAJVJrVijF70JfCUIj/6yECMl76QW1en22LBYwOEu5qHK38iTp36B
         kK5vAVqhZiOYc69Fyq9oek2SuvcWqR0sZ5RfEqN5nKRjxq8h1K5KX51hYHc9CmZ8YzB6
         xXrVh4JNIcHVVNyaAhQS7cOopm03u+I3R029Y53mIk+ovXZV0qH6I2th484FOLPBAdG0
         JAKWZl+mkgHLU1U7/zKgYyRT20hCSdG9WL2h4FR0jc5gk5OY3Rb9OjOpQpR3NbIXHh8O
         udrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dSybjoro;
       spf=pass (google.com: domain of 3ws9hxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WS9hXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Qb9O8Pvh6PTiiYk7wL7TtzQzh24QFEnLYC73CZv3rJ0=;
        b=pu4OfM01EbfO29KW7eqihMzGKvsW6+kRCLN3SzuwQ7Mfnst1FyFt7V65z5oRw89wap
         43Oz89VucgGlTpN7HUut4HYrYyd/id/gpZgKWu7HuX3wzVarGRbFE72HccbkJBiagA5X
         N/56TTJ+HgkzC7/OtJqO+3BX0xIxzsf8jKC6AJcl+3XGzwxxfb3+3KzJjAdK5V9ydxHm
         OSZOja4wjptrhDt9paBHTFa7Mte7kaAhBClpAkV1GkAjBOi2RNzZR7czbHrKKS4aYSQx
         diDFzf/1TqvdC2QYNaNpE4Qlt76qCbftpsFJvwLBRM9vBzECKA2K8Ca31OspSaEFaHnI
         LyNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qb9O8Pvh6PTiiYk7wL7TtzQzh24QFEnLYC73CZv3rJ0=;
        b=XETWVL3iP2SOr4CvUfDlxgidwzBhnoX9Fik/goK4aMYpjSDyfK3FPWupzTIwubAUuZ
         924oyyWS2HwuPKWNNjc02nh3IfOpgq+6SAXTLAzcHZ1yvdwxpvbMP9MFuPpbxjMj8Me/
         /sMdfRDboUBZV3LMlDpp9bwlFoTh4X2vxWx0VCuK47oQU+CsHrEtx3WXGHltqkuINylT
         OupmjQJDpqntyJZIVbqvFLkXcLZo3sbQzPiFLfP9aCTBmJVQ3EYxrC3pL8I4Tisne/rJ
         7qeTzIL+NQiun0EDrmKDDSVhkSzBICAjGJXYqhR8Iw6NGdSahO/R+luUe/9Bui0W/h3X
         P+Ig==
X-Gm-Message-State: AOAM5314kv4+0Mr3imDsvn+i9yk4BwdMogGnH9kjaXWs485TNW3YC/zx
	hdQ1oWlTn8tHJFSUAC0D2zg=
X-Google-Smtp-Source: ABdhPJxebXDwjkpCADQKrYhZK4iyxs0LNjK5GqXTJVGhh6Lvyf2JtS3zfIF2mnfySArhUAFxd0bIww==
X-Received: by 2002:a1c:e256:: with SMTP id z83mr1299067wmg.137.1600204635028;
        Tue, 15 Sep 2020 14:17:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:230d:: with SMTP id 13ls105798wmo.0.canary-gmail;
 Tue, 15 Sep 2020 14:17:14 -0700 (PDT)
X-Received: by 2002:a1c:678a:: with SMTP id b132mr1330812wmc.10.1600204634203;
        Tue, 15 Sep 2020 14:17:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204634; cv=none;
        d=google.com; s=arc-20160816;
        b=oBv+KsJdv92BJMDEl6ONFBkADmky9B4WkgYrmXrlxCMWqPCzgv40l3lQJpG/YHsaDL
         FVSEsmE3LPOQjUgXpvzj6WxhLGyGACVhQiWKTTGCesJ8jm74WEGX7Zx7qFZbt2MawZ9P
         g1yIL1He6YN7Ju6dCMOcumjClkZs4OOQ+xbKiCohCrR3tQGxj5wcslA0xkbsAZNFZBjg
         aLA7BOUy2Q9yqTy3kRyteEvE+M2Mtbt/hvnR/Ba1i3ZBtFNrPr5G2GkSvaK4Uvwym6E4
         x4CZl59BvHk/Xijp9WOd+EEnbKe0b+E9Flm/cpD+Om2e+9p+PKgCoKg2hwBHByi/T5Xm
         2xCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=5EqdZprNAKl8DcEkoPF/XnJisJp3YxDsBKGpOsfCaUM=;
        b=hng/jjmnwceqUai2MeKR8K5KUDAfaOcnJHyXdfUTZgrSHNcL2UeocWj40ahtvP7zVd
         7bRjXsPjqvVClCy8HrCkpOGj1+aGWTr1/lIRf1uLCoONiQydBYEPimlGmgINzon6mCdR
         KGHn1vdew26P4I1/c21WdcXqEKZEWFiYztEfwRmxivfQoFdWlHGWnqEFXhOQ3podAKbd
         8zn5zcBkKlDKiqlTcaDT/a9WMQwDZ3wdHSJ21mAb7E4k7npjKdE6wYKNOscSNq+C1+eH
         Sk6BOIEaCc/gprrC14TvlVmEMfqR9nP2GEhunxJEiasqD6MmvMcn48suZBegYQu0VTeS
         QLQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dSybjoro;
       spf=pass (google.com: domain of 3ws9hxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WS9hXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 21si27563wmj.2.2020.09.15.14.17.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ws9hxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id l17so1693890wrw.11
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:14 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c4d1:: with SMTP id
 g17mr1160652wmk.167.1600204633702; Tue, 15 Sep 2020 14:17:13 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:03 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <329ece34759c5208ae32a126dc5c978695ab1776.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 21/37] kasan: introduce CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dSybjoro;       spf=pass
 (google.com: domain of 3ws9hxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WS9hXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
---
 lib/Kconfig.kasan | 56 +++++++++++++++++++++++++++++++++--------------
 1 file changed, 39 insertions(+), 17 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index b4cf6c519d71..17c9ecfaecb9 100644
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
@@ -20,10 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 
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
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
@@ -38,13 +42,18 @@ choice
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
 
-	  Both generic and tag-based KASAN are strictly debugging features.
+	  All KASAN modes are strictly debugging features.
+
+	  For better error detection enable CONFIG_STACKTRACE.
 
 config KASAN_GENERIC
 	bool "Generic mode"
@@ -61,8 +70,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -72,9 +79,11 @@ config KASAN_SW_TAGS
 	help
 	  Enables software tag-based KASAN mode.
 
-	  This mode requires Top Byte Ignore support by the CPU and therefore
-	  is only supported for arm64. This mode requires Clang version 7.0.0
-	  or later.
+	  This mode require software memory tagging support in the form of
+	  HWASan-like compiler instrumentation.
+
+	  Currently this mode is only implemented for arm64 CPUs and relies on
+	  Top Byte Ignore. This mode requires Clang version 7.0.0 or later.
 
 	  This mode consumes about 1/16th of available memory at kernel start
 	  and introduces an overhead of ~20% for the rest of the allocations.
@@ -82,15 +91,27 @@ config KASAN_SW_TAGS
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
@@ -114,6 +135,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/329ece34759c5208ae32a126dc5c978695ab1776.1600204505.git.andreyknvl%40google.com.
