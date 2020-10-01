Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKWE3H5QKGQEDITXWZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 376BA280B0F
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:39 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 73sf25471wma.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593899; cv=pass;
        d=google.com; s=arc-20160816;
        b=wnNyL9uWCQ8HrOXLx9mFIJNr5Pv8E5XnWCP75fcmlIsvuyCqSMiJEnMgMyIKGmspoX
         YonsY4IYwrE9qeLyCgp0MD/ZnOyeYipZRYlK8pzsIfYYvSnADFNO93jEPFu4I0Mc+IIH
         FgCjXU5lpJHukVdgqe5gJqMv0hY0lKpngdewSvmwA5iYv3zCb61CIHZFryE9wUk2QqeK
         9IghgIkhz/NLtu2zVo0HisvxtA5ulanZwrxOfDlaUTnPv8iKXGXI2iQlsW/rHxXcVxw9
         nGYhp3gdhfPHew72EqQsfDfmrxGlQDaJTp0yPPvPhMRKPMoz7M5/bFBLEbz9qlMFNEAQ
         rRmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=J20Re27nC09LsUe0PBZCC2B6YjG4BygHg6M+fmwjWOE=;
        b=YuVili+Acl97fIplABRPwiXIRmTNhjLbDbRJ6xdYjlFVM+DR5eawNzQjXfKyEbgpyt
         5XeVEFi2pYQW7i7LPvXv2TIhxxWYqMDvgXz5SzejC979tkANDHFlw1n+MSnIAFAHG+fx
         nWzME3Q6Vss/2kj5CH1LBjM491r4gfnk07acwa+nDUKW6itCDu0vmyQvM0x7pyGIy++v
         X9THplEc5lxmtHPIGac0DaYOYFdQkElyTVtXQZCTdOw6laCUrgS8Wq+LUmJ6kM3Cst7p
         6yLEFmCoaKqAf2xr0UP7DBjZ4QYhSHyLgac1/PoDK9jERgo2Ifs6R9kNDK/Odyf2pd15
         Gizg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=unYP275C;
       spf=pass (google.com: domain of 3kwj2xwokccgo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KWJ2XwoKCcgo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J20Re27nC09LsUe0PBZCC2B6YjG4BygHg6M+fmwjWOE=;
        b=S3Gr+xN5E8y6qra2Z90nAiNV5Z5N9ZqixaIXRrZAXhEXDfFyRgdt7vCMMn5WLYL42q
         DOzchyBc3Kf04HdP+Svjk2LWU4gxupX7/5phQSmQ/Np3YhslTGolN/x8QfO+xf/zrEfv
         x3S3VVdKuOpkA2QmDFTpAXyyztC/qzu4cn9y85Ew3pb+mxorhN9X59lPo0yzBSiTKZGD
         ZaRx5JnhkK9an76qJFE495F9JoXjqilUGx6sBx5qNeLkXF/6bDdBQezA912bQkTQ0ARw
         SWq/KnqvOJZFrzofWCdUaW7CLRKSOWO8ZOXTLyAnJhVGhFqHbwCYxhn57ApJJOJAFIxf
         fdBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J20Re27nC09LsUe0PBZCC2B6YjG4BygHg6M+fmwjWOE=;
        b=Pqwq+j3fS0NAlLtpf/rXZQzuAlnwCHKBIMU1+pmX414ejTvLlSQQ2h1yNV0vELKLDW
         LitIQfLAPY8IMdQvkm0fOY9xa6tkJJ8S4QVONV6AIah4htOXU8Q2FMKZMngWmoAKvEU8
         JtT1Uh2mLkVEJYPG/cUTFxr9a/bUV8YAi3B1kvEUWF0M/KrQap2eWgU5jPtkiLSMqDhC
         au928pfolOreN+04zPqZNjJVtWcIfPtTbkpAkw5ALzYSxVBk3dpd+NHkEiO08v8wpune
         n9pup/62GWtJcW9XyAJM2Xv0w2NTyhFTGyb4Kn9a9eBslRXwQKul6H5aWL1C0/uY70Om
         z8iw==
X-Gm-Message-State: AOAM532UBoaXRDPS184jxosmucqdGnjFKPUFuwa7UlqzGwdC6gW2zzyu
	1m07rECE0FdUF6rXeb7bspk=
X-Google-Smtp-Source: ABdhPJz4ecLxRinbMHxmkj8BFWGWFWQ5dMBG5WnBQXuSSr6RhUUYIYaOecXls/DMF30sQV8n6pYVzA==
X-Received: by 2002:a05:6000:108a:: with SMTP id y10mr12118527wrw.41.1601593898921;
        Thu, 01 Oct 2020 16:11:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c2c1:: with SMTP id s184ls3642333wmf.2.canary-gmail;
 Thu, 01 Oct 2020 16:11:38 -0700 (PDT)
X-Received: by 2002:a7b:cb04:: with SMTP id u4mr2313719wmj.130.1601593898208;
        Thu, 01 Oct 2020 16:11:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593898; cv=none;
        d=google.com; s=arc-20160816;
        b=JR+jcI9tbO4nnSx6OrPoq+0dlJoK+N4+J01y4zKxgjyG6STvWeSFcjZOg73FArnU2K
         Xz6cS99lfTAqlvzOuoAjHhvriINJ3EKlDEKe/p18kRqkjNRbQxCZ2TUYeNxbedtUVsl4
         IiutQT0Q+nxrwnQrJqGJeFc26NRyCoD77OrIpC/QwsutGzZwRBBv3waZmpFoZKRykUdq
         Ak6mehUq9VlzYpQtVSGhavOGTvlRk4TGl6ljXw81Fey+k8HjMYxdj2soelyZkqWD2iau
         bR61heuNBE98NBCTIbohpqNilk+F2xcKT+JN742FCEv0IlWb3UdcBieSZ72kz44fbmXZ
         7bqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gu8ZqIPD+cy5m/eyqUkVUyD7ozQF5GFsoY52PFdGV1M=;
        b=wPKy4reFP7q22a6eGPS1Kn8v/sQxi3M4JFwIevaK6bIxQQUyOib5oTuup9E/Pz9mGm
         R+X4Jd8KRm5DfsfnM3gsmt0rAdlwWQq7NJ3E2WkAHnmwSs9rAZXU5sVj0w0aToC3tSeW
         KUwJgFJ4bP9tSyFBwfD61YMy24wN0jxV3NAmhgIjBnL/sRFRUpz+Z2oZn/gYXPE/qsZi
         p/Jj9TfDWO1GM4YkUxBMGdlEinoAoLTx4GdDUOEM7CCVGa3OfK1LZvppjKIfk3L9syFl
         nMF+PZk0wb0iMcxKy6LBSQNzN3G/1Y2jl9+uvo59K/q7ICionZmsaBrRD/4zVOyxA5mc
         CiCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=unYP275C;
       spf=pass (google.com: domain of 3kwj2xwokccgo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KWJ2XwoKCcgo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z11si258631wrp.4.2020.10.01.16.11.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kwj2xwokccgo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id a12so120670wrg.13
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:38 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:e4cc:: with SMTP id
 v12mr11233604wrm.216.1601593897751; Thu, 01 Oct 2020 16:11:37 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:23 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <d9b8787e4037a122aacc9e9f53e6e1e65f0b7fc1.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 22/39] kasan: introduce CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=unYP275C;       spf=pass
 (google.com: domain of 3kwj2xwokccgo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KWJ2XwoKCcgo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
---
 lib/Kconfig.kasan | 56 +++++++++++++++++++++++++++++++++--------------
 1 file changed, 39 insertions(+), 17 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f73d5979575a..516d3a24f7d7 100644
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
 	select CONSTRUCTORS
 	select STACKDEPOT
 	help
@@ -37,13 +41,18 @@ choice
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
@@ -61,8 +70,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -73,9 +80,11 @@ config KASAN_SW_TAGS
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
@@ -83,15 +92,27 @@ config KASAN_SW_TAGS
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
@@ -115,6 +136,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9b8787e4037a122aacc9e9f53e6e1e65f0b7fc1.1601593784.git.andreyknvl%40google.com.
