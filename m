Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAWGWT5QKGQEYGXJ2UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id AC9A0277BE0
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:47 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id s2sf623395pgm.18
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987906; cv=pass;
        d=google.com; s=arc-20160816;
        b=u7BNqAb/HFwvRWSJE6THt6nxaIBrFybarK7vWrthIEMWKXebV2T8rL/z8cxHHgY93o
         2+bXW2/oAF+tNv7LSarvaC7xdFFZh5gSsrR9UltK0oMb1fCOlKQrYB6WCTJMTTqBSx96
         9Ose9E01zF+oa/CRT7O5FEyCQZOXIl7+yl6KBQwTAoOOJ+QORR7kygz+j3XzAnh6TN+i
         ye0SJCDX1Htq+txM9yyyDT2c0FbIcqLTDbHNQsF9BDC+Cua1mBvl67FLb/3vYMlKNwAg
         mFfxM3x6tp/Vc4Upcz3ftwlYJMZZdcs5x057WFrxnIFuJXPjRAlkJ6oivCkqEI7vWYWC
         j84g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=X9MJs2ZmdRPk9Tzk2njHvbzx1ThLxu8h4tY1Hx0uRKE=;
        b=iujP6P7si1FJAmj8l5EejD15UjZ+17CzOEUm1vLajM7TRUXfa87pWKrUtqdr41Qwoj
         9O0knu03Wqbkk5S3wYCGMff3FMYs1mkfyL1BRHrKAc1SR4NYHPZlj+rs0F5gstPuP6jg
         cHmBknagmzZfC+gewLzBXotKSgYcJAo7j2gNfZ7pXrMAO5WB2BUq0w1wdDniOcurCVT/
         aqsIqNjdMAj4qHZYdqWJKOTwj6F3RYu6qndNJyT4Ct2/IssMHbCDL50/tp7BAbxJMamE
         /RrluP/eg2kysHncVTOUXnLw19W/KKgGhNC5tSQeKcf/vdr7Wn1xOcDuBhBVQ/3WB/iW
         Tghw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LE0TJrR9;
       spf=pass (google.com: domain of 3acntxwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ACNtXwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X9MJs2ZmdRPk9Tzk2njHvbzx1ThLxu8h4tY1Hx0uRKE=;
        b=HuaVwNWUMtCMcUtmEdOa9MBm2uQ054gWSaZGbHSCSdc3qN7qbbePi9M+I/kxCgB2jq
         iQp7UwEnAdy0KP4QE9QupnU03y5BRRAYvSbL+2SCLF+uBgDe8xboy1LinANbbApFVSCw
         qNVCHva6DJMpK7zp1gpSRMXNPRPSAUoi/cPtyDmRHQH0D77mlvvyIsvJa3AaITVeSAmO
         vFxhHfL/DYUbrYf61A3D7TXnWuzLC7KLDxd+v0/u4tPzzuPeyzJ5mXS2ffNY06EuJiSJ
         H47aZ7aDttj2bcPVgL9wZIjZUz+tXvCQP+v2RwLjcbvVD/RFNGBIEWFiTd46lXSMHnJY
         //7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X9MJs2ZmdRPk9Tzk2njHvbzx1ThLxu8h4tY1Hx0uRKE=;
        b=XXF0ptJkItpYeD9PA0luDyD42clUXtia+WHLE1UtJo9tUC72N8WwYlYUIL86Vsw2ER
         l6krqWT2vsnio37vtgJam1DAF+hOFFTddBY+zBDYTjIezsSAH8qoWZ2jTiQ7MAPbxdmp
         GAZyg47gWUSTWMdXRR48d7HAQG9ogG46SZVIRN3QbsRA1nDunnkYeCSaws1YrZdJ0NTx
         8DaFas1Jqju0SDZW/1xlOjzD/ga5S1fS2qDd0iIDgzC449ytLFjWWsz3Akohmhor6wgG
         oENNMUsKPuyqeOXrfH0EgHJ5F3zvk55963S1gqD+EcLLLkgwrUc5uCu61nA2B3D16egU
         rfTA==
X-Gm-Message-State: AOAM533wMGrkfMaxe9m4bAqMBZnPxBDcLGEUGl+wvykxFpKRgyio2EVo
	gcw7JBraYii7va6FzcOKniA=
X-Google-Smtp-Source: ABdhPJw5gBVnUDbNruBPos5DbXzKLoWTADz4Y4EYp/o+pp2TyFSDFLSGyGpux6ac0c8XmkD8himnOg==
X-Received: by 2002:aa7:8249:0:b029:142:2501:35c9 with SMTP id e9-20020aa782490000b0290142250135c9mr1215110pfn.41.1600987906411;
        Thu, 24 Sep 2020 15:51:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:774a:: with SMTP id s71ls244651pfc.11.gmail; Thu, 24 Sep
 2020 15:51:45 -0700 (PDT)
X-Received: by 2002:a05:6a00:15c8:b029:142:2501:35ca with SMTP id o8-20020a056a0015c8b0290142250135camr1273477pfu.42.1600987905845;
        Thu, 24 Sep 2020 15:51:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987905; cv=none;
        d=google.com; s=arc-20160816;
        b=bBL0pa4JSfVDXxrZNs4SBYjd3nVJh5+Rfvfz0xEZi6FKKXPE7L1XLSQA5NHAi2e2Qs
         TSIgIcEZXj7cUqhnT6MxfomPSMYANJzvxuYkYWx3Hc2LG05N8JEeCP+wp6TfahT0P6k3
         OG42T6jyGrY4AcytLY/v4mTNLfYf3k9D+2B1O/sUygcvk3bOGHrBe2XcgUT+c0jdMdyx
         u2+R9wCok9VPJVxxHDsdqPynDpDf3+RgKmcBLPd07uVwc65C0ILkWP3B1PIo7ngeSTSL
         c/F0SymS+fNcmX/ssENpdOKv10bbc4HQtE7aTPHsEBiCSX3rTishFBxX3jsB3CZtpBNV
         NjhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=/ayGZYJKDcGk7zFWFRfetLIXrgdYrCw7jhhhvhwkhIs=;
        b=X0/FBtQ12hU9LbGWeZywh/sDKtLAGBzdyH5HF2Oc68EGiZEhWE1MZuvZmxJO9AS0BX
         wlGJVxX+h6nZ/MrH0hRfz2cPKJq9niiStT9r5SglCT6KTxQXESrLzcc0Ui9WphAo/WOy
         rH5g/T4a+vn8ajLBsnwuvvDkQQ1RoP9qawECgWVf18s8L6nseJ3jFZo09fZ7LW1uT1SO
         CLH62cmE+4awA6QXKSrzuQJzSg6akm/EmftLmiQEYwGPBz8fQEOs+oEoX3/dkXchiwuz
         tQKylJO1ldaHxeYsu4NlAQfxApCTsO+BDY0p3rEYPrFjEx5YygXchP1ujbuseG5u5LrU
         pAhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LE0TJrR9;
       spf=pass (google.com: domain of 3acntxwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ACNtXwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id t16si82571pgu.1.2020.09.24.15.51.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3acntxwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id f5so507686qtk.11
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:45 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:47cc:: with SMTP id
 p12mr1635316qvw.22.1600987904911; Thu, 24 Sep 2020 15:51:44 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:29 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <76937ee6e88d0d1fc98003e503f31fe7b14a6a52.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 22/39] kasan: introduce CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=LE0TJrR9;       spf=pass
 (google.com: domain of 3acntxwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ACNtXwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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
 lib/Kconfig.kasan | 59 ++++++++++++++++++++++++++++++++---------------
 1 file changed, 41 insertions(+), 18 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index b4cf6c519d71..516d3a24f7d7 100644
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
-	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	select STACKDEPOT
 	help
@@ -38,17 +41,23 @@ choice
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
+	select SLUB_DEBUG if SLUB
 	help
 	  Enables generic KASAN mode.
 
@@ -61,20 +70,21 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
+	select SLUB_DEBUG if SLUB
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
@@ -82,15 +92,27 @@ config KASAN_SW_TAGS
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
@@ -114,6 +136,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/76937ee6e88d0d1fc98003e503f31fe7b14a6a52.1600987622.git.andreyknvl%40google.com.
