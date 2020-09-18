Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6ORSL5QKGQEIEXPDLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 87C7326FC8A
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 14:32:57 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id r8sf2207204edy.17
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 05:32:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600432377; cv=pass;
        d=google.com; s=arc-20160816;
        b=arRagQmlufINxGfTsno26jsF5uZoNaYPiP1QwptnBOp9uv+/yjWzuyF0vL1cJrG6ao
         c6fBeVtc/str4zMKqG1oVZXyFlkMQOhdJVd+IkAsuvxyPG4gj7KbTpGiNjgCfMEvvwBT
         mDMaU60EMvJoISU58q1gyYLNw1vqucSp6kwPJGHCxDRdWx6Pi9XJH5bJ6Q6sa4wI2r4i
         K0cdhLmI35Fqez5pUtp61yE1Up46mWcPX/+nROcIBAiERN6cHx4TZim1bC+22hsuSQoS
         1ufc5Jzgnp68lmQIr3cSy2IImtkzWDJTNWsdMxGVuB0Z+NLf6wgiyP5AWHTnkfRgZQDZ
         mZpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=huVaFsZutrLDtcRKWri2k5jkmYf7FOfpzgvg9uPdvl4=;
        b=XwyN72Jcjl1Z9J8V1VSCU/47L16hNtQiP3L5gkdFAdanUjg3RwGS3r0hVK4WdJ0zsa
         2Snj5EjtdAO6XbcwK6/CjnFT4rBaoD5POZKoBpEjyn9HLfrb6JSCRwPiqMJTHKJt1Hwo
         cXVtkq2WBOIj3etPpJaGahiB17RY5cqotg9tHd0HYlNXw/x68AOUvYbAaziYqGLoW1Wo
         Mj/p/S7qAxQhsAouRIbRV7jYujKn5/Zr7RS3nHLlpHn6Scynr+QhB1/I+uj2TJnqGuWo
         H3pXSgcTbdpglMOYUjC9RQCx0D0o1e3PleoAULTThKAsNDDGesQDs/uOu6UNCFibMTrZ
         /A4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qL4mSxuD;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=huVaFsZutrLDtcRKWri2k5jkmYf7FOfpzgvg9uPdvl4=;
        b=dPkUGbP4Og9C8112B6YRk5cTVj8bbJqlwoy3G6CLhxPx3Y6SvqQFLEoCRD6BCcUzsd
         Z4IH7SYhcuXumQeF5+Kk3tf/vdtvIrrYpb5J5RYYnIwkLAw4/FPBjERaj27pozpRPP6Z
         ugdxvmSID9Y8UmqdBTP2R9nprgy7WAQDOW+tZ3LIEXlCuInif2CRMSKNU28I/76Y7EOr
         zdSXh4atGeO5COTyWsFe+K5OFyy2Z5ejcmqFs3S+Y5ygueR3CJD57dFfYCWTGlx3h4gX
         dK0xfSxOP7S/O9NaS7vOTqgkEMIeNFsxgnwe1FwtJJbhngOyPoAH4d7Uhzz3SaTSSCjO
         Mh4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=huVaFsZutrLDtcRKWri2k5jkmYf7FOfpzgvg9uPdvl4=;
        b=e3RKnH3xFvRsD79+KjZGQDD8gltLK0Pp+Su6ixRdNkHZxEurPzSVeN7gZQb7qkY9Yh
         UmP5U135CkMM38WdbQ3Qv+HA8uQAc3PTOu8q3m4BELg4x8s8+OOs6jWEnXSjyu8nu5hA
         ixyWZZeUztPjQpL+b5WrMMErfRSc7hHYf9crcBgJRYgBnaHrRbD/bmkChSBSL4pzXVfX
         NpoY/mFoQbRFjJi+ZWkOUi3LZDo3tjVeRFmEdMYS+eyVtVyYIzbAIrnhJ93Rf0C3Lcr8
         QuEcXtbHmljcBBodRqc7pFwXJpbsjkDnKoKRGYXiwnbkY51y2M+T54culTjzr9Buv2t3
         gfAA==
X-Gm-Message-State: AOAM5310OZIIcaGiFSAY+tinsXKtbODmMOF55doIfNqdov/7e8Pc3m2E
	0qV+OZhjTSClafhxlxs02m4=
X-Google-Smtp-Source: ABdhPJzol1YPDOVA+EGEP0HDRCn74wn5NLhhgu1Tu1JsmMoK/J+pZ1Yx/4xpDwWG01b3RmU9/ldS0w==
X-Received: by 2002:a17:906:c348:: with SMTP id ci8mr36980833ejb.417.1600432377251;
        Fri, 18 Sep 2020 05:32:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bc05:: with SMTP id j5ls315118edh.0.gmail; Fri, 18 Sep
 2020 05:32:56 -0700 (PDT)
X-Received: by 2002:aa7:d30b:: with SMTP id p11mr38516179edq.80.1600432376189;
        Fri, 18 Sep 2020 05:32:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600432376; cv=none;
        d=google.com; s=arc-20160816;
        b=jCzrn6vw0YhJEHVy81440+QnvtDM7+4tyZwYJwvhFBprwjQ/deGCR2ANKQbchil17S
         J3Z/LWW6AojxrQZ/o5FoO6OYKjgDTPnnrqQaY6AQXpPr390QwddPILo28Vj7TievJGVL
         w2VNpzSR1EUPcIO6SyP5yCfcXJ0QYO/W+ZEWV/kSlLRh5iZOApLSolaOTK1qvKEPuLVI
         yVPTvi046MNksn+v0LYwzLBcsD+lrbPA52x0UOsCNQ7XZgQaRaycvRqBU80OXjBHS9/y
         xkv9f4fECiV62FkH6D7KMLItdRSqdaWoMbe9qHdXlUfMaKxb7Ist8ux7J0Vjds8P2dD4
         8WoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RW3V/7rc9G+S8I7/pZacY9c5WPGbtuzmcvpRc7I+JUM=;
        b=PNqTjkrnIG085LNfKg1UU5PAk8Bia1b3JBE9G06iuudWKJ2lfznHjASqErYtAh2yzU
         euXfeLoJhcg0yWmyQlphyvXDpV2aJInCIiJF+p4M77Mrv9jXTuH+nJ68dTStcCfma/9d
         gafIMnmz+EFlr0oaJQpCTljPKmfk77vDolj7TYPk9dW1UUET4aC3Cqb2R15vHbs3ClXJ
         E2J1f23UPmYff3TcdL9WyVrVluj8iyemHyjE3jTAPseMCyWchGgYkOIu9D2506fN0W2O
         jeI9hFnjzausTEe91yOPhebDeKqYl0Nlnqe1vdzQpLV6d8U6H3Zme3DX1V/qthET5Oyt
         RC0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qL4mSxuD;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id a16si138485ejk.1.2020.09.18.05.32.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 05:32:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id q9so5174046wmj.2
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 05:32:56 -0700 (PDT)
X-Received: by 2002:a1c:7e15:: with SMTP id z21mr15195514wmc.21.1600432375666;
        Fri, 18 Sep 2020 05:32:55 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id y6sm4995614wrt.80.2020.09.18.05.32.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 05:32:54 -0700 (PDT)
Date: Fri, 18 Sep 2020 14:32:49 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 21/37] kasan: introduce CONFIG_KASAN_HW_TAGS
Message-ID: <20200918123249.GC2384246@elver.google.com>
References: <cover.1600204505.git.andreyknvl@google.com>
 <329ece34759c5208ae32a126dc5c978695ab1776.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <329ece34759c5208ae32a126dc5c978695ab1776.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qL4mSxuD;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> This patch adds a configuration option for a new KASAN mode called
> hardware tag-based KASAN. This mode uses the memory tagging approach
> like the software tag-based mode, but relies on arm64 Memory Tagging
> Extension feature for tag management and access checking.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
> Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
> ---
>  lib/Kconfig.kasan | 56 +++++++++++++++++++++++++++++++++--------------
>  1 file changed, 39 insertions(+), 17 deletions(-)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index b4cf6c519d71..17c9ecfaecb9 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
>  config HAVE_ARCH_KASAN_SW_TAGS
>  	bool
>  
> -config	HAVE_ARCH_KASAN_VMALLOC
> +config HAVE_ARCH_KASAN_HW_TAGS
> +	bool
> +
> +config HAVE_ARCH_KASAN_VMALLOC
>  	bool
>  
>  config CC_HAS_KASAN_GENERIC
> @@ -20,10 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
>  
>  menuconfig KASAN
>  	bool "KASAN: runtime memory debugger"
> -	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
> -		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
> +	depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
> +		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
> +		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
> +		   HAVE_ARCH_KASAN_HW_TAGS
>  	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> -	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
>  	select SLUB_DEBUG if SLUB

Is SLUB_DEBUG necessary with HW_TAGS?

>  	select CONSTRUCTORS
>  	select STACKDEPOT
> @@ -38,13 +42,18 @@ choice
>  	prompt "KASAN mode"
>  	default KASAN_GENERIC
>  	help
> -	  KASAN has two modes: generic KASAN (similar to userspace ASan,
> -	  x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC) and
> -	  software tag-based KASAN (a version based on software memory
> -	  tagging, arm64 only, similar to userspace HWASan, enabled with
> -	  CONFIG_KASAN_SW_TAGS).
> +	  KASAN has three modes:
> +	  1. generic KASAN (similar to userspace ASan,
> +	     x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
> +	  2. software tag-based KASAN (arm64 only, based on software
> +	     memory tagging (similar to userspace HWASan), enabled with
> +	     CONFIG_KASAN_SW_TAGS), and
> +	  3. hardware tag-based KASAN (arm64 only, based on hardware
> +	     memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
>  
> -	  Both generic and tag-based KASAN are strictly debugging features.
> +	  All KASAN modes are strictly debugging features.
> +
> +	  For better error detection enable CONFIG_STACKTRACE.

I don't think CONFIG_STACKTRACE improves error detection, right? It only
makes the reports more readable

>  
>  config KASAN_GENERIC
>  	bool "Generic mode"
> @@ -61,8 +70,6 @@ config KASAN_GENERIC
>  	  and introduces an overhead of ~x1.5 for the rest of the allocations.
>  	  The performance slowdown is ~x3.
>  
> -	  For better error detection enable CONFIG_STACKTRACE.
> -
>  	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>  	  (the resulting kernel does not boot).
>  
> @@ -72,9 +79,11 @@ config KASAN_SW_TAGS
>  	help
>  	  Enables software tag-based KASAN mode.
>  
> -	  This mode requires Top Byte Ignore support by the CPU and therefore
> -	  is only supported for arm64. This mode requires Clang version 7.0.0
> -	  or later.
> +	  This mode require software memory tagging support in the form of
> +	  HWASan-like compiler instrumentation.
> +
> +	  Currently this mode is only implemented for arm64 CPUs and relies on
> +	  Top Byte Ignore. This mode requires Clang version 7.0.0 or later.
>  
>  	  This mode consumes about 1/16th of available memory at kernel start
>  	  and introduces an overhead of ~20% for the rest of the allocations.
> @@ -82,15 +91,27 @@ config KASAN_SW_TAGS
>  	  casting and comparison, as it embeds tags into the top byte of each
>  	  pointer.
>  
> -	  For better error detection enable CONFIG_STACKTRACE.
> -
>  	  Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
>  	  (the resulting kernel does not boot).
>  
> +config KASAN_HW_TAGS
> +	bool "Hardware tag-based mode"
> +	depends on HAVE_ARCH_KASAN_HW_TAGS
> +	depends on SLUB
> +	help
> +	  Enables hardware tag-based KASAN mode.
> +
> +	  This mode requires hardware memory tagging support, and can be used
> +	  by any architecture that provides it.
> +
> +	  Currently this mode is only implemented for arm64 CPUs starting from
> +	  ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
> +
>  endchoice
>  
>  choice
>  	prompt "Instrumentation type"
> +	depends on KASAN_GENERIC || KASAN_SW_TAGS
>  	default KASAN_OUTLINE
>  
>  config KASAN_OUTLINE
> @@ -114,6 +135,7 @@ endchoice
>  
>  config KASAN_STACK_ENABLE
>  	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> +	depends on KASAN_GENERIC || KASAN_SW_TAGS
>  	help
>  	  The LLVM stack address sanitizer has a know problem that
>  	  causes excessive stack usage in a lot of functions, see

How about something like the below change (introduce KASAN_INSTRUMENTED
Kconfig var) to avoid the repeated "KASAN_GENERIC || KASAN_SW_TAGS".
This could then also be used in the various .c/.h files (and make some
of the code more readable hopefully).

+config KASAN_INSTRUMENTED
+	def_bool KASAN_GENERIC || KASAN_SW_TAGS
+
 choice
 	prompt "Instrumentation type"
-	depends on KASAN_GENERIC || KASAN_SW_TAGS
+	depends on KASAN_INSTRUMENTED
 	default KASAN_OUTLINE
 
 config KASAN_OUTLINE
@@ -135,7 +141,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
-	depends on KASAN_GENERIC || KASAN_SW_TAGS
+	depends on KASAN_INSTRUMENTED
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918123249.GC2384246%40elver.google.com.
