Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB5R3D5QKGQELUGJJ2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 79C82280607
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:57:27 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id v5sf2330741wrs.17
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:57:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601575047; cv=pass;
        d=google.com; s=arc-20160816;
        b=SwZSfFJvZ7nDBZrxpeZR94o0+g4PIAMqx5WKjZHzWnpBJrIF0P49rpqso+Iy2OdILe
         6Af/eXHAGlX7VP1/yHBG/cff6GL/CoLOmp6htDHGnCv4i1hnlXUY1SFOfaiodAVM6FeM
         +/wSwxtkI4stXWgs6LuSSBxqMgVWxob7EL8ezprJxhu43fJ9PnuboDQdlWlEqURpSRJD
         L4M8/Jq/55Lxua3gdY+UmaIBVlSjOsamq3JetKpa5FThGS+hHDj2Nn8eJX0mP9CXqKn1
         RiI8wlj2Sh2Kaiw+VCLPqINhgN+/Nk1J3bFawq/jy1OiqBuJ1lGRkcFcw/gosY/IcumP
         0/rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=e7frKet0c+TXsJx/732KEYAfYS3Sd6fHfc1w5tzapbo=;
        b=0a/sP9OnG4A7svG3732HaamSO26utMpkLqcsCVOyPmY8t7ULjPqi//hXOdialaTuBa
         7YaC7yIK3zu16HAVaeHriaRjPB2lX5TKFlvKIoTRuIWsNrAIac8V1jKL+hRO8WCw74pm
         k+84EWgKX+fM4mM5RbC1xs2elOL3uUXcUDqDwjMBQhjlkmfHwM/lYpImYvZZhPM53pdG
         kdixsaqM+QC992epyza5plvf7ROIBLr19DXFu7rHXXIbVFn1fX0Wam+flTKp7sLeCq/2
         /t+nZPJvC54/TBwfES7bxRAfQP31SHL6ky0KzYSb+WJyrj/+m0SZTcq3RiQdZvpfJt1z
         VWoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ftzp9vYt;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=e7frKet0c+TXsJx/732KEYAfYS3Sd6fHfc1w5tzapbo=;
        b=QR+hVzIoSHpHaK/jwtfSDQNuIXlcRKIva7Lxon9u7WPq9cQhSr+T6IsXT2Djfla27M
         8bRNdDEQC53vHH2NprOAZiv6oGbCAFYbINkyAADlDCdVhllBRxG7AeW+RqfVQNt28I9D
         IhldQxeTDDvzYhUQDBjep4hKWAVqshuu7o5VpfBsAsOtZU16IOtnFhMw1XRXEXpBqgVb
         UOl5qVSz30yBOh9Y+lPpvvQm7jlnVrANEzc9Xrx5aiaNy+hJ5MB4Nl86U0wtAuesoZdp
         cnejh84BQGiybT3gNm6h09d1w6GO44X4xXpM1gWmXIM1ZGscBGJY1+8vH3pzsitKtzFo
         20cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e7frKet0c+TXsJx/732KEYAfYS3Sd6fHfc1w5tzapbo=;
        b=obnMJor4P5ZoG49mXcQNLJ8ikdhTFYU98GxVsuq3x8BnwRZcKXUgfXJZ/1RaN0poFM
         p+GU6hoGEaHAPN4McLWqhXqf+dpEA9NAkXgpjf3s4DgcyElAr7iaD5yKgsMDsD3BodzQ
         Eei9P2HdiMcE8BI6/3cc8lsQWr2Dj00B7npUzUdUqJscfzPGRq/VgPk8fWl2+xkPe4H8
         B1eBASfH69twAlT8jLyVz5zKklf5mUGkZbnPlUreefpyTekshdl6vV0LJy6REmBUGWCs
         ds4bUe4KXZV+ZNWGn2IyzYG7yLu5xqEmStux13P75/ADBqMuW20v5zlhHOo/oR7VQUL2
         CBNw==
X-Gm-Message-State: AOAM53241oV+A4z3+q2fXF6Q5gwMvonM0f3577jDmMyXXuELH+bfwHM7
	nNuoNilSafJbODYXJwF9ULk=
X-Google-Smtp-Source: ABdhPJz7+tu5fybTA4HdwDm7X/VhcK39l+qNCbiyKzWRcBKnS4FOtiiDIaEO7uL99d2DvbtQYvLezw==
X-Received: by 2002:a5d:4910:: with SMTP id x16mr11219531wrq.204.1601575047207;
        Thu, 01 Oct 2020 10:57:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9e53:: with SMTP id h80ls3305560wme.1.canary-gmail; Thu,
 01 Oct 2020 10:57:26 -0700 (PDT)
X-Received: by 2002:a1c:e389:: with SMTP id a131mr1203482wmh.181.1601575046340;
        Thu, 01 Oct 2020 10:57:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601575046; cv=none;
        d=google.com; s=arc-20160816;
        b=X68WWSIxvKt8JLWE43Vksymkduvmt52Rv0jrXfjPoTFmJXbHBG10jaeYZpoxzlGxNF
         MhnEueN2INnwA2Jbmv+xx6qb5S/ceKXZVeJREYhx8uiZzsdo2XnLRWAFrGkMZE9geKV0
         EyHxmv6hNzYfYdNqc5GvgoxLXYeSAk1ByJd+t8wu896FWg9y1ZdjemzfTyjIzv2tw14C
         PGQrYWLrdHXrsbPNOKNStGsPCVHFpw9UdR9svQ062pDz6yWpiDkTYuOLBG8f6xDY+s3h
         RL3dIX3b5bXrIRGlSV5ZyHYffaZzwwN/NFKzpqF6q+xNmIjplJ6zh+nwjFmUaRV4bKE6
         Yyqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NrXP5K1QAOK1ooEoF09QcxyxzBvczwzY+6+OVR8Sv6k=;
        b=QmMakD9woT+C5Oduk2fF3TJb/kPUWzoGYBs25Wwkt0kVoD10PDJCMsy+kLU5rG82m2
         ZvEUAiq/uoTIWVjhDmYAFtpyjBLr6tjuibxg27fLaW2NUhuGlR1shMRcXuu9xuUUrNaO
         +GhTcUcDmaZNYHj8vJ7sZ9pu/RnTRAr3lbZlqppZRVi5xhTL5Np7PzDrbo1C5SLwVIFG
         TMO5t6ZQjgApqfa79d23pkxcXVkROlYkXMZKLt0skHe97BEu4Da78IhCzSGnypmfP/Ic
         bJK/6BElSY1wzrl+/UHedkpkzlCHwtar1JFRh9jY31AQIofmJf+eqm6ZHMLOVmjv0ym0
         9BXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ftzp9vYt;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id 24si27823wmg.1.2020.10.01.10.57.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:57:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id k10so6846226wru.6
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:57:26 -0700 (PDT)
X-Received: by 2002:adf:dd82:: with SMTP id x2mr10956498wrl.419.1601575045792;
        Thu, 01 Oct 2020 10:57:25 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id j10sm10054494wrn.2.2020.10.01.10.57.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:57:25 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:57:19 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
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
Subject: Re: [PATCH v3 22/39] kasan: introduce CONFIG_KASAN_HW_TAGS
Message-ID: <20201001175719.GR4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <76937ee6e88d0d1fc98003e503f31fe7b14a6a52.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <76937ee6e88d0d1fc98003e503f31fe7b14a6a52.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ftzp9vYt;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> This patch adds a configuration option for a new KASAN mode called
> hardware tag-based KASAN. This mode uses the memory tagging approach
> like the software tag-based mode, but relies on arm64 Memory Tagging
> Extension feature for tag management and access checking.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
> ---
>  lib/Kconfig.kasan | 59 ++++++++++++++++++++++++++++++++---------------
>  1 file changed, 41 insertions(+), 18 deletions(-)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index b4cf6c519d71..516d3a24f7d7 100644
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
> @@ -20,11 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
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
> -	select SLUB_DEBUG if SLUB

See my comment in the other patch about moving this line again.

>  	select CONSTRUCTORS
>  	select STACKDEPOT
>  	help
> @@ -38,17 +41,23 @@ choice
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
> +
> +	  All KASAN modes are strictly debugging features.
>  
> -	  Both generic and tag-based KASAN are strictly debugging features.
> +	  For better error reports enable CONFIG_STACKTRACE.
>  
>  config KASAN_GENERIC
>  	bool "Generic mode"
>  	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
> +	select SLUB_DEBUG if SLUB
>  	help
>  	  Enables generic KASAN mode.
>  
> @@ -61,20 +70,21 @@ config KASAN_GENERIC
>  	  and introduces an overhead of ~x1.5 for the rest of the allocations.
>  	  The performance slowdown is ~x3.
>  
> -	  For better error detection enable CONFIG_STACKTRACE.
> -
>  	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>  	  (the resulting kernel does not boot).
>  
>  config KASAN_SW_TAGS
>  	bool "Software tag-based mode"
>  	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
> +	select SLUB_DEBUG if SLUB
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
> @@ -82,15 +92,27 @@ config KASAN_SW_TAGS
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
> @@ -114,6 +136,7 @@ endchoice
>  
>  config KASAN_STACK_ENABLE
>  	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> +	depends on KASAN_GENERIC || KASAN_SW_TAGS
>  	help
>  	  The LLVM stack address sanitizer has a know problem that
>  	  causes excessive stack usage in a lot of functions, see
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001175719.GR4162920%40elver.google.com.
