Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLNG5GJQMGQEQORI2FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id F3373521471
	for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 13:57:34 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id bp17-20020a056512159100b00472631eb445sf7149002lfb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 04:57:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652183854; cv=pass;
        d=google.com; s=arc-20160816;
        b=SqVLHRGqChrjtvsMcAmRbT87DLgfM3joAOch2xDQ1acVVvDftfO+7nqgFG3J2wLy3h
         FjNZDkoqusiPWaRzRgBDS4axSWaVHuS/Y+XPbk1tGrBd4vmjvhNcAAfVvCRI3F6XAWHB
         YSbrtoi+UyVt8PXsBW3vCOURl4VctUrlwFIbovtiuk8dgBALsGqlvYlmkmveFdcR4C5p
         lzHM6gapPC5FvNj55/acbhL4pwdeV9V5hoh3Biq5/ch400OCip0Ohe4V2tS0AfCghxDm
         6VDYhbPAENTIcgk8ei+MIVz0m3ZG+q7EQtbAo5KtlvElcyBBtL9sZvyjkl5hUwWnoAg7
         W4XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ATHNbmEuVVDACQ7u2vKC4qqTTsrZzxfl+ydmEeTSwQE=;
        b=JoqdUmryZQcQ+at77LpPNTLyfskjm6gEbJC303C8Bj41oD40awPNNMXsLmA57oEq60
         edEJKmYw1WmYksKBGCfzm3j5YZ0iMNqNhD6rz/RsLQ0KB1VG7HH/8EHQ/lVgNTX45rK0
         UD8u8Gf/s4cnFrbS4Zb+YCsF00Zf/RJ8D2vecHhph4wOQJgTGoZ+nd0Np5JtjXdE2+JL
         FheWBZQFFvnXvxQ6vZUdz574rwOEIQyBolyilskYEKUWueVg3kpeEP4X/19/kF9y5VU9
         GYm0k8hkzTeQVXBe++9Pa/AHEsMOYoC51bmgUYpH74iv4AhSZ8YLr9ikJ/VjOHt0JpcJ
         6f5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W1Per8Y5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ATHNbmEuVVDACQ7u2vKC4qqTTsrZzxfl+ydmEeTSwQE=;
        b=Xi5BznC5tIyrGHLQDKaJ3EhNJb9Bfwviw67oU+QIn980rMbAk5CUSk8gIVCU7/GQx2
         IspREp2+ZOZQZoiFM7l6Dl4z2NKUy1bOc3Kt4RP83o+rpTxZonb/fYfiqNtBpy1ObW89
         p4WfOqQ2PxcxMD9B3BJ3wSxcRgs0hqX+op+8I0RROjiMu+pdsJmCbVjKFsD4VWsXXubE
         IB36wRM3+GhOjzvPeiWy+ATSnBs+c+SGMD5vM/7vFmmD5wDtZbtOciidZ4LxGUPOBPmN
         nZZ2MiDc00mtYaydqgJVE5AQ5kYdVqTdHedzp2oxLgI5afsVOYIlh7Uvbagw7TSYoGJo
         SAew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ATHNbmEuVVDACQ7u2vKC4qqTTsrZzxfl+ydmEeTSwQE=;
        b=4oIibdK2M0ZVSwTW7lunVrH8/uqgb95CZZMETwN0o239SSeiWuMq45G0Gl9RRGxMrn
         ya1sT0Rll3kdIfLwxXWzeV1AW94ptrf30XuAB05OYsIuzJYs0aEJDZEPhkrfmvrtZHvY
         HhhphlIfZdYmGMW2xtma+H6dGPzmjkuGJyjP+6DvDGKNRASgTLBQKVJ52aGWF3nwDLXZ
         lCbotwYNlj64egt+cSJ1Zy3Bkpf9jvOibTgtmVtBXWRn3oyiyJKApkzmnVKys9CoSvYj
         7v2/OFyw2QDgX+BtjuFQbeI8AdEQUOrbR1wDjpvGBIzYguU13W6zHcciWozyxij2KdkQ
         loHQ==
X-Gm-Message-State: AOAM531/uh2e26llDL38SlngHWYUAHYfx0RDsmeFBGtF8lcJew/wxKMJ
	HhaYQyxNWhiLq3FGkkv0h68=
X-Google-Smtp-Source: ABdhPJy3BJ6jP/bVI7EqmuW2+F7SzAUClWrzzHRkMwkhzHAR/3pnDLqn7WNTrYnMRZEOAAR/fgWSRg==
X-Received: by 2002:a05:6512:10d5:b0:473:dddb:6b20 with SMTP id k21-20020a05651210d500b00473dddb6b20mr16462187lfg.7.1652183854180;
        Tue, 10 May 2022 04:57:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a782:0:b0:250:5cd7:50da with SMTP id c2-20020a2ea782000000b002505cd750dals3492446ljf.11.gmail;
 Tue, 10 May 2022 04:57:32 -0700 (PDT)
X-Received: by 2002:a05:651c:10a9:b0:250:bbb8:823e with SMTP id k9-20020a05651c10a900b00250bbb8823emr8515417ljn.371.1652183852659;
        Tue, 10 May 2022 04:57:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652183852; cv=none;
        d=google.com; s=arc-20160816;
        b=KwRhH1wxc2ojPF18Lc6yJztJLDOrZ6I+vQnjCYRSr0USYU2QMXgo1EtCbcBNz4Y9k+
         C+83ipHdRUuHUnEJ6CmS2Ehjl9hgz2ax4yNVjPAkrqIEuNsoOv4dI/eJOXgwVe9TwJof
         V5s5syvo4woOf5TVaTltPuZbqZazNiZ3Qu5argtSui6sr3mKlMSlhHZ/IuvCffNq4YdW
         7UiE+eVLDPQsvszRG5HloXT8FKa6Ep01mcQEhhrNztmwgQlz3kAL2xgW8yfe+R2oGBr6
         BTRwoY466HqMbU1MjQoTug7P8rtAw1rRrIfuzk+VnY7CVL1KEoVLacxPvvXj4GULhPH1
         Hc5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/m0glBNNCVKw7fvlcpkMEkUOHFdiKfYATAc+fdZIDDw=;
        b=GbSWZzGq/wLcE6KdQlaOnw9F9Tuei3ktr95NKNmVnUCxTVFC9MrI4ik/tYbzM2ifbo
         0wS0bnAFjFQ+S8QZEeS/yjy8CYcTeNcCaAt2LW684+s3lARSxDXHenAdfpX0GFMq7AKp
         ifqRKkO3i5oaQ6RdeLo8j8QNouYwV5XZiYzhAd0HRn6cfx0+EGCy8lE2jyBc8OMcH3zY
         Km7/UiNM3mFzPVOw6JVeXStVEEVdf7KjM3aNV+UcTBdmIZxPg39vVUyJJrd60DkBiXQG
         4CuUCMDY3520cqGbGbOOBZ/8tFuOFbUuWPsR5Q+Hv+4q3vMmgv6QEorho4iVl0Yq6c1k
         C3bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W1Per8Y5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id v22-20020a05651203b600b0047208583d26si719146lfp.11.2022.05.10.04.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 May 2022 04:57:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id k2so23456523wrd.5
        for <kasan-dev@googlegroups.com>; Tue, 10 May 2022 04:57:32 -0700 (PDT)
X-Received: by 2002:a5d:56c8:0:b0:20a:d4a1:94de with SMTP id m8-20020a5d56c8000000b0020ad4a194demr17994567wrw.268.1652183851987;
        Tue, 10 May 2022 04:57:31 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:640f:aa66:3ec8:cbb6])
        by smtp.gmail.com with ESMTPSA id x18-20020adfdd92000000b0020c5253d915sm13491130wrl.97.2022.05.10.04.57.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 May 2022 04:57:31 -0700 (PDT)
Date: Tue, 10 May 2022 13:57:25 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 3/3] kasan: clean-up kconfig options descriptions
Message-ID: <YnpTJR177vJ5G+HW@elver.google.com>
References: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
 <47afaecec29221347bee49f58c258ac1ced3b429.1652123204.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <47afaecec29221347bee49f58c258ac1ced3b429.1652123204.git.andreyknvl@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=W1Per8Y5;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as
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

On Mon, May 09, 2022 at 09:07PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Various readability clean-ups of KASAN Kconfig options.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

But see further (not in this patch) suggestion for improvement below.

> ---
>  lib/Kconfig.kasan | 168 ++++++++++++++++++++++------------------------
>  1 file changed, 82 insertions(+), 86 deletions(-)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 1f3e620188a2..f0973da583e0 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -1,4 +1,5 @@
>  # SPDX-License-Identifier: GPL-2.0-only
> +
>  # This config refers to the generic KASAN mode.
>  config HAVE_ARCH_KASAN
>  	bool
> @@ -15,9 +16,8 @@ config HAVE_ARCH_KASAN_VMALLOC
>  config ARCH_DISABLE_KASAN_INLINE
>  	bool
>  	help
> -	  An architecture might not support inline instrumentation.
> -	  When this option is selected, inline and stack instrumentation are
> -	  disabled.
> +	  Disables both inline and stack instrumentation. Selected by
> +	  architectures that do not support these instrumentation types.
>  
>  config CC_HAS_KASAN_GENERIC
>  	def_bool $(cc-option, -fsanitize=kernel-address)
> @@ -26,13 +26,13 @@ config CC_HAS_KASAN_SW_TAGS
>  	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
>  
>  # This option is only required for software KASAN modes.
> -# Old GCC versions don't have proper support for no_sanitize_address.
> +# Old GCC versions do not have proper support for no_sanitize_address.
>  # See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=89124 for details.
>  config CC_HAS_WORKING_NOSANITIZE_ADDRESS
>  	def_bool !CC_IS_GCC || GCC_VERSION >= 80300
>  
>  menuconfig KASAN
> -	bool "KASAN: runtime memory debugger"
> +	bool "KASAN: dynamic memory safety error detector"
>  	depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
>  		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
>  		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
> @@ -40,10 +40,13 @@ menuconfig KASAN
>  	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
>  	select STACKDEPOT_ALWAYS_INIT
>  	help
> -	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
> -	  designed to find out-of-bounds accesses and use-after-free bugs.
> +	  Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
> +	  error detector designed to find out-of-bounds and use-after-free bugs.
> +
>  	  See Documentation/dev-tools/kasan.rst for details.
>  
> +	  For better error reports, also enable CONFIG_STACKTRACE.
> +
>  if KASAN
>  
>  choice
> @@ -51,75 +54,71 @@ choice
>  	default KASAN_GENERIC
>  	help
>  	  KASAN has three modes:
> -	  1. generic KASAN (similar to userspace ASan,
> -	     x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
> -	  2. software tag-based KASAN (arm64 only, based on software
> -	     memory tagging (similar to userspace HWASan), enabled with
> -	     CONFIG_KASAN_SW_TAGS), and
> -	  3. hardware tag-based KASAN (arm64 only, based on hardware
> -	     memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
>  
> -	  All KASAN modes are strictly debugging features.
> +	  1. Generic KASAN (supported by many architectures, enabled with
> +	     CONFIG_KASAN_GENERIC, similar to userspace ASan),
> +	  2. Software Tag-Based KASAN (arm64 only, based on software memory
> +	     tagging, enabled with CONFIG_KASAN_SW_TAGS, similar to userspace
> +	     HWASan), and
> +	  3. Hardware Tag-Based KASAN (arm64 only, based on hardware memory
> +	     tagging, enabled with CONFIG_KASAN_HW_TAGS).
>  
> -	  For better error reports enable CONFIG_STACKTRACE.
> +	  See Documentation/dev-tools/kasan.rst for details about each mode.
>  
>  config KASAN_GENERIC
> -	bool "Generic mode"
> +	bool "Generic KASAN"
>  	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
>  	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
>  	select SLUB_DEBUG if SLUB
>  	select CONSTRUCTORS
>  	help
> -	  Enables generic KASAN mode.
> +	  Enables Generic KASAN.
>  
> -	  This mode is supported in both GCC and Clang. With GCC it requires
> -	  version 8.3.0 or later. Any supported Clang version is compatible,
> -	  but detection of out-of-bounds accesses for global variables is
> -	  supported only since Clang 11.
> +	  Requires GCC 8.3.0+ or Clang.
>  
> -	  This mode consumes about 1/8th of available memory at kernel start
> -	  and introduces an overhead of ~x1.5 for the rest of the allocations.
> +	  Consumes about 1/8th of available memory at kernel start and adds an
> +	  overhead of ~50% for dynamic allocations.
>  	  The performance slowdown is ~x3.
>  
> -	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> -	  (the resulting kernel does not boot).
> +	  (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)

Why aren't they made mutually exclusive via Kconfig constraints? Does it
work these days?

Either KASAN_GENERIC and KASAN_SW_TAGS do "depends on !DEBUG_SLAB ||
COMPILE_TEST", or DEBUG_SLAB does "depends on !(KASAN_GENERIC || KASAN_SW_TAGS) || COMPILE_TEST".

I feel DEBUG_SLAB might not be used very much these days, so perhaps
DEBUG_SLAB should add the constraint, also given KASAN is the better
debugging aid.

>  config KASAN_SW_TAGS
> -	bool "Software tag-based mode"
> +	bool "Software Tag-Based KASAN"
>  	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
>  	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
>  	select SLUB_DEBUG if SLUB
>  	select CONSTRUCTORS
>  	help
> -	  Enables software tag-based KASAN mode.
> +	  Enables Software Tag-Based KASAN.
>  
> -	  This mode require software memory tagging support in the form of
> -	  HWASan-like compiler instrumentation.
> +	  Requires GCC 11+ or Clang.
>  
> -	  Currently this mode is only implemented for arm64 CPUs and relies on
> -	  Top Byte Ignore. This mode requires Clang.
> +	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
>  
> -	  This mode consumes about 1/16th of available memory at kernel start
> -	  and introduces an overhead of ~20% for the rest of the allocations.
> -	  This mode may potentially introduce problems relating to pointer
> -	  casting and comparison, as it embeds tags into the top byte of each
> -	  pointer.
> +	  Consumes about 1/16th of available memory at kernel start and
> +	  add an overhead of ~20% for dynamic allocations.
>  
> -	  Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
> -	  (the resulting kernel does not boot).
> +	  May potentially introduce problems related to pointer casting and
> +	  comparison, as it embeds a tag into the top byte of each pointer.
> +
> +	  (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)
>  
>  config KASAN_HW_TAGS
> -	bool "Hardware tag-based mode"
> +	bool "Hardware Tag-Based KASAN"
>  	depends on HAVE_ARCH_KASAN_HW_TAGS
>  	depends on SLUB
>  	help
> -	  Enables hardware tag-based KASAN mode.
> +	  Enables Hardware Tag-Based KASAN.
> +
> +	  Requires GCC 10+ or Clang 12+.
>  
> -	  This mode requires hardware memory tagging support, and can be used
> -	  by any architecture that provides it.
> +	  Supported only on arm64 CPUs starting from ARMv8.5 and relies on
> +	  Memory Tagging Extension and Top Byte Ignore.
>  
> -	  Currently this mode is only implemented for arm64 CPUs starting from
> -	  ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
> +	  Consumes about 1/32nd of available memory.
> +
> +	  May potentially introduce problems related to pointer casting and
> +	  comparison, as it embeds a tag into the top byte of each pointer.
>  
>  endchoice
>  
> @@ -131,83 +130,80 @@ choice
>  config KASAN_OUTLINE
>  	bool "Outline instrumentation"
>  	help
> -	  Before every memory access compiler insert function call
> -	  __asan_load*/__asan_store*. These functions performs check
> -	  of shadow memory. This is slower than inline instrumentation,
> -	  however it doesn't bloat size of kernel's .text section so
> -	  much as inline does.
> +	  Makes the compiler insert function calls that check whether the memory
> +	  is accessible before each memory access. Slower than KASAN_INLINE, but
> +	  does not bloat the size of the kernel's .text section so much.
>  
>  config KASAN_INLINE
>  	bool "Inline instrumentation"
>  	depends on !ARCH_DISABLE_KASAN_INLINE
>  	help
> -	  Compiler directly inserts code checking shadow memory before
> -	  memory accesses. This is faster than outline (in some workloads
> -	  it gives about x2 boost over outline instrumentation), but
> -	  make kernel's .text size much bigger.
> +	  Makes the compiler directly insert memory accessibility checks before
> +	  each memory access. Faster than KASAN_OUTLINE (gives ~x2 boost for
> +	  some workloads), but makes the kernel's .text size much bigger.
>  
>  endchoice
>  
>  config KASAN_STACK
> -	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> +	bool "Stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>  	depends on KASAN_GENERIC || KASAN_SW_TAGS
>  	depends on !ARCH_DISABLE_KASAN_INLINE
>  	default y if CC_IS_GCC
>  	help
> -	  The LLVM stack address sanitizer has a know problem that
> -	  causes excessive stack usage in a lot of functions, see
> -	  https://bugs.llvm.org/show_bug.cgi?id=38809
> -	  Disabling asan-stack makes it safe to run kernels build
> -	  with clang-8 with KASAN enabled, though it loses some of
> -	  the functionality.
> -	  This feature is always disabled when compile-testing with clang
> -	  to avoid cluttering the output in stack overflow warnings,
> -	  but clang users can still enable it for builds without
> -	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
> -	  to use and enabled by default.
> -	  If the architecture disables inline instrumentation, stack
> -	  instrumentation is also disabled as it adds inline-style
> -	  instrumentation that is run unconditionally.
> +	  Disables stack instrumentation and thus KASAN's ability to detect
> +	  out-of-bounds bugs in stack variables.
> +
> +	  With Clang, stack instrumentation has a problem that causes excessive
> +	  stack usage, see https://bugs.llvm.org/show_bug.cgi?id=38809. Thus,
> +	  with Clang, this option is deemed unsafe.
> +
> +	  This option is always disabled when compile-testing with Clang to
> +	  avoid cluttering the log with stack overflow warnings.
> +
> +	  With GCC, enabling stack instrumentation is assumed to be safe.
> +
> +	  If the architecture disables inline instrumentation via
> +	  ARCH_DISABLE_KASAN_INLINE, stack instrumentation gets disabled
> +	  as well, as it adds inline-style instrumentation that is run
> +	  unconditionally.
>  
>  config KASAN_TAGS_IDENTIFY
> -	bool "Enable memory corruption identification"
> +	bool "Memory corruption type identification"
>  	depends on KASAN_SW_TAGS || KASAN_HW_TAGS
>  	help
> -	  This option enables best-effort identification of bug type
> -	  (use-after-free or out-of-bounds) at the cost of increased
> -	  memory consumption.
> +	  Enables best-effort identification of the bug types (use-after-free
> +	  or out-of-bounds) at the cost of increased memory consumption.
> +	  Only applicable for the tag-based KASAN modes.
>  
>  config KASAN_VMALLOC
>  	bool "Check accesses to vmalloc allocations"
>  	depends on HAVE_ARCH_KASAN_VMALLOC
>  	help
> -	  This mode makes KASAN check accesses to vmalloc allocations for
> -	  validity.
> +	  Makes KASAN check the validity of accesses to vmalloc allocations.
>  
> -	  With software KASAN modes, checking is done for all types of vmalloc
> -	  allocations. Enabling this option leads to higher memory usage.
> +	  With software KASAN modes, all types vmalloc allocations are
> +	  checked. Enabling this option leads to higher memory usage.
>  
> -	  With hardware tag-based KASAN, only VM_ALLOC mappings are checked.
> -	  There is no additional memory usage.
> +	  With Hardware Tag-Based KASAN, only non-executable VM_ALLOC mappings
> +	  are checked. There is no additional memory usage.
>  
>  config KASAN_KUNIT_TEST
>  	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
>  	depends on KASAN && KUNIT
>  	default KUNIT_ALL_TESTS
>  	help
> -	  This is a KUnit test suite doing various nasty things like
> -	  out of bounds and use after free accesses. It is useful for testing
> -	  kernel debugging features like KASAN.
> +	  A KUnit-based KASAN test suite. Triggers different kinds of
> +	  out-of-bounds and use-after-free accesses. Useful for testing whether
> +	  KASAN can detect certain bug types.
>  
>  	  For more information on KUnit and unit tests in general, please refer
> -	  to the KUnit documentation in Documentation/dev-tools/kunit.
> +	  to the KUnit documentation in Documentation/dev-tools/kunit/.
>  
>  config KASAN_MODULE_TEST
>  	tristate "KUnit-incompatible tests of KASAN bug detection capabilities"
>  	depends on m && KASAN && !KASAN_HW_TAGS
>  	help
> -	  This is a part of the KASAN test suite that is incompatible with
> -	  KUnit. Currently includes tests that do bad copy_from/to_user
> -	  accesses.
> +	  A part of the KASAN test suite that is not integrated with KUnit.
> +	  Incompatible with Hardware Tag-Based KASAN.
>  
>  endif # KASAN
> -- 
> 2.25.1
> 
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/47afaecec29221347bee49f58c258ac1ced3b429.1652123204.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YnpTJR177vJ5G%2BHW%40elver.google.com.
