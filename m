Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVVWWOGAMGQEZJFGS4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id DF48F44D3A6
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 09:59:02 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 205-20020a1c00d6000000b003335d1384f1sf1507537wma.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 00:59:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636621142; cv=pass;
        d=google.com; s=arc-20160816;
        b=SP+i0fArcMFMieBNdoUt6JVRb4PYLZuGPOXZqfkcr9XvI/Qs2ETBkx3aQwe3b4hz8z
         76V5nOe61IsQ5Lj4rINarJvQ+E2w8M91PNwH+1a1MJyEhNMiVlAJQWnxChFmjQZxUDG3
         dICcBozrvLMrhUQvRvZPVaTQvd7xx4H8FICyDG9HaYLDUUzXH/2Y2/YvIKuGP1i7bIlc
         58hu2Bdkovg7EkQ6Qw3/ACMyuuzLgTx1I+35VaRt6k/zttqEVzPAuR7GaTJfH3A38NFd
         F7XNyl1LjOTf/FBGweKfAHVk544vgyLOtwaAJR0KrS3qHDVyW5bIiVAQ1lTWHNaQGSDU
         607w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=XfpKLhYsMqzOfdvUusmhhSJAdzKH06MPHXTDrn7jFWA=;
        b=xCp6rijpF32Ult1wUF1ByZwc/+5bo6G+cEKMIXZH0MS7kMTS6nWCVDIpEOfp1NV9/l
         1ltPOgDWLP0x5OsjuW8BcW9lMmqUCBjqF4vVPvDh+jwWBzRgihPQ6IoHNlAQ4ZFHCc1z
         uYf7H08ncKQjJK4xM1Y39hAzNDi03/lu+Q6J/A5ZzOK9tQb/hJaUtDFnbpzydkTEt78H
         8Ciq0HLKVsOUwtusqVohNJs50TJJHEHxwHGkAU2JKq928RXRkLVu1vQ7FOgIo2IdfWZK
         rMiplH0XwaHhu0cOmXjgOY8M6xiltm482sYBDqcFps1VelcwBtX4E7KWDiAmeQPwjBgg
         plKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ow2WLWo0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XfpKLhYsMqzOfdvUusmhhSJAdzKH06MPHXTDrn7jFWA=;
        b=cnDWhONeh7nfkeKJDI6x3OF6Mzr89Or3rTB6pkl6yGeAj8HzmUEZvcwpn/ehSZB7yM
         u14bNDAk0U6PSTCD9HpQ9RXxDEGG6ZQJiwvB0b2KvuuBOF/1vAnDTfrhfZkY5PyY62Wo
         gC7yg6p3MTnVWxdEyTaSRlHlxZViL6XwSwRqjH/rvCPIeazxRZqTsNUqgxVr7fYHwdr5
         aPFhaE/Sg4TkHL/EoXNlDOf/HjylfVbpCoWAFBW+xEwyo+kmlgJm3DRFaxaiuzrqEk3a
         AX26nbjFWFd4f2nfhnaWCburpReHeF5ZZL4CO3m9UOCf3YpAZFG9pZw2B9TNKDR+FjlX
         tzww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XfpKLhYsMqzOfdvUusmhhSJAdzKH06MPHXTDrn7jFWA=;
        b=liIrr9m9xqLpkATTuponO1vKroBGdTraC4oxbii/BE3pSvErkG/pBfDF6fslnNMM3I
         pDdCUYWru0M6+Z7jMJM7/YIkTLnKyqraX3X9NUTp7Bl+J6+QWeRke4nfzbAW/TpbaSAv
         fhTgPeC/x3owzdk1p7U7yjTJI2uA0oUGk0JZ+z2NhYqlfPidpfMUcsNTfbEu7L39/eJE
         FZ1i/eT/N2jfUVQPblowpnrJnXpWzT+fTKuekjVyGUkDKNBJOCrmcfdtN5i37oz4l7pu
         IhYz0dwM/JqzZYyOpirYptv2CkfSHT1mMBg/EcPaUXXWW+gilJHVNTr1EDafArzF67pn
         QaFg==
X-Gm-Message-State: AOAM5338WPwEpcPFsNB8GMU1oJ2tgxNnLgbq0m5JIp69KtdbMk0bkHnI
	D8BHe5Y1tbYa4wxFV79fB48=
X-Google-Smtp-Source: ABdhPJyRpbhdLNL2DhSnHaIKX1GMzeRlKPJk6MBqFNZ0Prh4h9W9C023ofkvqE2EPtPs3HmGM1KcqA==
X-Received: by 2002:a7b:cbc3:: with SMTP id n3mr6528163wmi.15.1636621142662;
        Thu, 11 Nov 2021 00:59:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8b:: with SMTP id n11ls4522663wms.2.canary-gmail;
 Thu, 11 Nov 2021 00:59:01 -0800 (PST)
X-Received: by 2002:a1c:e906:: with SMTP id q6mr24033572wmc.126.1636621141714;
        Thu, 11 Nov 2021 00:59:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636621141; cv=none;
        d=google.com; s=arc-20160816;
        b=Cwa8Ul7QeUOdKmCDA3o1dYcTKFobN8xIVq7LfrRHHY8sdQWTdruyqpvHgy0Y5G2ONK
         Qj+N+S/4TlEDvbcXMLL66rqAW+Z9PRrC5FbUyT0edQysR97nFglMXqn9kiyokPYHFN2d
         bzApcTelOr5VIyRfD6ngXjNfm1G57QReagabS8lVZij2BgOXDza+VUhz+karz3sv6C3u
         V5741bHtGY3j9gMS3ODLMZCcsPJXIqCpWN6HQITpuxIXFPoumoJcdg5xoUTx6r1Ctak/
         90kpwUzQ35zlUG4v2+iAHCZZ3KOr6AyW/ml1kApMi7LhUN77F4pcfxni6vnvO+wFRJZW
         eQ/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KE0Q6DOV6GHSl4Ouk9hbWg9wbGXQ6gt7NPW0dQOJ5po=;
        b=YTn7ieiG+nBpgDYA721ciQixaPjMHC7GvzRPwTIfLEVIApH4xxvD0ge73fHn9EfymB
         99BSQfyC1dYqpC43YaDpuGQ607sicKO1xKQuxcGfGOLcViy+c/u93BOSNfGmj0HPxYTH
         IsovzSyrr8Ot8bhid5/OurZ7+puVx3QKF2eWLcqQluxXGqIdvbLBIbE0XGBKWx6fA7qH
         1H01y+84IZDqhwCmNw4hjCcIaPMuT8vlnKejhC/vwDuYO4rAJdy0nNxZwn6xNlILXeHA
         fqnwoJHrM1Dx8qmDQovne5X3gyyXXx5AyOtquLWDbwmOsXT+6mcT0l1E223RG0JgnMgF
         RIuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ow2WLWo0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id s138si738227wme.1.2021.11.11.00.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Nov 2021 00:59:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id t30so8530405wra.10
        for <kasan-dev@googlegroups.com>; Thu, 11 Nov 2021 00:59:01 -0800 (PST)
X-Received: by 2002:a05:6000:1010:: with SMTP id a16mr6841303wrx.155.1636621141247;
        Thu, 11 Nov 2021 00:59:01 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:fd21:69cc:1f2b:9812])
        by smtp.gmail.com with ESMTPSA id m36sm2258925wms.25.2021.11.11.00.59.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Nov 2021 00:59:00 -0800 (PST)
Date: Thu, 11 Nov 2021 09:58:54 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Valentin Schneider <valentin.schneider@arm.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>, Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v2 1/5] preempt: Restore preemption model selection
 configs
Message-ID: <YYzbTvrNQTUhgrWW@elver.google.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
 <20211110202448.4054153-2-valentin.schneider@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211110202448.4054153-2-valentin.schneider@arm.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ow2WLWo0;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as
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

On Wed, Nov 10, 2021 at 08:24PM +0000, Valentin Schneider wrote:
> Commit c597bfddc9e9 ("sched: Provide Kconfig support for default dynamic
> preempt mode") changed the selectable config names for the preemption
> model. This means a config file must now select
> 
>   CONFIG_PREEMPT_BEHAVIOUR=y
> 
> rather than
> 
>   CONFIG_PREEMPT=y
> 
> to get a preemptible kernel. This means all arch config files would need to
> be updated - right now they'll all end up with the default
> CONFIG_PREEMPT_NONE_BEHAVIOUR.
> 
> Rather than touch a good hundred of config files, restore usage of
> CONFIG_PREEMPT{_NONE, _VOLUNTARY}. Make them configure:
> o The build-time preemption model when !PREEMPT_DYNAMIC
> o The default boot-time preemption model when PREEMPT_DYNAMIC
> 
> Add siblings of those configs with the _BUILD suffix to unconditionally
> designate the build-time preemption model (PREEMPT_DYNAMIC is built with
> the "highest" preemption model it supports, aka PREEMPT). Downstream
> configs should by now all be depending / selected by CONFIG_PREEMPTION
> rather than CONFIG_PREEMPT, so only a few sites need patching up.
> 
> Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>

Acked-by: Marco Elver <elver@google.com>

Much better, thank you!

> ---
>  include/linux/kernel.h   |  2 +-
>  include/linux/vermagic.h |  2 +-
>  init/Makefile            |  2 +-
>  kernel/Kconfig.preempt   | 42 ++++++++++++++++++++--------------------
>  kernel/sched/core.c      |  6 +++---
>  5 files changed, 27 insertions(+), 27 deletions(-)
> 
> diff --git a/include/linux/kernel.h b/include/linux/kernel.h
> index 2776423a587e..9c7d774ef809 100644
> --- a/include/linux/kernel.h
> +++ b/include/linux/kernel.h
> @@ -88,7 +88,7 @@
>  struct completion;
>  struct user;
>  
> -#ifdef CONFIG_PREEMPT_VOLUNTARY
> +#ifdef CONFIG_PREEMPT_VOLUNTARY_BUILD
>  
>  extern int __cond_resched(void);
>  # define might_resched() __cond_resched()
> diff --git a/include/linux/vermagic.h b/include/linux/vermagic.h
> index 1eaaa93c37bf..329d63babaeb 100644
> --- a/include/linux/vermagic.h
> +++ b/include/linux/vermagic.h
> @@ -15,7 +15,7 @@
>  #else
>  #define MODULE_VERMAGIC_SMP ""
>  #endif
> -#ifdef CONFIG_PREEMPT
> +#ifdef CONFIG_PREEMPT_BUILD
>  #define MODULE_VERMAGIC_PREEMPT "preempt "
>  #elif defined(CONFIG_PREEMPT_RT)
>  #define MODULE_VERMAGIC_PREEMPT "preempt_rt "
> diff --git a/init/Makefile b/init/Makefile
> index 2846113677ee..04eeee12c076 100644
> --- a/init/Makefile
> +++ b/init/Makefile
> @@ -30,7 +30,7 @@ $(obj)/version.o: include/generated/compile.h
>  quiet_cmd_compile.h = CHK     $@
>        cmd_compile.h = \
>  	$(CONFIG_SHELL) $(srctree)/scripts/mkcompile_h $@	\
> -	"$(UTS_MACHINE)" "$(CONFIG_SMP)" "$(CONFIG_PREEMPT)"	\
> +	"$(UTS_MACHINE)" "$(CONFIG_SMP)" "$(CONFIG_PREEMPT_BUILD)"	\
>  	"$(CONFIG_PREEMPT_RT)" $(CONFIG_CC_VERSION_TEXT) "$(LD)"
>  
>  include/generated/compile.h: FORCE
> diff --git a/kernel/Kconfig.preempt b/kernel/Kconfig.preempt
> index 60f1bfc3c7b2..ce77f0265660 100644
> --- a/kernel/Kconfig.preempt
> +++ b/kernel/Kconfig.preempt
> @@ -1,12 +1,23 @@
>  # SPDX-License-Identifier: GPL-2.0-only
>  
> +config PREEMPT_NONE_BUILD
> +	bool
> +
> +config PREEMPT_VOLUNTARY_BUILD
> +	bool
> +
> +config PREEMPT_BUILD
> +	bool
> +	select PREEMPTION
> +	select UNINLINE_SPIN_UNLOCK if !ARCH_INLINE_SPIN_UNLOCK
> +
>  choice
>  	prompt "Preemption Model"
> -	default PREEMPT_NONE_BEHAVIOUR
> +	default PREEMPT_NONE
>  
> -config PREEMPT_NONE_BEHAVIOUR
> +config PREEMPT_NONE
>  	bool "No Forced Preemption (Server)"
> -	select PREEMPT_NONE if !PREEMPT_DYNAMIC
> +	select PREEMPT_NONE_BUILD if !PREEMPT_DYNAMIC
>  	help
>  	  This is the traditional Linux preemption model, geared towards
>  	  throughput. It will still provide good latencies most of the
> @@ -18,10 +29,10 @@ config PREEMPT_NONE_BEHAVIOUR
>  	  raw processing power of the kernel, irrespective of scheduling
>  	  latencies.
>  
> -config PREEMPT_VOLUNTARY_BEHAVIOUR
> +config PREEMPT_VOLUNTARY
>  	bool "Voluntary Kernel Preemption (Desktop)"
>  	depends on !ARCH_NO_PREEMPT
> -	select PREEMPT_VOLUNTARY if !PREEMPT_DYNAMIC
> +	select PREEMPT_VOLUNTARY_BUILD if !PREEMPT_DYNAMIC
>  	help
>  	  This option reduces the latency of the kernel by adding more
>  	  "explicit preemption points" to the kernel code. These new
> @@ -37,10 +48,10 @@ config PREEMPT_VOLUNTARY_BEHAVIOUR
>  
>  	  Select this if you are building a kernel for a desktop system.
>  
> -config PREEMPT_BEHAVIOUR
> +config PREEMPT
>  	bool "Preemptible Kernel (Low-Latency Desktop)"
>  	depends on !ARCH_NO_PREEMPT
> -	select PREEMPT
> +	select PREEMPT_BUILD
>  	help
>  	  This option reduces the latency of the kernel by making
>  	  all kernel code (that is not executing in a critical section)
> @@ -58,7 +69,7 @@ config PREEMPT_BEHAVIOUR
>  
>  config PREEMPT_RT
>  	bool "Fully Preemptible Kernel (Real-Time)"
> -	depends on EXPERT && ARCH_SUPPORTS_RT && !PREEMPT_DYNAMIC
> +	depends on EXPERT && ARCH_SUPPORTS_RT
>  	select PREEMPTION
>  	help
>  	  This option turns the kernel into a real-time kernel by replacing
> @@ -75,17 +86,6 @@ config PREEMPT_RT
>  
>  endchoice
>  
> -config PREEMPT_NONE
> -	bool
> -
> -config PREEMPT_VOLUNTARY
> -	bool
> -
> -config PREEMPT
> -	bool
> -	select PREEMPTION
> -	select UNINLINE_SPIN_UNLOCK if !ARCH_INLINE_SPIN_UNLOCK
> -
>  config PREEMPT_COUNT
>         bool
>  
> @@ -95,8 +95,8 @@ config PREEMPTION
>  
>  config PREEMPT_DYNAMIC
>  	bool "Preemption behaviour defined on boot"
> -	depends on HAVE_PREEMPT_DYNAMIC
> -	select PREEMPT
> +	depends on HAVE_PREEMPT_DYNAMIC && !PREEMPT_RT
> +	select PREEMPT_BUILD
>  	default y
>  	help
>  	  This option allows to define the preemption model on the kernel
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index f2611b9cf503..97047aa7b6c2 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -6625,13 +6625,13 @@ __setup("preempt=", setup_preempt_mode);
>  static void __init preempt_dynamic_init(void)
>  {
>  	if (preempt_dynamic_mode == preempt_dynamic_undefined) {
> -		if (IS_ENABLED(CONFIG_PREEMPT_NONE_BEHAVIOUR)) {
> +		if (IS_ENABLED(CONFIG_PREEMPT_NONE)) {
>  			sched_dynamic_update(preempt_dynamic_none);
> -		} else if (IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY_BEHAVIOUR)) {
> +		} else if (IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)) {
>  			sched_dynamic_update(preempt_dynamic_voluntary);
>  		} else {
>  			/* Default static call setting, nothing to do */
> -			WARN_ON_ONCE(!IS_ENABLED(CONFIG_PREEMPT_BEHAVIOUR));
> +			WARN_ON_ONCE(!IS_ENABLED(CONFIG_PREEMPT));
>  			preempt_dynamic_mode = preempt_dynamic_full;
>  			pr_info("Dynamic Preempt: full\n");
>  		}
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YYzbTvrNQTUhgrWW%40elver.google.com.
