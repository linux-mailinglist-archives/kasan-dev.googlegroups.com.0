Return-Path: <kasan-dev+bncBDV37XP3XYDRBM7R3TUQKGQEWKKJIGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E21D571D08
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2019 18:41:23 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id f24sf4142814lfj.17
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2019 09:41:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563900083; cv=pass;
        d=google.com; s=arc-20160816;
        b=RUKKo4UX19a9guqTDeHzyPrW/t3P0FgdCdd38Hr44tNP4Uw946i6p29tbpI9vBI2kd
         abYNotGMkQsbui9Iz0luNuxblEDLnrp1i6lG0z/cFG/8kBbCVX8dmpiBtR8gJasVMEhT
         aVPkbnvaPyjonWnnAeY0S3fFR8Xo6SVGEHD2yRPi02R9h74O/s36TPPIwV0wMB0U5FsG
         GwvsxKy+pah8iESONbxWf1EERkDEdSm4iuNGXmO/PDxncWZqEfKhS8UDbNLjc5GGYJ3g
         e8Ozckk0VFwwc68LVED06ppwlpqhPJxaVvDwKE2J8JLQa51FQ8yG6ugkgzJk66JmIS7O
         KueA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=qF99ZmJf2szn/rrpCy3l0KsokeSIMyIMQiKiK9b9Omc=;
        b=Q4ia+RCGQBxp7ijaWLozmum+g38LwleyCENEjhoOgs+7HDces33iy/qeqkGH28u7Mg
         DOhz5PKut16thldWeXpZX3/Bsrz3zzqdDEkERWnakxiclbHH8ydHKqdlckVsZTJaRoHp
         ZiISdOu/udgkrwpAIPswydI37so66slTUZvwRpZOWaE8UrCZwW+EFHgBQyBq+oCjJUwF
         2Nd6QUtp3xnz0Fpwh15evUr6ErsXreFYlPrlRZHMLPq5DVHWcAeuAGXhneQcTRcWytEj
         oSfBj5VVAjncyJ57f7p0j7/sCw9kPIZ2lzfbQbDQ7BleF2kJ5zYDfqOB+IdIUL95p4Wy
         TJ8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qF99ZmJf2szn/rrpCy3l0KsokeSIMyIMQiKiK9b9Omc=;
        b=EoeIGHRilNrcne25s/GczXr+igD12n1TtrTbyCrMSCOI88xYRFPn1x+nuXeZGfZx+I
         h17yGDAWDJo4uHtNb8N6B43DAKYMe2x9fGJJ/Nrrf12z7O6i16rbfcQWCvcxwFCWlaqj
         U6ZCqcY41q+i5uLP7uvGe8b52EVXApXDllJ2aJi8Uafj994webU/K7S1kUGJhegEe54m
         oaSjgw7vQiWU5itPl4FqAv+28u+vFvgDAnEZLjyoeP/8q66BRe9v4w4WPRHel1PK6xDE
         tfkTjJPmiXlq9R3sPlMDIXFEz6V1C2ujTg/Jv3Aojr9DoJh11mGYn9aGns2pUrzSqnOZ
         3vFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qF99ZmJf2szn/rrpCy3l0KsokeSIMyIMQiKiK9b9Omc=;
        b=mVWTgx+3Fiw1rvRQw424f+2gXg33+LP8hgeVWEvotWqVtPR1t4nVFKG4L6CM3UplsS
         m2LGTNPTwiUL7RX9uc8fADocXPXDkh95FDmHaTnd6MptA0zOcMmTdAg1rK1NP52FD3LG
         GuwOCoilKJ3iLgBB3kqdVnx/+pdNkxNXWf49+oEZdESv4Evn6xVs4ZhEq+QOhyWk2IUJ
         NMbLgJKOv8Sy8iukPiJqbHz0NFpK0E5e+bTYN5XJQ3Smw5iSrpY1lMZh3oF+CSSTMZ6c
         oYq16YvNOJ9p8BP2ocCgtJVnDy0QmhrW+hiwjUijL7jqNkQGI0rE61S17d4QTEFsvUf7
         lrvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFPHC1Catt0HGiFjme0XnyqFmXuF8njY0ETgLuiIOZg9iLY0+0
	JNKecdpN2XXv5U8FJSGNweY=
X-Google-Smtp-Source: APXvYqy4ILiDRDQThsMGAcyC7GDMeUhWBcy6tJr23LOsma9Kfk6LBnIxcJ1cLnszudb0NR7l6p1Y4A==
X-Received: by 2002:a19:c514:: with SMTP id w20mr36009433lfe.182.1563900083460;
        Tue, 23 Jul 2019 09:41:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:96d5:: with SMTP id d21ls4941635ljj.16.gmail; Tue, 23
 Jul 2019 09:41:22 -0700 (PDT)
X-Received: by 2002:a2e:8816:: with SMTP id x22mr41877835ljh.131.1563900082798;
        Tue, 23 Jul 2019 09:41:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563900082; cv=none;
        d=google.com; s=arc-20160816;
        b=hnDOq1RD0Ax9kJw98W2MDknbSSzbsgAph8OSaqcDuiqh34SWGiJAemUL+eHpIzvxTv
         dmcIM7QI4UvY87df/5XR7jXmNED95Yb4B93lnqjtCFISR9+xEr1ljV5jjm8SKmkIaavm
         2iB7yrkLx03/jjrHckwsjpksMC/XTL5G/WeFIF2Se+sMstr+AVb9ZuYW6IQx77kJLdbp
         73BVarMqc9oF7XJ6UkBCbh87oDkWb/8q+PpERNQ6MJ7D0FbAAJUgyiDuK81aPfeuU91v
         CnWkTzcOSLT6yJIkVCXm/f4oxMli8rkUhZPNGblY0cJv5N3QgfCGXlrXt+5P0mNSW8Dr
         v9dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=CWX87h+Ok9E97o55gY6nn+kgeIPA0nmVYXdmyOIRyCY=;
        b=RWzJKY4Muh7BAJql9c2IPZ9t/uuFmCkMEZzIOHJ4mu71envY64taIG5+RvFPcKtWoL
         2PcgwK+xVgUGy+WZqAYtP/XXVe1baMYaRIXWbY2JM6nSZCKy2XY4Hsjlj5S4udP6ig0i
         PPiT6Ugg0Ou2tOQPqL/AT9HSVlD87W1AFJm8DVoK+Ioyr5Fkyn2Ung97YbDNIN4naK+R
         EP9nGEgBTXeNMZyf/Poz6oNBBiBRsKLMifSW5bVhHxJcKcCulBHVTNl2cGmn4/+zgVNl
         KeV2urg4MakRo0WrVizOjcAE7VzsPJdQddLkobUCL96RWhlGGZXfcI27i4/imxdzv7gL
         V65w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s14si2497080ljg.4.2019.07.23.09.41.21
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Jul 2019 09:41:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E3C0B337;
	Tue, 23 Jul 2019 09:41:19 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3A13E3F71A;
	Tue, 23 Jul 2019 09:41:18 -0700 (PDT)
Date: Tue, 23 Jul 2019 17:41:16 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Zijlstra <peterz@infradead.org>, x86@kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/2] kernel/fork: Add support for stack-end guard page
Message-ID: <20190723164115.GB56959@lakrids.cambridge.arm.com>
References: <20190719132818.40258-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190719132818.40258-1-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Jul 19, 2019 at 03:28:17PM +0200, Marco Elver wrote:
> Enabling STACK_GUARD_PAGE helps catching kernel stack overflows immediately
> rather than causing difficult-to-diagnose corruption. Note that, unlike
> virtually-mapped kernel stacks, this will effectively waste an entire page of
> memory; however, this feature may provide extra protection in cases that cannot
> use virtually-mapped kernel stacks, at the cost of a page.
> 
> The motivation for this patch is that KASAN cannot use virtually-mapped kernel
> stacks to detect stack overflows. An alternative would be implementing support
> for vmapped stacks in KASAN, but would add significant extra complexity.

Do we have an idea as to how much additional complexity?

> While the stack-end guard page approach here wastes a page, it is
> significantly simpler than the alternative.  We assume that the extra
> cost of a page can be justified in the cases where STACK_GUARD_PAGE
> would be enabled.
> 
> Note that in an earlier prototype of this patch, we used
> 'set_memory_{ro,rw}' functions, which flush the TLBs. This, however,
> turned out to be unacceptably expensive, especially when run with
> fuzzers such as Syzkaller, as the kernel would encounter frequent RCU
> timeouts. The current approach of not flushing the TLB is therefore
> best-effort, but works in the test cases considered -- any comments on
> better alternatives or improvements are welcome.

Ouch. I don't think that necessarily applies to other architectures, and
from my PoV it would be nicer if we could rely on regular vmap'd stacks.
That way we have one code path, and we can rely on the fault.

> 
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Ingo Molnar <mingo@redhat.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: "H. Peter Anvin" <hpa@zytor.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: x86@kernel.org
> Cc: linux-kernel@vger.kernel.org
> Cc: kasan-dev@googlegroups.com
> ---
>  arch/Kconfig                         | 15 +++++++++++++++
>  arch/x86/include/asm/page_64_types.h |  8 +++++++-
>  include/linux/sched/task_stack.h     | 11 +++++++++--
>  kernel/fork.c                        | 22 +++++++++++++++++++++-
>  4 files changed, 52 insertions(+), 4 deletions(-)
> 
> diff --git a/arch/Kconfig b/arch/Kconfig
> index e8d19c3cb91f..cca3258fff1f 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -935,6 +935,21 @@ config LOCK_EVENT_COUNTS
>  	  the chance of application behavior change because of timing
>  	  differences. The counts are reported via debugfs.
>  
> +config STACK_GUARD_PAGE
> +	default n
> +	bool "Use stack-end page as guard page"
> +	depends on !VMAP_STACK && ARCH_HAS_SET_DIRECT_MAP && THREAD_INFO_IN_TASK && !STACK_GROWSUP
> +	help
> +	  Enable this if you want to use the stack-end page as a guard page.
> +	  This causes kernel stack overflows to be caught immediately rather
> +	  than causing difficult-to-diagnose corruption. Note that, unlike
> +	  virtually-mapped kernel stacks, this will effectively waste an entire
> +	  page of memory; however, this feature may provide extra protection in
> +	  cases that cannot use virtually-mapped kernel stacks, at the cost of
> +	  a page. Note that, this option does not implicitly increase the
> +	  default stack size. The main use-case is for KASAN to avoid reporting
> +	  misleading bugs due to stack overflow.

These dependencies can also be satisfied on arm64, but I don't believe
this will work correctly there, and we'll need something like a
ARCH_HAS_STACK_GUARD_PAGE symbol so that x86 can opt-in.

On arm64 our exception vectors don't specify an alternative stack, so we
don't have a direct equivalent to x86 double-fault handler. Our kernel
stack overflow handling requires explicit tests in the entry assembly
that are only built (or valid) when VMAP_STACK is selected.

> +
>  source "kernel/gcov/Kconfig"
>  
>  source "scripts/gcc-plugins/Kconfig"
> diff --git a/arch/x86/include/asm/page_64_types.h b/arch/x86/include/asm/page_64_types.h
> index 288b065955b7..b218b5713c02 100644
> --- a/arch/x86/include/asm/page_64_types.h
> +++ b/arch/x86/include/asm/page_64_types.h
> @@ -12,8 +12,14 @@
>  #define KASAN_STACK_ORDER 0
>  #endif
>  
> +#ifdef CONFIG_STACK_GUARD_PAGE
> +#define STACK_GUARD_SIZE PAGE_SIZE
> +#else
> +#define STACK_GUARD_SIZE 0
> +#endif
> +
>  #define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
> -#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
> +#define THREAD_SIZE  ((PAGE_SIZE << THREAD_SIZE_ORDER) - STACK_GUARD_SIZE)

I'm pretty sure that common code relies on THREAD_SIZE being a
power-of-two. I also know that if we wanted to enable this on arm64 that
would very likely be a requirement.

For example, in kernel/trace/trace_stack.c we have:

| this_size = ((unsigned long)stack) & (THREAD_SIZE-1);

... and INIT_TASK_DATA() allocates the initial task stack using
THREAD_SIZE, so that may require special care, as it might not be sized
or aligned as you expect.

>  
>  #define EXCEPTION_STACK_ORDER (0 + KASAN_STACK_ORDER)
>  #define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)
> diff --git a/include/linux/sched/task_stack.h b/include/linux/sched/task_stack.h
> index 2413427e439c..7ee86ad0a282 100644
> --- a/include/linux/sched/task_stack.h
> +++ b/include/linux/sched/task_stack.h
> @@ -11,6 +11,13 @@
>  
>  #ifdef CONFIG_THREAD_INFO_IN_TASK
>  
> +#ifndef STACK_GUARD_SIZE
> +#ifdef CONFIG_STACK_GUARD_PAGE
> +#error "Architecture not compatible with STACK_GUARD_PAGE"
> +#endif
> +#define STACK_GUARD_SIZE 0
> +#endif

The core code you add assumes that when enabled, this is PAGE_SIZE, so
I think the definition should live in a common header.

As above, it should not be possible to select CONFIG_STACK_GUARD_PAGE
unless the architecture supports it. If nothing else, this avoids
getting bug reports on randconfigs.

Thanks,
Mark.

> +
>  /*
>   * When accessing the stack of a non-current task that might exit, use
>   * try_get_task_stack() instead.  task_stack_page will return a pointer
> @@ -18,14 +25,14 @@
>   */
>  static inline void *task_stack_page(const struct task_struct *task)
>  {
> -	return task->stack;
> +	return task->stack + STACK_GUARD_SIZE;
>  }
>  
>  #define setup_thread_stack(new,old)	do { } while(0)
>  
>  static inline unsigned long *end_of_stack(const struct task_struct *task)
>  {
> -	return task->stack;
> +	return task->stack + STACK_GUARD_SIZE;
>  }
>  
>  #elif !defined(__HAVE_THREAD_FUNCTIONS)
> diff --git a/kernel/fork.c b/kernel/fork.c
> index d8ae0f1b4148..22033b03f7da 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -94,6 +94,7 @@
>  #include <linux/livepatch.h>
>  #include <linux/thread_info.h>
>  #include <linux/stackleak.h>
> +#include <linux/set_memory.h>
>  
>  #include <asm/pgtable.h>
>  #include <asm/pgalloc.h>
> @@ -249,6 +250,14 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>  					     THREAD_SIZE_ORDER);
>  
>  	if (likely(page)) {
> +		if (IS_ENABLED(CONFIG_STACK_GUARD_PAGE)) {
> +			/*
> +			 * Best effort: do not flush TLB to avoid the overhead
> +			 * of flushing all TLBs.
> +			 */
> +			set_direct_map_invalid_noflush(page);
> +		}
> +
>  		tsk->stack = page_address(page);
>  		return tsk->stack;
>  	}
> @@ -258,6 +267,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>  
>  static inline void free_thread_stack(struct task_struct *tsk)
>  {
> +	struct page* stack_page;
>  #ifdef CONFIG_VMAP_STACK
>  	struct vm_struct *vm = task_stack_vm_area(tsk);
>  
> @@ -285,7 +295,17 @@ static inline void free_thread_stack(struct task_struct *tsk)
>  	}
>  #endif
>  
> -	__free_pages(virt_to_page(tsk->stack), THREAD_SIZE_ORDER);
> +	stack_page = virt_to_page(tsk->stack);
> +
> +	if (IS_ENABLED(CONFIG_STACK_GUARD_PAGE)) {
> +		/*
> +		 * Avoid flushing TLBs, and instead rely on spurious fault
> +		 * detection of stale TLBs.
> +		 */
> +		set_direct_map_default_noflush(stack_page);
> +	}
> +
> +	__free_pages(stack_page, THREAD_SIZE_ORDER);
>  }
>  # else
>  static struct kmem_cache *thread_stack_cache;
> -- 
> 2.22.0.657.g960e92d24f-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190723164115.GB56959%40lakrids.cambridge.arm.com.
