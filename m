Return-Path: <kasan-dev+bncBCS4VDMYRUNBBTUVVGGQMGQEQB7RNCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 66B30467BC4
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 17:50:24 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id x9-20020a056a00188900b0049fd22b9a27sf2235868pfh.18
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 08:50:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638550222; cv=pass;
        d=google.com; s=arc-20160816;
        b=PVbScxnhoVLbIFXkPg+5txDYmLIhN5iYAbz0xgVrYjncrq34vQwSPwq7NXdXZ+Vffn
         /+NnrbOF2DID3ATYRe9FnnfnAvQVrvEu/BSozl/s6lQ9hg4iDkKFCCLvNijJwmrG+NkG
         DAScf872nMwxMhvJNJi69aWv5Mr/GML84RyIDwwo1K0LFoCzYcL1kzoviSOH2+c0z7mL
         1f1Ki6Mjcgi+FizZPZtcsfSAYRWVUeNmm+WGNgXE78CsmJeJfKb5O6pdqOUlX1xHEhHP
         j/qS8OH6VhJXsbQ1KhTmpoeP+XtMcOBIpkRKU2U9sU3YBM0Y1bsEPW759jdUs/ptYHl1
         B0Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=jezqMSEltVDLV6iiDlpsrZw6yUbgHw4sAT/0cZzYDeA=;
        b=Ro75hw6L7GYkQTKZW/2S705vwRO+WQAVYbYVWfMOVS/pnnyP7VojS6msYiO+GcUeM5
         fcyn4gCuWcWCtErh0X+yRFWFAxIzBvxaQcKhnDCeDhDkeUKuiSCtTcqdSNau1CMzlWud
         8tKzoDyWtPmFcc7aaUWxSEdnEJqw7inxAMWtHhxMMs83hnexvi0nBpackxD+MzJDTfBS
         CSsdxiczTtPFHH8CUfUBb8hDC06Z0+YGQ9yXTuckl3RxeBXn9xKvEdksXt/LIZCzH+XZ
         9LwyJ8lyuKdfyuA/ueHvbmO4u5tF+jcLGeMUOshZhpc2nQhPx+kzLZqrIqEUyCIQX5+J
         HNRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=COwM0Fwa;
       spf=pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jezqMSEltVDLV6iiDlpsrZw6yUbgHw4sAT/0cZzYDeA=;
        b=SCypT8JfNWsvi6fduS4ts67pHYqYOkpYI9EEZMwCMzEONLAKwIWEZPV302tEaNMe9/
         JzttBadMp7nxKcZIl+wjukB0OTYxMzEIhTFycRYb8C0H39gUmAZVCNaXmRZPJOurAhd6
         T2ThARz8qbwLXjRYoQZiGx4swRi2u53PJ2by4MyUkN/gqVrHa1pUzi7P3q6swOC7lWpG
         pUrbyN4kK+29a5+RjQsx9FN48SYtLfpN1C8emeAPX/kNmZhskUl7KXim9stX4rCylN04
         IX1FJUPaUVvDoNBhaiGVI2O2A292NumeWYFUZ0kg2ClrqQjRgAgB7pd3XnUAdFUdq1wn
         nxrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jezqMSEltVDLV6iiDlpsrZw6yUbgHw4sAT/0cZzYDeA=;
        b=Zqfx/j4czlJu6Hfea7jQJDlY3YmiXAP1iZwwbWzYdK5P0r4BnnaJiZ423+MwQW7brs
         Tw1e3F7AV8vF3z/YzKB9aVQNUo9A9PoN1KdjM7TujqJpDs5lIE0U5wDE9RC0Bu+qGpic
         VgnaJNAqHfbm2iQmg1rioPmukbPmenLFrLUHKyDVgvk27WluDPvtKw0PObFUEP7PddOR
         bzq+bsQklcvL5v92S0V9pkYVrzcHcifriHiuvEXE+IY4sf6VvNTvgA9maJP6ag35+UTR
         z8Xd6vNGqBv4Io7JYSXQlIaK+/zMN+C6eG+n83TFoncnSbKCzIvei6TjrPDut2vRmq8L
         czgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SHhCs2yV5tI6FkoP81g9Ul18GC7uoBHu+5S+xWk66V8MFIb3D
	KFZhmhdxyI2fTP/eyKNOZ7o=
X-Google-Smtp-Source: ABdhPJwS/RZ2DohuocxE8SBcBjtG3KWDIV9mtYIwMah0Q+28r28OuMWfgaaLGzPwPxCOEKn9IInjOQ==
X-Received: by 2002:a65:6a0b:: with SMTP id m11mr5393113pgu.372.1638550222704;
        Fri, 03 Dec 2021 08:50:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6002:: with SMTP id y2ls4561468pji.1.gmail; Fri, 03
 Dec 2021 08:50:21 -0800 (PST)
X-Received: by 2002:a17:90b:1e51:: with SMTP id pi17mr15517050pjb.245.1638550221608;
        Fri, 03 Dec 2021 08:50:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638550221; cv=none;
        d=google.com; s=arc-20160816;
        b=et1nwmGkuQ20ENqJptfl8zycybv/jNUqE1mZYFdYlvJztmvMrj8GoJS9TKMosENZp1
         H0vsYKEH3bwbMEWZdSoJYEi5ER8BW8JkFNzalohfM3eACQGV2Udr2wso6AsGPLLA94gF
         b09+FdPZXmGgG0qDbtH27d+zzhEd2TKLsyHveRfWYvtUe5R1kOY/n0Ur9i0klQJF1hVv
         vaHMB5JtV5RXXHsBCbJMSD8Bc9uGmtrsf2Fa916bE3+zm43Cb8RP9eTUnnULY/nnrcEo
         W8BlbzmHYDEZWRXWgAoLnJ1p4GmAKYVFjZ6xoGaSpJQIrNXTGN1iEhcFx8nh/SKugrWl
         ysAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=mME6iD0r/1PvXbEJ8MIi1mo8SRq46W2sCptqvDagdtg=;
        b=uWLHHlS7UiX/zj6RUwY1XSvlYYcTmpA9upiajjSNQWYag+E5F55uxNO4vSP8XyGWSf
         2amrabEZo3Rr5tDhLWByMNvggu4wLAIKXvRUQd6lhUD4P6WxnFQE8FLIDzp/uclXSVZV
         2beeRIueGPet0x0E93qju1SODtPjZysHDivz0hHeEplLYKy3QAfmLgnRiXLQiiokiy3a
         f6anr4D3sbI/IPpHnFVu0qOdI+8UaMQ9WpGACVIyR9IJdNMS34x7dqedPw1tF53J/NRF
         EJVPUleZi0kaAp34Ts2FTHwc80h6nGRzyfbSIdDcSrx3gQ0ENU9HJv6K571/cMyknxa6
         sEVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=COwM0Fwa;
       spf=pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id x31si365169pfh.5.2021.12.03.08.50.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Dec 2021 08:50:21 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 0B29462B37;
	Fri,  3 Dec 2021 16:50:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6B076C53FAD;
	Fri,  3 Dec 2021 16:50:20 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 370875C02A9; Fri,  3 Dec 2021 08:50:20 -0800 (PST)
Date: Fri, 3 Dec 2021 08:50:20 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 04/25] kcsan: Add core support for a subset of weak
 memory modeling
Message-ID: <20211203165020.GR641268@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-5-elver@google.com>
 <YanbzWyhR0LwdinE@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YanbzWyhR0LwdinE@elver.google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=COwM0Fwa;       spf=pass
 (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Dec 03, 2021 at 09:56:45AM +0100, Marco Elver wrote:
> On Tue, Nov 30, 2021 at 12:44PM +0100, Marco Elver wrote:
> [...]
> > v3:
> > * Remove kcsan_noinstr hackery, since we now try to avoid adding any
> >   instrumentation to .noinstr.text in the first place.
> [...]
> 
> I missed some cleanups after changes from v2 to v3 -- the below cleanup
> is missing.
> 
> Full replacement patch attached.

I pulled this into -rcu with the other patches from your v3 post, thank
you all!

							Thanx, Paul

> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 2254cb75cbb0..916060913966 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -12,7 +12,6 @@
>  #include <linux/delay.h>
>  #include <linux/export.h>
>  #include <linux/init.h>
> -#include <linux/instrumentation.h>
>  #include <linux/kernel.h>
>  #include <linux/list.h>
>  #include <linux/moduleparam.h>
> @@ -21,8 +20,6 @@
>  #include <linux/sched.h>
>  #include <linux/uaccess.h>
>  
> -#include <asm/sections.h>
> -
>  #include "encoding.h"
>  #include "kcsan.h"
>  #include "permissive.h"
> @@ -1086,9 +1083,7 @@ noinline void __tsan_func_entry(void *call_pc)
>  	if (!IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
>  		return;
>  
> -	instrumentation_begin();
>  	add_kcsan_stack_depth(1);
> -	instrumentation_end();
>  }
>  EXPORT_SYMBOL(__tsan_func_entry);
>  
> @@ -1100,7 +1095,6 @@ noinline void __tsan_func_exit(void)
>  	if (!IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
>  		return;
>  
> -	instrumentation_begin();
>  	reorder_access = get_reorder_access(get_ctx());
>  	if (!reorder_access)
>  		goto out;
> @@ -1120,7 +1114,6 @@ noinline void __tsan_func_exit(void)
>  	}
>  out:
>  	add_kcsan_stack_depth(-1);
> -	instrumentation_end();
>  }
>  EXPORT_SYMBOL(__tsan_func_exit);
>  

> >From 7ac337afb7bec3cc5c5bd5e4155b08bdb554bc7d Mon Sep 17 00:00:00 2001
> From: Marco Elver <elver@google.com>
> Date: Thu, 5 Aug 2021 14:57:45 +0200
> Subject: [PATCH v4 04/25] kcsan: Add core support for a subset of weak memory
>  modeling
> 
> Add support for modeling a subset of weak memory, which will enable
> detection of a subset of data races due to missing memory barriers.
> 
> KCSAN's approach to detecting missing memory barriers is based on
> modeling access reordering, and enabled if `CONFIG_KCSAN_WEAK_MEMORY=y`,
> which depends on `CONFIG_KCSAN_STRICT=y`. The feature can be enabled or
> disabled at boot and runtime via the `kcsan.weak_memory` boot parameter.
> 
> Each memory access for which a watchpoint is set up, is also selected
> for simulated reordering within the scope of its function (at most 1
> in-flight access).
> 
> We are limited to modeling the effects of "buffering" (delaying the
> access), since the runtime cannot "prefetch" accesses (therefore no
> acquire modeling). Once an access has been selected for reordering, it
> is checked along every other access until the end of the function scope.
> If an appropriate memory barrier is encountered, the access will no
> longer be considered for reordering.
> 
> When the result of a memory operation should be ordered by a barrier,
> KCSAN can then detect data races where the conflict only occurs as a
> result of a missing barrier due to reordering accesses.
> 
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v4:
> * Remove redundant instrumentation_begin/end() now that kcsan_noinstr no
>   longer exists.
> 
> v3:
> * Remove kcsan_noinstr hackery, since we now try to avoid adding any
>   instrumentation to .noinstr.text in the first place.
> * Restrict config WEAK_MEMORY to only be enabled with tooling where
>   we actually remove instrumentation from noinstr.
> * Don't define kcsan_weak_memory bool if !KCSAN_WEAK_MEMORY.
> 
> v2:
> * Define kcsan_noinstr as noinline if we rely on objtool nop'ing out
>   calls, to avoid things like LTO inlining it.
> ---
>  include/linux/kcsan-checks.h |  10 +-
>  include/linux/kcsan.h        |  10 +-
>  include/linux/sched.h        |   3 +
>  kernel/kcsan/core.c          | 202 ++++++++++++++++++++++++++++++++---
>  lib/Kconfig.kcsan            |  20 ++++
>  scripts/Makefile.kcsan       |   9 +-
>  6 files changed, 235 insertions(+), 19 deletions(-)
> 
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 5f5965246877..a1c6a89fde71 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -99,7 +99,15 @@ void kcsan_set_access_mask(unsigned long mask);
>  
>  /* Scoped access information. */
>  struct kcsan_scoped_access {
> -	struct list_head list;
> +	union {
> +		struct list_head list; /* scoped_accesses list */
> +		/*
> +		 * Not an entry in scoped_accesses list; stack depth from where
> +		 * the access was initialized.
> +		 */
> +		int stack_depth;
> +	};
> +
>  	/* Access information. */
>  	const volatile void *ptr;
>  	size_t size;
> diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
> index 13cef3458fed..c07c71f5ba4f 100644
> --- a/include/linux/kcsan.h
> +++ b/include/linux/kcsan.h
> @@ -49,8 +49,16 @@ struct kcsan_ctx {
>  	 */
>  	unsigned long access_mask;
>  
> -	/* List of scoped accesses. */
> +	/* List of scoped accesses; likely to be empty. */
>  	struct list_head scoped_accesses;
> +
> +#ifdef CONFIG_KCSAN_WEAK_MEMORY
> +	/*
> +	 * Scoped access for modeling access reordering to detect missing memory
> +	 * barriers; only keep 1 to keep fast-path complexity manageable.
> +	 */
> +	struct kcsan_scoped_access reorder_access;
> +#endif
>  };
>  
>  /**
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 78c351e35fec..0cd40b010487 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1339,6 +1339,9 @@ struct task_struct {
>  #ifdef CONFIG_TRACE_IRQFLAGS
>  	struct irqtrace_events		kcsan_save_irqtrace;
>  #endif
> +#ifdef CONFIG_KCSAN_WEAK_MEMORY
> +	int				kcsan_stack_depth;
> +#endif
>  #endif
>  
>  #if IS_ENABLED(CONFIG_KUNIT)
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index bd359f8ee63a..481f8a524089 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -40,6 +40,13 @@ module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
>  module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
>  module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);
>  
> +#ifdef CONFIG_KCSAN_WEAK_MEMORY
> +static bool kcsan_weak_memory = true;
> +module_param_named(weak_memory, kcsan_weak_memory, bool, 0644);
> +#else
> +#define kcsan_weak_memory false
> +#endif
> +
>  bool kcsan_enabled;
>  
>  /* Per-CPU kcsan_ctx for interrupts */
> @@ -351,6 +358,67 @@ void kcsan_restore_irqtrace(struct task_struct *task)
>  #endif
>  }
>  
> +static __always_inline int get_kcsan_stack_depth(void)
> +{
> +#ifdef CONFIG_KCSAN_WEAK_MEMORY
> +	return current->kcsan_stack_depth;
> +#else
> +	BUILD_BUG();
> +	return 0;
> +#endif
> +}
> +
> +static __always_inline void add_kcsan_stack_depth(int val)
> +{
> +#ifdef CONFIG_KCSAN_WEAK_MEMORY
> +	current->kcsan_stack_depth += val;
> +#else
> +	BUILD_BUG();
> +#endif
> +}
> +
> +static __always_inline struct kcsan_scoped_access *get_reorder_access(struct kcsan_ctx *ctx)
> +{
> +#ifdef CONFIG_KCSAN_WEAK_MEMORY
> +	return ctx->disable_scoped ? NULL : &ctx->reorder_access;
> +#else
> +	return NULL;
> +#endif
> +}
> +
> +static __always_inline bool
> +find_reorder_access(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size,
> +		    int type, unsigned long ip)
> +{
> +	struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);
> +
> +	if (!reorder_access)
> +		return false;
> +
> +	/*
> +	 * Note: If accesses are repeated while reorder_access is identical,
> +	 * never matches the new access, because !(type & KCSAN_ACCESS_SCOPED).
> +	 */
> +	return reorder_access->ptr == ptr && reorder_access->size == size &&
> +	       reorder_access->type == type && reorder_access->ip == ip;
> +}
> +
> +static inline void
> +set_reorder_access(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size,
> +		   int type, unsigned long ip)
> +{
> +	struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);
> +
> +	if (!reorder_access || !kcsan_weak_memory)
> +		return;
> +
> +	reorder_access->ptr		= ptr;
> +	reorder_access->size		= size;
> +	reorder_access->type		= type | KCSAN_ACCESS_SCOPED;
> +	reorder_access->ip		= ip;
> +	reorder_access->stack_depth	= get_kcsan_stack_depth();
> +}
> +
>  /*
>   * Pull everything together: check_access() below contains the performance
>   * critical operations; the fast-path (including check_access) functions should
> @@ -389,8 +457,10 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
>  	 * The access_mask check relies on value-change comparison. To avoid
>  	 * reporting a race where e.g. the writer set up the watchpoint, but the
>  	 * reader has access_mask!=0, we have to ignore the found watchpoint.
> +	 *
> +	 * reorder_access is never created from an access with access_mask set.
>  	 */
> -	if (ctx->access_mask)
> +	if (ctx->access_mask && !find_reorder_access(ctx, ptr, size, type, ip))
>  		return;
>  
>  	/*
> @@ -440,11 +510,13 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
>  	atomic_long_t *watchpoint;
>  	u64 old, new, diff;
> -	unsigned long access_mask;
>  	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
> +	bool interrupt_watcher = kcsan_interrupt_watcher;
>  	unsigned long ua_flags = user_access_save();
>  	struct kcsan_ctx *ctx = get_ctx();
> +	unsigned long access_mask = ctx->access_mask;
>  	unsigned long irq_flags = 0;
> +	bool is_reorder_access;
>  
>  	/*
>  	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
> @@ -467,6 +539,17 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  		goto out;
>  	}
>  
> +	/*
> +	 * The local CPU cannot observe reordering of its own accesses, and
> +	 * therefore we need to take care of 2 cases to avoid false positives:
> +	 *
> +	 *	1. Races of the reordered access with interrupts. To avoid, if
> +	 *	   the current access is reorder_access, disable interrupts.
> +	 *	2. Avoid races of scoped accesses from nested interrupts (below).
> +	 */
> +	is_reorder_access = find_reorder_access(ctx, ptr, size, type, ip);
> +	if (is_reorder_access)
> +		interrupt_watcher = false;
>  	/*
>  	 * Avoid races of scoped accesses from nested interrupts (or scheduler).
>  	 * Assume setting up a watchpoint for a non-scoped (normal) access that
> @@ -482,7 +565,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  	 * information is lost if dirtied by KCSAN.
>  	 */
>  	kcsan_save_irqtrace(current);
> -	if (!kcsan_interrupt_watcher)
> +	if (!interrupt_watcher)
>  		local_irq_save(irq_flags);
>  
>  	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> @@ -503,7 +586,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  	 * Read the current value, to later check and infer a race if the data
>  	 * was modified via a non-instrumented access, e.g. from a device.
>  	 */
> -	old = read_instrumented_memory(ptr, size);
> +	old = is_reorder_access ? 0 : read_instrumented_memory(ptr, size);
>  
>  	/*
>  	 * Delay this thread, to increase probability of observing a racy
> @@ -515,8 +598,17 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  	 * Re-read value, and check if it is as expected; if not, we infer a
>  	 * racy access.
>  	 */
> -	access_mask = ctx->access_mask;
> -	new = read_instrumented_memory(ptr, size);
> +	if (!is_reorder_access) {
> +		new = read_instrumented_memory(ptr, size);
> +	} else {
> +		/*
> +		 * Reordered accesses cannot be used for value change detection,
> +		 * because the memory location may no longer be accessible and
> +		 * could result in a fault.
> +		 */
> +		new = 0;
> +		access_mask = 0;
> +	}
>  
>  	diff = old ^ new;
>  	if (access_mask)
> @@ -585,11 +677,20 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  	 */
>  	remove_watchpoint(watchpoint);
>  	atomic_long_dec(&kcsan_counters[KCSAN_COUNTER_USED_WATCHPOINTS]);
> +
>  out_unlock:
> -	if (!kcsan_interrupt_watcher)
> +	if (!interrupt_watcher)
>  		local_irq_restore(irq_flags);
>  	kcsan_restore_irqtrace(current);
>  	ctx->disable_scoped--;
> +
> +	/*
> +	 * Reordered accesses cannot be used for value change detection,
> +	 * therefore never consider for reordering if access_mask is set.
> +	 * ASSERT_EXCLUSIVE are not real accesses, ignore them as well.
> +	 */
> +	if (!access_mask && !is_assert)
> +		set_reorder_access(ctx, ptr, size, type, ip);
>  out:
>  	user_access_restore(ua_flags);
>  }
> @@ -597,7 +698,6 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  static __always_inline void
>  check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
>  {
> -	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
>  	atomic_long_t *watchpoint;
>  	long encoded_watchpoint;
>  
> @@ -608,12 +708,14 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
>  	if (unlikely(size == 0))
>  		return;
>  
> +again:
>  	/*
>  	 * Avoid user_access_save in fast-path: find_watchpoint is safe without
>  	 * user_access_save, as the address that ptr points to is only used to
>  	 * check if a watchpoint exists; ptr is never dereferenced.
>  	 */
> -	watchpoint = find_watchpoint((unsigned long)ptr, size, !is_write,
> +	watchpoint = find_watchpoint((unsigned long)ptr, size,
> +				     !(type & KCSAN_ACCESS_WRITE),
>  				     &encoded_watchpoint);
>  	/*
>  	 * It is safe to check kcsan_is_enabled() after find_watchpoint in the
> @@ -627,9 +729,42 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
>  	else {
>  		struct kcsan_ctx *ctx = get_ctx(); /* Call only once in fast-path. */
>  
> -		if (unlikely(should_watch(ctx, ptr, size, type)))
> +		if (unlikely(should_watch(ctx, ptr, size, type))) {
>  			kcsan_setup_watchpoint(ptr, size, type, ip);
> -		else if (unlikely(ctx->scoped_accesses.prev))
> +			return;
> +		}
> +
> +		if (!(type & KCSAN_ACCESS_SCOPED)) {
> +			struct kcsan_scoped_access *reorder_access = get_reorder_access(ctx);
> +
> +			if (reorder_access) {
> +				/*
> +				 * reorder_access check: simulates reordering of
> +				 * the access after subsequent operations.
> +				 */
> +				ptr = reorder_access->ptr;
> +				type = reorder_access->type;
> +				ip = reorder_access->ip;
> +				/*
> +				 * Upon a nested interrupt, this context's
> +				 * reorder_access can be modified (shared ctx).
> +				 * We know that upon return, reorder_access is
> +				 * always invalidated by setting size to 0 via
> +				 * __tsan_func_exit(). Therefore we must read
> +				 * and check size after the other fields.
> +				 */
> +				barrier();
> +				size = READ_ONCE(reorder_access->size);
> +				if (size)
> +					goto again;
> +			}
> +		}
> +
> +		/*
> +		 * Always checked last, right before returning from runtime;
> +		 * if reorder_access is valid, checked after it was checked.
> +		 */
> +		if (unlikely(ctx->scoped_accesses.prev))
>  			kcsan_check_scoped_accesses();
>  	}
>  }
> @@ -916,19 +1051,56 @@ DEFINE_TSAN_VOLATILE_READ_WRITE(8);
>  DEFINE_TSAN_VOLATILE_READ_WRITE(16);
>  
>  /*
> - * The below are not required by KCSAN, but can still be emitted by the
> - * compiler.
> + * Function entry and exit are used to determine the validty of reorder_access.
> + * Reordering of the access ends at the end of the function scope where the
> + * access happened. This is done for two reasons:
> + *
> + *	1. Artificially limits the scope where missing barriers are detected.
> + *	   This minimizes false positives due to uninstrumented functions that
> + *	   contain the required barriers but were missed.
> + *
> + *	2. Simplifies generating the stack trace of the access.
>   */
>  void __tsan_func_entry(void *call_pc);
> -void __tsan_func_entry(void *call_pc)
> +noinline void __tsan_func_entry(void *call_pc)
>  {
> +	if (!IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
> +		return;
> +
> +	add_kcsan_stack_depth(1);
>  }
>  EXPORT_SYMBOL(__tsan_func_entry);
> +
>  void __tsan_func_exit(void);
> -void __tsan_func_exit(void)
> +noinline void __tsan_func_exit(void)
>  {
> +	struct kcsan_scoped_access *reorder_access;
> +
> +	if (!IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
> +		return;
> +
> +	reorder_access = get_reorder_access(get_ctx());
> +	if (!reorder_access)
> +		goto out;
> +
> +	if (get_kcsan_stack_depth() <= reorder_access->stack_depth) {
> +		/*
> +		 * Access check to catch cases where write without a barrier
> +		 * (supposed release) was last access in function: because
> +		 * instrumentation is inserted before the real access, a data
> +		 * race due to the write giving up a c-s would only be caught if
> +		 * we do the conflicting access after.
> +		 */
> +		check_access(reorder_access->ptr, reorder_access->size,
> +			     reorder_access->type, reorder_access->ip);
> +		reorder_access->size = 0;
> +		reorder_access->stack_depth = INT_MIN;
> +	}
> +out:
> +	add_kcsan_stack_depth(-1);
>  }
>  EXPORT_SYMBOL(__tsan_func_exit);
> +
>  void __tsan_init(void);
>  void __tsan_init(void)
>  {
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index e0a93ffdef30..e4394ea8068b 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -191,6 +191,26 @@ config KCSAN_STRICT
>  	  closely aligns with the rules defined by the Linux-kernel memory
>  	  consistency model (LKMM).
>  
> +config KCSAN_WEAK_MEMORY
> +	bool "Enable weak memory modeling to detect missing memory barriers"
> +	default y
> +	depends on KCSAN_STRICT
> +	# We can either let objtool nop __tsan_func_{entry,exit}() and builtin
> +	# atomics instrumentation in .noinstr.text, or use a compiler that can
> +	# implement __no_kcsan to really remove all instrumentation.
> +	depends on STACK_VALIDATION || CC_IS_GCC
> +	help
> +	  Enable support for modeling a subset of weak memory, which allows
> +	  detecting a subset of data races due to missing memory barriers.
> +
> +	  Depends on KCSAN_STRICT, because the options strenghtening certain
> +	  plain accesses by default (depending on !KCSAN_STRICT) reduce the
> +	  ability to detect any data races invoving reordered accesses, in
> +	  particular reordered writes.
> +
> +	  Weak memory modeling relies on additional instrumentation and may
> +	  affect performance.
> +
>  config KCSAN_REPORT_VALUE_CHANGE_ONLY
>  	bool "Only report races where watcher observed a data value change"
>  	default y
> diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
> index 37cb504c77e1..4c7f0d282e42 100644
> --- a/scripts/Makefile.kcsan
> +++ b/scripts/Makefile.kcsan
> @@ -9,7 +9,12 @@ endif
>  
>  # Keep most options here optional, to allow enabling more compilers if absence
>  # of some options does not break KCSAN nor causes false positive reports.
> -export CFLAGS_KCSAN := -fsanitize=thread \
> -	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
> +kcsan-cflags := -fsanitize=thread -fno-optimize-sibling-calls \
>  	$(call cc-option,$(call cc-param,tsan-compound-read-before-write=1),$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1))) \
>  	$(call cc-param,tsan-distinguish-volatile=1)
> +
> +ifndef CONFIG_KCSAN_WEAK_MEMORY
> +kcsan-cflags += $(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0))
> +endif
> +
> +export CFLAGS_KCSAN := $(kcsan-cflags)
> -- 
> 2.34.0.384.gca35af8252-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211203165020.GR641268%40paulmck-ThinkPad-P17-Gen-1.
