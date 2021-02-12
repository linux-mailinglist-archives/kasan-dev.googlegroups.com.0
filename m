Return-Path: <kasan-dev+bncBCXK7HEV3YBRBV63TGAQMGQEWWSAFHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 52A17319DC4
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 13:00:24 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id l4sf4776485oif.16
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 04:00:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613131223; cv=pass;
        d=google.com; s=arc-20160816;
        b=0oqWUGRrRQHKVTjIcKEmfdAFaOqhKbrjIl0B6HnSlk9GqswK9nvIOjqmQMmTf9wJUS
         FL6dw3ikjfND1sONG4EPOlm7BiFqYNPn/5alliR44oh2Xo5CraviFct2D2wB3pyL8emp
         BloadaGaIw8Mj7LPDZ0wlNbLg7uxbJdbD2G2OzgH1A0rWr4CnT+2oRdUJe3wbfZSFE/N
         g0g4xD+DPj6gFUWCCdraVBLJoD6abcJse2Q9x3l523sFvTwwMQaHx9wnZcsRRHSILkyd
         KgO3vytjjs01UvLNGQyTiz1gKXkI6DZMXnepiBo4obaf4VKgYaU9RbUPQbZY6P/ystdr
         o24Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wlNfh6o7yjoTwhxUv5CfnzK49ARBQyUrmMWWMBYBUvI=;
        b=fvkg5E7VNAXlkis9QhqGtTzfoFVO6jRbNvU9cCu1SJn2YJv0jzgEiEC7N0HQ5RQ1iE
         N/VJYNyYTxWLCxKrpuHaQIUFveMsB+j7W3tMB19YBSbFxG7HZi2fhP0VzJg9V7qtUMRR
         N9MOC7gvN2FDsi+EIOOO6HnZTK20e88/87rPUyRXCtv1/WSrwUD4js3g5ssqUEXfNjVW
         lZQG8/BUrXPEA4wyU0PyWbxzFVavR9m4A04fBLcJ/a4bypoG82Cnz2YM5TySgyue9Qjq
         D+JxpxdGd3W5P9J+0gJYuXVlsOTk4dLgfyB3Q9VFKQnvwuaDauuj92t6Hu57uljx7LLK
         d8vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wlNfh6o7yjoTwhxUv5CfnzK49ARBQyUrmMWWMBYBUvI=;
        b=sUj0ajLJ2kRz8wehZ2uhb/LT29kw98/p6CLy8I2JdGM4Mxyv57Gb9EqdBWoMq7BYCM
         CPSxdSfGLQE1muxmDmdMsd7Sufi0M5CmAa43HeQj3+gBtQ94Ot6OhRwY1p8lwiRCBpeP
         7evsnhzMNYcFDUbH6OzSO0LXqLV2yVRQ3b4CI6/1vcKnhJejBnBwz9ALU31hUWFjJAhj
         PE4YvyecPSccXer7ms0cQ8r9aJ+TtoW9CCennPynWqo2Ar7mc3Nzzc76HHS48VK0ml61
         ncGSazqEkRZw6W5YIbx/GyRchM3a+RoXyWfa7ASCn8tDy4Qq3jVZnXNUxKNXVJEkX1X1
         EV1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wlNfh6o7yjoTwhxUv5CfnzK49ARBQyUrmMWWMBYBUvI=;
        b=fil5zeidCPBHlaWc8zRTa+F+13ndvJNJgf2YV9hrPXlCHGK5scZRFoECkS5tWHufX4
         pPZErnQo3DklLQk4tQgd/KSYYsnMzv48ozqGm/jD6YZ4izJab+e+crVSAQmBv1cgaS/s
         yfJU0vbcGopwAKQqFUWoWcj90P24uBXO5ty1HKI3D2bvZDi9EXVhJN/zKgeTR55a3JXD
         srd4ALAzWvd0JcrG7HTVEzvlcmHpK7cTwnPm7i7MeI+JnsgD1quTHVjcqPjmyW52LXnS
         P/9UZb8tOgge1grEPZGAKP47cKPUMsppcWlAzzAVb5dA4//TkN+OyZtic8BX/2AfR5PP
         Vydw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mJvTupHtoaWi9AjRMomDXiLjFSE4SSVSfG2JzzCCG9cVeW+h/
	n4tQMbrnXkzusz/ypdDXfus=
X-Google-Smtp-Source: ABdhPJx9mCwtRm7N6hPNFrH0EpA55GTGKgK06ZmF8wxXFW39M2WxlsN0Go0/xnUl67jS8YoSdpeg3Q==
X-Received: by 2002:a9d:2c43:: with SMTP id f61mr1670193otb.329.1613131223228;
        Fri, 12 Feb 2021 04:00:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d755:: with SMTP id o82ls2139749oig.2.gmail; Fri, 12 Feb
 2021 04:00:22 -0800 (PST)
X-Received: by 2002:aca:da83:: with SMTP id r125mr1572213oig.127.1613131222841;
        Fri, 12 Feb 2021 04:00:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613131222; cv=none;
        d=google.com; s=arc-20160816;
        b=GeL6hezTrAApErBxSgSiUmlKF6wpn7e4cvnUHIhSl3tFk/bWGPc4vAJOM6z4el5QFU
         DHi+ogMZzQxcIh3lAxlOM2rrT2hj4hPNdILp/FqR4ncHnDgu6fUXkk7ee5phgTgVBpeT
         eVohO1jQJnMDyrGa85+/ISa/FogA2KSU8+bKnmxBbAofdDugmMG1L4L1orJEpmKpwinO
         E6sFz0pxSdNDtlzHVqTtLRo6OTCxnFLIVu0+MkMWKoHk0GGLQRo575yYEa76LL27F5Y7
         fclQSHkyzJWiivrZ1ZOehBrZQ+4A7cLme+1mi5OseHh8ls/k1gDXOyQhtMc3xNoV8Zc+
         qWGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=phzxsFOI+5yGNK0cA4SleoHbv9jgAqHmcgPzwcGgPwc=;
        b=LY/y3oUZqtYWL5Lx9fPwkZE6doEhX7SyaTN0fiFc2UCuRbhohKRZnzWE/iF9v1RVp0
         9OUDiTC7ZLfOL9VZh10A5sGpJ0kZlQSZpwlA+NAafDDo1XS05zFRqkBwycLBL0OkrtCX
         R3GzlSVXZODsHnKKmdb2q4sv5XMELSPmzeEjCDXJgWB+GuQk8pa8p2HmtwvB5ulM1Xql
         YdRoO7GZuzNK1CQSW47PqLT3hLS+1CVGHpSNLFs0bU53AA60YjsfogvZhY7QF5s5R3A3
         4Zqbmj0t+vHjoQUMcHDV/bYa2Y/r+IHDF3F4RIJKXq/oH2/63XSgzgZJbWW8twxaVqZN
         Ot2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e206si712009oib.3.2021.02.12.04.00.22
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Feb 2021 04:00:22 -0800 (PST)
Received-SPF: pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 48B8A113E;
	Fri, 12 Feb 2021 04:00:22 -0800 (PST)
Received: from e121166-lin.cambridge.arm.com (e121166-lin.cambridge.arm.com [10.1.196.255])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 80EA73F719;
	Fri, 12 Feb 2021 04:00:20 -0800 (PST)
Date: Fri, 12 Feb 2021 12:00:15 +0000
From: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v13 6/7] arm64: mte: Report async tag faults before
 suspend
Message-ID: <20210212120015.GA18281@e121166-lin.cambridge.arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-7-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210211153353.29094-7-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: lorenzo.pieralisi@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Feb 11, 2021 at 03:33:52PM +0000, Vincenzo Frascino wrote:
> When MTE async mode is enabled TFSR_EL1 contains the accumulative
> asynchronous tag check faults for EL1 and EL0.
> 
> During the suspend/resume operations the firmware might perform some
> operations that could change the state of the register resulting in
> a spurious tag check fault report.
> 
> Report asynchronous tag faults before suspend and clear the TFSR_EL1
> register after resume to prevent this to happen.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h |  4 ++++
>  arch/arm64/kernel/mte.c      | 20 ++++++++++++++++++++
>  arch/arm64/kernel/suspend.c  |  3 +++
>  3 files changed, 27 insertions(+)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 43169b978cd3..33e88a470357 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -41,6 +41,7 @@ void mte_sync_tags(pte_t *ptep, pte_t pte);
>  void mte_copy_page_tags(void *kto, const void *kfrom);
>  void flush_mte_state(void);
>  void mte_thread_switch(struct task_struct *next);
> +void mte_suspend_enter(void);
>  void mte_suspend_exit(void);
>  long set_mte_ctrl(struct task_struct *task, unsigned long arg);
>  long get_mte_ctrl(struct task_struct *task);
> @@ -66,6 +67,9 @@ static inline void flush_mte_state(void)
>  static inline void mte_thread_switch(struct task_struct *next)
>  {
>  }
> +static inline void mte_suspend_enter(void)
> +{
> +}
>  static inline void mte_suspend_exit(void)
>  {
>  }
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index f5aa5bea6dfe..de905102245a 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -258,12 +258,32 @@ void mte_thread_switch(struct task_struct *next)
>  	mte_check_tfsr_el1();
>  }
>  
> +void mte_suspend_enter(void)
> +{
> +	if (!system_supports_mte())
> +		return;
> +
> +	/*
> +	 * The barriers are required to guarantee that the indirect writes
> +	 * to TFSR_EL1 are synchronized before we report the state.
> +	 */
> +	dsb(nsh);
> +	isb();
> +
> +	/* Report SYS_TFSR_EL1 before suspend entry */
> +	mte_check_tfsr_el1();
> +}
> +
>  void mte_suspend_exit(void)
>  {
>  	if (!system_supports_mte())
>  		return;
>  
>  	update_gcr_el1_excl(gcr_kernel_excl);
> +
> +	/* Clear SYS_TFSR_EL1 after suspend exit */
> +	write_sysreg_s(0, SYS_TFSR_EL1);

AFAICS it is not needed, it is done already in __cpu_setup() (that is
called by cpu_resume on return from cpu_suspend() from firmware).

However, I have a question. We are relying on context switch to set
sctlr_el1_tfc0 right ? If that's the case, till the thread resuming from
low power switches context we are running with SCTLR_EL1_TCF0 not
reflecting the actual value.

Just making sure that I understand it correctly, I need to check the
resume from suspend-to-RAM path, it is something that came up with perf
save/restore already in the past.

Lorenzo

> +
>  }
>  
>  long set_mte_ctrl(struct task_struct *task, unsigned long arg)
> diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
> index a67b37a7a47e..25a02926ad88 100644
> --- a/arch/arm64/kernel/suspend.c
> +++ b/arch/arm64/kernel/suspend.c
> @@ -91,6 +91,9 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
>  	unsigned long flags;
>  	struct sleep_stack_data state;
>  
> +	/* Report any MTE async fault before going to suspend */
> +	mte_suspend_enter();
> +
>  	/*
>  	 * From this point debug exceptions are disabled to prevent
>  	 * updates to mdscr register (saved and restored along with
> -- 
> 2.30.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212120015.GA18281%40e121166-lin.cambridge.arm.com.
