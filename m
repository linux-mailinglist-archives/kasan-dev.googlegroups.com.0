Return-Path: <kasan-dev+bncBDV37XP3XYDRBRHKSWJAMGQEHBC4EXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D5124ED703
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 11:32:53 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id c12-20020a2ebf0c000000b0024af8f2794bsf612881ljr.12
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 02:32:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648719172; cv=pass;
        d=google.com; s=arc-20160816;
        b=JI/9N+ZEkpRo1pgpP8Fti7O0F8rrfpbIpGnzSUnU9a0Meyew7tzwyMnETfNOoj0AOA
         uwO/VjzkN3u1hocKHrcZaEthAtuCIRxBfrHV/vs40H7hsTCVHLnYGAZQvgFq/XsuC6rN
         hVF/U+v1qP5gspNUiu2xxy3WUcMINILWlgQ/0YmCfHY0SMO387h3OvestPRBMLXM0yuU
         6z79bhAu10QaecAaVfz04/hJ7/nM8rs2oFMWcX5gWHnNSTe7JG2sG29SHQZmK+1KyYhV
         1fTwIlkKqIGPzPAPy4lVwkWsMBRQeP/DaFF8KFdYpr9NhHtUVjfl4IU3UAbLD0Nedg7q
         j50Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lAG0VhOTMDX7zXDOs720D2S3sgaPM4RcKgR5tSQqJNQ=;
        b=CxRgDj0RCJBmm0SOLUQ2zWnBtIou0q9drsjnagw1JEPuSHSSBbowNobxh2NthU5HAc
         j4fKuOwoLGeIfkmIbMrY9Bnr5BGwdV2rNbvyAxZw8DgaE+VUOzjUhQNb3fiPTgy5YwFu
         qr9zVLjg3bifvty4jlGGChJlJdFBsz4zsKgBePR3krmsbcUX0ZGXiPku8tXj1qEE0zXU
         H01xFCJ1SamtYEoVB8/kyq4WgcRhBHxq4jJNeE7Oq3rmN4Hz7NO1AL71KrN8q2pIwPaE
         mumSOQLSh5nqo7+X9amxIRmegsRUhkSUJhUktVnoWo/OaLzmzOLLnnNkMYKfVTj+/FOt
         /0EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lAG0VhOTMDX7zXDOs720D2S3sgaPM4RcKgR5tSQqJNQ=;
        b=XrMihNmwOTeBTj79FKpHXWV6rZF+dJkrvrMx6/9I5AJR2j+rE2uK1brSAv8hoewwWi
         UTK9WADeym/Bfz4tuVAwP0NHE0M36RLeH+Xbq5ZOtWAmjhutVjpueChEwVy50ly7NYHl
         ibThUkg1pOKeZnknembYFTzc5EWmVDDKsKME//2S4ERW89lFHM8ra7VP9w3J95vocAcz
         51DasuHEtEnKoBCRVZowuibH28ZrDwN6UsznHm80dJAig9kod5k8S8Ab4J/9hrDZGWz2
         W1fCWbSNkUAezinWNayeTpP5cLP3gMGTiRwxJSuXqqi6yK57l31Rdy4qniu1jWgIWK4O
         3Uyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lAG0VhOTMDX7zXDOs720D2S3sgaPM4RcKgR5tSQqJNQ=;
        b=2HAQw9ttTuugRyEnJCpF8hD0uUvqM9WqjsxqNUazahrb6nK2esEj86zRnII0dYf1d5
         rWKalvpdE1ZdRbB7ag6NRGjGPnu+IEf2CRiVO2DWCEw1mjoHyEYEAe0mTE4dUtR4w7A7
         DUU1lqWfbTEftYm532uZYZ5FugI76fHTu2rjWiiSBcxzlQ/mVciSrtlfwiwWj6uEXFVV
         o1EngnSa3de46gs8Z1OfhOYu145XT2ASn2GC/H6punOBOHPecEY/O9o77c7EzNP6Yxw1
         rJlMjFu688kWvZbIa2CVDXUKqxQ9/2HmC9NRnOc0ZC8HNVnd25hsVh7a7bRzf4Jh/0aH
         +fgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532VciM8g7fbc0St9FsevsNtYH2XlCL+72ztDrGZ+5wgYM5x8Qrv
	57B4KvaZdZC5t1WA/vNttOE=
X-Google-Smtp-Source: ABdhPJwiXI3z+BRL71MetdUXsaI4196twcryZSKaWfFY6xzjeA1qWlqL+awAaCTIKf19yIReB0jC4Q==
X-Received: by 2002:a2e:a7c7:0:b0:249:8273:b488 with SMTP id x7-20020a2ea7c7000000b002498273b488mr10268185ljp.238.1648719172553;
        Thu, 31 Mar 2022 02:32:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5285:0:b0:44a:94d2:1d8f with SMTP id q5-20020ac25285000000b0044a94d21d8fls4240483lfm.0.gmail;
 Thu, 31 Mar 2022 02:32:51 -0700 (PDT)
X-Received: by 2002:a19:dc13:0:b0:448:3735:776b with SMTP id t19-20020a19dc13000000b004483735776bmr9961404lfg.77.1648719171384;
        Thu, 31 Mar 2022 02:32:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648719171; cv=none;
        d=google.com; s=arc-20160816;
        b=TFOVPkco3U4c1yk8Cn+3snMkgFbOwZYWc0yrlSTKgZ6LNW1vmU29zKsKSao1znA7or
         GORKRISjARzv5PKNjuYR2T5LPhiVBy63/wsmvQO9jb/1zoHwO1kbmwGRZQ0x9QcqIIP3
         ZmB4PH3mUURjKqWlM+40iaczx0G6WWZQn++dZY47CtSZdpQaaE2ddeSK3zzUMUyd3Z6f
         of6ANQ0kGggnfKlvIfY2O3O4Uqqxbq3h/xeDsTshU+hd1OZ56t5iz3Y0mIuqed3xYEKl
         07Hod1DzV7O+xzyQARgGyv6bdjdtogvu0KirTIKLkxuzwPQbFDgKI9DeSYgfl0gAWf2C
         6Fhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=elONmd/Ehy9uWW1lbKER4jTkktfzY3h6QrrkTEe6J3M=;
        b=EO8uy0yprW34mHcXLg5KlMCp18/ysHt0waCQrsMDr420E6FOeI19Hd8V9L9zJJ9/vl
         lWEBOfCHEGkA6fIYgGhlQyqCnNEsp/oes56cIXymGw1uH0FuPE1M9sFGezNXU5gfbY5d
         Tr9K+Nj/hoWVvmEYoZWxSyk6CHgb2xPR42afRfrJwRg6rsvROYt7LMrngXWGgI72FwXt
         VL/moI7lez3Fa894pSrN4PO8GHhWiwCSY1qNQU6F7eRXxARd4tYrbm3za6VAz6xGqBiD
         i0eZWtgTPj3Re4pds1lcXuXqWgWvLR7m8QXU7NqI0rUNGLJd0sK51F5GDA/GOZtuzREK
         Cg7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id bu30-20020a056512169e00b0044842a98a98si1176276lfb.2.2022.03.31.02.32.51
        for <kasan-dev@googlegroups.com>;
        Thu, 31 Mar 2022 02:32:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1AF6923A;
	Thu, 31 Mar 2022 02:32:50 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3B0083F718;
	Thu, 31 Mar 2022 02:32:47 -0700 (PDT)
Date: Thu, 31 Mar 2022 10:32:41 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 3/4] arm64: implement stack_trace_save_shadow
Message-ID: <YkV1ORaR97g45Fag@FVFF77S0Q05N>
References: <cover.1648049113.git.andreyknvl@google.com>
 <0bb72ea8fa88ef9ae3508c23d993952a0ae6f0f9.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0bb72ea8fa88ef9ae3508c23d993952a0ae6f0f9.1648049113.git.andreyknvl@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Mar 23, 2022 at 04:32:54PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Implement the stack_trace_save_shadow() interface that collects stack
> traces based on the Shadow Call Stack (SCS) for arm64.
> 
> The implementation walks through available SCS pointers (the per-task one
> and the per-interrupt-type ones) and copies the frames.
> 
> Note that the frame of the interrupted function is not included into
> the stack trace, as it is not yet saved on the SCS when an interrupt
> happens.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/Kconfig             |  1 +
>  arch/arm64/kernel/stacktrace.c | 83 ++++++++++++++++++++++++++++++++++
>  2 files changed, 84 insertions(+)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index a659e238f196..d89cecf6c923 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -201,6 +201,7 @@ config ARM64
>  	select MMU_GATHER_RCU_TABLE_FREE
>  	select HAVE_RSEQ
>  	select HAVE_RUST
> +	select HAVE_SHADOW_STACKTRACE
>  	select HAVE_STACKPROTECTOR
>  	select HAVE_SYSCALL_TRACEPOINTS
>  	select HAVE_KPROBES
> diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrace.c
> index e4103e085681..89daa710d91b 100644
> --- a/arch/arm64/kernel/stacktrace.c
> +++ b/arch/arm64/kernel/stacktrace.c
> @@ -12,9 +12,11 @@
>  #include <linux/sched/debug.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/stacktrace.h>
> +#include <linux/scs.h>
>  
>  #include <asm/irq.h>
>  #include <asm/pointer_auth.h>
> +#include <asm/scs.h>
>  #include <asm/stack_pointer.h>
>  #include <asm/stacktrace.h>
>  
> @@ -210,3 +212,84 @@ noinline notrace void arch_stack_walk(stack_trace_consume_fn consume_entry,
>  
>  	walk_stackframe(task, &frame, consume_entry, cookie);
>  }
> +
> +static const struct {
> +	unsigned long ** __percpu saved;
> +	unsigned long ** __percpu base;
> +} scs_parts[] = {
> +#ifdef CONFIG_ARM_SDE_INTERFACE
> +	{
> +		.saved = &sdei_shadow_call_stack_critical_saved_ptr,
> +		.base = &sdei_shadow_call_stack_critical_ptr,
> +	},
> +	{
> +		.saved = &sdei_shadow_call_stack_normal_saved_ptr,
> +		.base = &sdei_shadow_call_stack_normal_ptr,
> +	},
> +#endif /* CONFIG_ARM_SDE_INTERFACE */
> +	{
> +		.saved = &irq_shadow_call_stack_saved_ptr,
> +		.base = &irq_shadow_call_stack_ptr,
> +	},
> +};
> +
> +static inline bool walk_shadow_stack_part(
> +				unsigned long *scs_top, unsigned long *scs_base,
> +				unsigned long *store, unsigned int size,
> +				unsigned int *skipnr, unsigned int *len)
> +{
> +	unsigned long *frame;
> +
> +	for (frame = scs_top; frame >= scs_base; frame--) {
> +		if (*skipnr > 0) {
> +			(*skipnr)--;
> +			continue;
> +		}
> +		/*
> +		 * Do not leak PTR_AUTH tags in stack traces.
> +		 * Use READ_ONCE_NOCHECK as SCS is poisoned with Generic KASAN.
> +		 */
> +		store[(*len)++] =
> +			ptrauth_strip_insn_pac(READ_ONCE_NOCHECK(*frame));
> +		if (*len >= size)
> +			return true;
> +	}
> +
> +	return false;
> +}

This doesn't do any of the trampoline repatinting (e.g. for kretprobes or
ftrace graph caller) that the regular unwinder does, so if either of those are
in use this is going to produce bogus results.

I really don't want to have to duplicate this logic.

> +
> +noinline notrace int arch_stack_walk_shadow(unsigned long *store,
> +					    unsigned int size,
> +					    unsigned int skipnr)
> +{
> +	unsigned long *scs_top, *scs_base, *scs_next;
> +	unsigned int len = 0, part;
> +
> +	preempt_disable();

This doesn't look necessary; it's certinaly not needed for the regular unwinder.

Critically, in the common case of unwinding just the task stack, we don't need
to look at any of the per-cpu stacks, and so there's no need to disable
preemption. See the stack nesting logic in the regular unwinder.

If we *do* need to unwind per-cpu stacks, we figure that out and verify our
countext *at* the transition point.

> +
> +	/* Get the SCS pointer. */
> +	asm volatile("mov %0, x18" : "=&r" (scs_top));

Does the compiler guarantee where this happens relative to any prologue
manipulation of x18?

This seems like something we should be using a compilar intrinsic for, or have
a wrapper that passes this in if necessary.

> +
> +	/* The top SCS slot is empty. */
> +	scs_top -= 1;
> +
> +	/* Handle SDEI and hardirq frames. */
> +	for (part = 0; part < ARRAY_SIZE(scs_parts); part++) {
> +		scs_next = *this_cpu_ptr(scs_parts[part].saved);
> +		if (scs_next) {
> +			scs_base = *this_cpu_ptr(scs_parts[part].base);
> +			if (walk_shadow_stack_part(scs_top, scs_base, store,
> +						   size, &skipnr, &len))
> +				goto out;
> +			scs_top = scs_next;
> +		}
> +	}

We have a number of portential stack nesting orders (and may need to introduce
more stacks in future), so I think we need to be more careful with this. The
regular unwinder handles that dynamically.

Thanks,
Mark.

> +
> +	/* Handle task and softirq frames. */
> +	scs_base = task_scs(current);
> +	walk_shadow_stack_part(scs_top, scs_base, store, size, &skipnr, &len);
> +
> +out:
> +	preempt_enable();
> +	return len;
> +}
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YkV1ORaR97g45Fag%40FVFF77S0Q05N.
