Return-Path: <kasan-dev+bncBDV37XP3XYDRBKPESWJAMGQE2SWC7ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id B9ACD4ED6A9
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 11:19:38 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id h4-20020a2ea484000000b002480c04898asf9919092lji.6
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 02:19:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648718378; cv=pass;
        d=google.com; s=arc-20160816;
        b=WyqiRJudXnHbKLsmCSwyhCQnQeLHqQNObiK1adwn24t/QaHQgXAV5mm6Ji4soIrIsw
         UuutRcZVDGVQLjDRdXEwzS23VRXhszxG5RuspuBM/8Oztlprb8hsUE3aAedga1J2du46
         5aRYQES5dZeyZOXEyADKnTMTIlLq+6zXprL+WycLJRRg4JD8JQxMuQuo57zPUok90sQZ
         ndSsvlqevs5DGsLvkxbNAQMR20E3LK3UzfoUtaOA5bcZKThQpHrYtqLPPrYY5Jdws9PD
         jB66Jlvp3IoLS5ghj4bTO5zMoia+FQc6erEijXSyxyW0dpe0TyjH6x829hqzFCDBHQZG
         3YfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1pf7BLM7jEpOO01ZOlHa4cbX+d1gh5dVNSz0L5v4270=;
        b=P8LogBr0/5gjWZynZapQwWp5Yghrluk+SyP/CtOyT8JRMfzBb1ahlzyMAMf9MUVzd1
         023U0p0BKBJRm/RVqHZb6GIihejCuQmu+0tOB9mnXizjkw+7Z16nSA6wK0wBWCa0rZEV
         G0+OByEozDD/65S61JE6411j/VMGP+uKAfNiG3C7zuMrHmkx62q7C9U3oI7NmgoKjH/E
         nwHk59uaB8uMMfeMLyQ8uilGX2QtVnnrYDfrqS80gwbl5F0pA+y9yH4KQHWZ6E0XFId+
         MuEYriAVB50oHriTyqObJENm2ANfAshnWT1jXQILvIRA90iDhvp2hiJ3r9ouyFfqnOFL
         okQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1pf7BLM7jEpOO01ZOlHa4cbX+d1gh5dVNSz0L5v4270=;
        b=nHJ+Sfquut60iRR+VL807OJBlJzE5tp/B35uhraUC3ajRc+0qaKC4dAJgRY54e67YQ
         jfV7KxgyDrvYMQcIw5ha3oJAenq63+hyEzToZhgR5r5hA4AgFrzqpQtpqANIdCT78CVq
         J45W1xU5oWPD1abnf0U7P/ymKZGvmJrwRLlR2qT4fZKSWJlnMziVzFpUPpSRcAozRdLM
         wb2cP/FBj3Ag/WG2xPaCuJfxJU3wDoGNB3ktb7EgqT3evjo6MhXbc/blHNqafsu3l7Qg
         QwdWgVJT2+uk5danxuimk6ICdg6QE4PiCy86Njl5wPD72D9oenv8mrOQ4WW4mvciOQOL
         DkRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1pf7BLM7jEpOO01ZOlHa4cbX+d1gh5dVNSz0L5v4270=;
        b=LxE9ybWNBdaMfT30uGGB98iWpvGMstvYL3sdCRDnqDbR4W4fIr09D7GMOJ6pJT4pA/
         Il63/pIHPQLqRGJwXRpIVbMMJJqNpEgdmAUGcOfXsIV+1cRLID2keJui4Yb4gO+299lf
         dPmkGsFQhF00GR8KhWNTBaRb/fb+OC+0xnw0cjIEQ6y5seVdS78AZoYb5eR2tH0/Yw7l
         nTDKE9+9wEr5JfpF7HjT+2WZ9vdp6IuGWTX/rySE7C28dGHsDI0h2ZysJ2upvKf1IqUj
         CJpakoBVPkqIBrMJ7nq8fzHkzcKDKdDajlbuSHopi1krARgOYzr6i0EJMgODzVNdvJ5R
         a0IQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533saJYRgt73cyFHcW3XuOdoWxpW1fG+ffIl2RDgXU3MnUQU0JNG
	V/10FN/Wn3p8KD98saV8nK0=
X-Google-Smtp-Source: ABdhPJwxj3JdPvW6FjhWmNXiv+CbcCpcXKlvBXlv1XxdVhii6MT0N+sXRMDtWJSNQoW5rIYAmrbNJQ==
X-Received: by 2002:a19:6750:0:b0:44a:1fd7:530f with SMTP id e16-20020a196750000000b0044a1fd7530fmr10114539lfj.341.1648718378108;
        Thu, 31 Mar 2022 02:19:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls4231788lfb.1.gmail; Thu, 31 Mar 2022
 02:19:37 -0700 (PDT)
X-Received: by 2002:a05:6512:ba3:b0:44a:7a70:7dcb with SMTP id b35-20020a0565120ba300b0044a7a707dcbmr10204711lfv.222.1648718376942;
        Thu, 31 Mar 2022 02:19:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648718376; cv=none;
        d=google.com; s=arc-20160816;
        b=VFp4OaDvv903Fhxi1e0ur0PS3gPbhA/13+QHjsIXMSUxiwF9hNVp7xp1aM+7vm/D90
         MIxq67tYUofjitpIfi45L36qvnLO0yiW9tPlX+Na3sopE+GKYdJKBminJmvoo2ALH8zK
         /yDZm36hvHp3pxq+R928o1dOF6NxCie2werb9ortZru7kA0zWMn2ezY5g2hyUEaI3XFA
         4uhvXDS6Pg/dqI8Nc45e22PzZE5RSiC90CbGiiAfxDnoc7jRDF7egPrUHHn1SU2Y7VcM
         RvS9hL4oMSaGDgtvFe4bIJ4do2xzUFFKeeUQrmzIRXfVbiEsD7GrvJgc17wfDrCH6OHJ
         dfVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=GPzritAAJUD0HrITV7wMz8tXKVU1ryWw2kFn2vluens=;
        b=sEg/EYTy4f1Gq6HjQjFFLsvSTuLIlc0T9VX3NQaWjCUAwE1C+9wlDHrbO2im6x3jVE
         kaqz12JfYTQcQp6eMEFTKRWKeDPHjENqiUk2xYM+lK+1dl5smjSybkpaM8so5C2IIzT+
         imJfPbdNl+MFgNF/MJZYrXRq2nUoFwWJgKSib61vtfzDAgFPi+/oFpIx26oF5kNHw2Bm
         e3LEqhgqpPG0Bte6egZnqnZ038hdlMMIMjkOEU4x2S2xmAcktazTZgRJEL1krZAd5JPU
         3x/mrJqOkZFOHmmnJnwqFVQ0Mjs/RpQyo+nGNbw8liyAGBAeFpUp4srPx9aO5uK24Gtx
         Hc9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i6-20020a2e8646000000b0024af7c96042si98571ljj.7.2022.03.31.02.19.36
        for <kasan-dev@googlegroups.com>;
        Thu, 31 Mar 2022 02:19:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9652723A;
	Thu, 31 Mar 2022 02:19:35 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B74053F718;
	Thu, 31 Mar 2022 02:19:32 -0700 (PDT)
Date: Thu, 31 Mar 2022 10:19:21 +0100
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
Subject: Re: [PATCH v2 1/4] stacktrace: add interface based on shadow call
 stack
Message-ID: <YkVyGdniIBXf4t8/@FVFF77S0Q05N>
References: <cover.1648049113.git.andreyknvl@google.com>
 <21e3e20ea58e242e3c82c19abbfe65b579e0e4b8.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <21e3e20ea58e242e3c82c19abbfe65b579e0e4b8.1648049113.git.andreyknvl@google.com>
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

On Wed, Mar 23, 2022 at 04:32:52PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a new interface stack_trace_save_shadow() for collecting stack traces
> by copying frames from the Shadow Call Stack.
> 
> Collecting stack traces this way is significantly faster: boot time
> of a defconfig build with KASAN enabled gets descreased by ~30%.

Hmm... just to check, do ou know if that's just because of hte linear copy, or
because we're skipping other work we have to do in the regular stacktrace?

> The few patches following this one add an implementation of
> stack_trace_save_shadow() for arm64.
> 
> The implementation of the added interface is not meant to use
> stack_trace_consume_fn to avoid making a function call for each
> collected frame to further improve performance.

... because we could easily provide an inline-optimized stack copy *without*
having to write a distinct unwinder, and I'd *really* like to avoid having a
bunch of distinct unwinders for arm64, as it really hinders maintenance. We're
working on fixing/improving the arm64 unwinder for things like
RELIABLE_STACKTRACE, and I know that some of that work is non-trivial to make
work with an SCS-based unwind rather than an FP-based unwind, and/or will
undermine the saving anyway.

> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/Kconfig               |  6 ++++++
>  include/linux/stacktrace.h | 15 +++++++++++++++
>  kernel/stacktrace.c        | 21 +++++++++++++++++++++
>  3 files changed, 42 insertions(+)
> 
> diff --git a/arch/Kconfig b/arch/Kconfig
> index e12a4268c01d..207c1679c53a 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -1041,6 +1041,12 @@ config HAVE_RELIABLE_STACKTRACE
>  	  arch_stack_walk_reliable() function which only returns a stack trace
>  	  if it can guarantee the trace is reliable.
>  
> +config HAVE_SHADOW_STACKTRACE
> +	bool
> +	help
> +	  If this is set, the architecture provides the arch_stack_walk_shadow()
> +	  function, which collects the stack trace from the shadow call stack.
> +
>  config HAVE_ARCH_HASH
>  	bool
>  	default n
> diff --git a/include/linux/stacktrace.h b/include/linux/stacktrace.h
> index 97455880ac41..b74d1e42e157 100644
> --- a/include/linux/stacktrace.h
> +++ b/include/linux/stacktrace.h
> @@ -60,6 +60,9 @@ int arch_stack_walk_reliable(stack_trace_consume_fn consume_entry, void *cookie,
>  
>  void arch_stack_walk_user(stack_trace_consume_fn consume_entry, void *cookie,
>  			  const struct pt_regs *regs);
> +
> +int arch_stack_walk_shadow(unsigned long *store, unsigned int size,
> +			   unsigned int skipnr);
>  #endif /* CONFIG_ARCH_STACKWALK */
>  
>  #ifdef CONFIG_STACKTRACE
> @@ -108,4 +111,16 @@ static inline int stack_trace_save_tsk_reliable(struct task_struct *tsk,
>  }
>  #endif
>  
> +#if defined(CONFIG_STACKTRACE) && defined(CONFIG_HAVE_SHADOW_STACKTRACE)
> +int stack_trace_save_shadow(unsigned long *store, unsigned int size,
> +			    unsigned int skipnr);
> +#else
> +static inline int stack_trace_save_shadow(unsigned long *store,
> +					  unsigned int size,
> +					  unsigned int skipnr)
> +{
> +	return -ENOSYS;
> +}
> +#endif
> +
>  #endif /* __LINUX_STACKTRACE_H */
> diff --git a/kernel/stacktrace.c b/kernel/stacktrace.c
> index 9ed5ce989415..fe305861fd55 100644
> --- a/kernel/stacktrace.c
> +++ b/kernel/stacktrace.c
> @@ -237,6 +237,27 @@ unsigned int stack_trace_save_user(unsigned long *store, unsigned int size)
>  }
>  #endif
>  
> +#ifdef CONFIG_HAVE_SHADOW_STACKTRACE
> +/**
> + * stack_trace_save_shadow - Save a stack trace based on shadow call stack
> + * @store:	Pointer to the storage array
> + * @size:	Size of the storage array
> + * @skipnr:	Number of entries to skip at the start of the stack trace
> + *
> + * Return: Number of trace entries stored.
> + */
> +int stack_trace_save_shadow(unsigned long *store, unsigned int size,
> +			    unsigned int skipnr)
> +{
> +	/*
> +	 * Do not use stack_trace_consume_fn to avoid making a function
> +	 * call for each collected frame to improve performance.
> +	 * Skip + 1 frame to skip stack_trace_save_shadow.
> +	 */
> +	return arch_stack_walk_shadow(store, size, skipnr + 1);
> +}
> +#endif

If we really need this, can we make it an __always_inline in a header so that
we can avoid the skip? Generally the skipping is problematic due to
inlining/outlining and LTO, and I'd like to avoid adding more of it
unnecessarily.

Thanks,
Mark.

> +
>  #else /* CONFIG_ARCH_STACKWALK */
>  
>  /*
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YkVyGdniIBXf4t8/%40FVFF77S0Q05N.
