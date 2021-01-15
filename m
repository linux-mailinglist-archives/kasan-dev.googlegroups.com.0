Return-Path: <kasan-dev+bncBDV37XP3XYDRBG7RQ2AAMGQELSPNJUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B2032F7FEE
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 16:45:33 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id q12sf5790981plr.9
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 07:45:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610725531; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWTDxhP+r8VeGYd9KQ60IT965u9btg1Rv0pgU5Ii95k3tCI/bgp8v6F7cYc7TQkIhO
         RrpxwmUJ8uC6w7ZuYKco/TAA+w2jh9cVjjEFXiXb58FEjg0vQv4B/Ze4n5KGsIkyaRqW
         kOYUT9vlcZZirseZE9rVjVL9AuUi/9IgJbwCISVGO1SZzpqZdgE4MM62ti/y3rOMPH+q
         pPW9BzsoWmMPoRSjRJV4iuaN1MBoK5N4YnI1EcN9RCkhI+QrovxGV9CpDGrrCKZdKDBt
         S2F+4fQyvhW/MHcBAkU1500jfqPQ15A4AARLCQ4zIV2HgUJ0+06LnpStIy+4hobQdckd
         0/1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Pvq5NVd5OXDC4kwgjyMLclJuQxJbnujKdUP+D14eOYM=;
        b=BQeJ8agrcGnNVX6sMtDZjL+aD6S70sUS5jbjPYfK5XgznBvKwMpSVJOiF43v5ipQkP
         N9x7+9mKH9+oDwRT2+ORZ6HBaMEwTlYVbQ+Bhh6cr34iTfb8H7/jza3wtzZnBiNraoKH
         rUsU9aX5yT2CLa+x4lv2IiJbOeFkXFgrdEHj+r/PyYaQuP9qgBFKp7xXYn8lP0MM6J25
         WOkeNHRVnKbPFWzkPsYFmLQQVSRgKGIhKIQdrFialzAU0JJADSRakFb3xpVM3KNbVQIV
         ZuQzBz070v6x+SQBPEIXKBIDx8KLBAsADo/lV82oZjpTy4kW8jZSu0mCDnb6QHtfdTHT
         c3Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pvq5NVd5OXDC4kwgjyMLclJuQxJbnujKdUP+D14eOYM=;
        b=NsCR14E0ctgDfSBBVRpADVrdYPUetA0cKNb+HM9h3Qo5XT/dUJdfJDmu5iNv//7IVT
         frESC1a0YzEmbQJXYcm5ZkeC9tF7fSY2M2kDoSYZKFbktiO22L7gUTSD97S/qt8p/zD3
         udi2IbQKwvagZeocad71lpq2seoMPqca/PkmtoUtP7qDL45q7PGeA6qk5hXf1DbYixnb
         sFjLmYQ052t+adErunxS1p9sR1+/6RZrRUDmLzz6Ku+y/RKgQ70wov2TDrbiDfBM2SY4
         G5WfPRWx2oV6T5yTiwqEqW9mfTY4Cj4nHmbKTT+Fp1Es4VjA8UU7UlMvLIOnY2qvrj+V
         Ktgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Pvq5NVd5OXDC4kwgjyMLclJuQxJbnujKdUP+D14eOYM=;
        b=cpv4QA5IDtwoZrflCgRpQtzoXmQz4Ih4NXVwoqlaU5XuHy3uDDFeeMnuPg6fosG0Up
         08khQFshp9Abb694ECXurO3/Q5XqnPiPriKQOwBGsuY70Zj4LZZIO7uzP+Cr3HqvyKkC
         IIg420BmLMYwZVN1vVUMfisDM0SiSPF7C3W6DIdlHYi2iiuLGcul9DNeSI65GzgMuVyI
         UDedm+Cw+sCTiIGJ4Br7cPAiodMLexcNwd0Y6BO+3om8z5p1LhY3EoaSVL47uVDDlMqj
         v/EOQPELReaCDT0T/rnC93d8dPOOVMIYXFtVJ3qXR1OtIRsDXIYo2TminNXRMxdwfwgW
         gC0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5330NDZ6+Mxh3W6YZeROKvmxi1uZSd8Yb7E+VV8lbnOwaXko6BMm
	PkdwLXtlBXka0z8QeFK8NU4=
X-Google-Smtp-Source: ABdhPJz1E711xBPc48jY5kxmZ3VTETQkMHmyWSMO2bja4xFoNNXLIkmdG49UVdxHnMLLG/K+fpyyTA==
X-Received: by 2002:a17:902:c517:b029:d6:e179:2097 with SMTP id o23-20020a170902c517b02900d6e1792097mr13092372plx.70.1610725531559;
        Fri, 15 Jan 2021 07:45:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9286:: with SMTP id j6ls3681814pfa.7.gmail; Fri, 15 Jan
 2021 07:45:31 -0800 (PST)
X-Received: by 2002:a62:7907:0:b029:19d:cf5d:20ae with SMTP id u7-20020a6279070000b029019dcf5d20aemr13436688pfc.2.1610725530968;
        Fri, 15 Jan 2021 07:45:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610725530; cv=none;
        d=google.com; s=arc-20160816;
        b=KIZDyp9n42XGtxpTiaYHD6iVBASl9MTgBzI/Z48Mlv3Qr+v78AIec3UUFgX1DNVtfV
         3DV5/y9cG0PEVRYtFdLeTQshjXJuutDHW+VkmR0np3wtvtmhqt/HTo3u5UgHZB9ql4fa
         PZVZkxfxVEWjV00HYrTcZ4jjNbm+sFOtVVMYHYfDlgAvozI+FFarIIpmw9+iSE+l/D72
         J3JlEQCUQzsTO0/v8Hg5NBrcCT11SUXlWz9Mfag1JqCIicftEiYDOlCFBrHnrjIJOQjv
         4JrplLYHeKx2mMIbXl+5tcs0i8weLyWmbtBVG2rgsELHStdltSyS+XeAyiENfxVx42uq
         /pqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=qYDOFfjlCPlX9ZjcBfjfbWnFaoykYPxz/pl8dXAzmNo=;
        b=cUMMEIoioR1Zvz4JkC0hIrNfpJ5uWjDOastRHZ64RTp3+7L06jE031sJoz4qNTdG6W
         H6MACyrh5grivIZNNUJI7smigehG+L46amLOaJfPU2Dh57SWldteFN6F7t1cy5mkUJHe
         Oz79R3NWaNPdx+WCw/IAZkn4zlExzEcGxdmKw2WpmHN05YLi8e/cOm2HSSpgDhBcwLlZ
         lbrkwGCa7WgscjaCC8MQAZobZXUkhFMXmwfTkwvpsDknnJIwYHL6chmWY234GUhFdgfC
         J+tb/0PPqe4/KriR2M2urSAYhKSpDDXZDXG37U8jzKJDFfzfT9ubnbcsB5NA8cwjI3nl
         T5Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ce15si786154pjb.3.2021.01.15.07.45.30
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 07:45:30 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 457CBD6E;
	Fri, 15 Jan 2021 07:45:30 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.41.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 70C153F70D;
	Fri, 15 Jan 2021 07:45:24 -0800 (PST)
Date: Fri, 15 Jan 2021 15:45:20 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 4/4] arm64: mte: Optimize mte_assign_mem_tag_range()
Message-ID: <20210115154520.GD44111@C02TD0UTHF1T.local>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-5-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210115120043.50023-5-vincenzo.frascino@arm.com>
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

On Fri, Jan 15, 2021 at 12:00:43PM +0000, Vincenzo Frascino wrote:
> mte_assign_mem_tag_range() is called on production KASAN HW hot
> paths. It makes sense to optimize it in an attempt to reduce the
> overhead.
> 
> Optimize mte_assign_mem_tag_range() based on the indications provided at
> [1].

... what exactly is the optimization?

I /think/ you're just trying to have it inlined, but you should mention
that explicitly.

> 
> [1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
>  arch/arm64/lib/mte.S         | 15 ---------------
>  2 files changed, 25 insertions(+), 16 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 1a715963d909..9730f2b07b79 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -49,7 +49,31 @@ long get_mte_ctrl(struct task_struct *task);
>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
>  			 unsigned long addr, unsigned long data);
>  
> -void mte_assign_mem_tag_range(void *addr, size_t size);
> +static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> +{
> +	u64 _addr = (u64)addr;
> +	u64 _end = _addr + size;
> +
> +	/*
> +	 * This function must be invoked from an MTE enabled context.
> +	 *
> +	 * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> +	 * size must be non-zero and MTE_GRANULE_SIZE aligned.
> +	 */
> +	do {
> +		/*
> +		 * 'asm volatile' is required to prevent the compiler to move
> +		 * the statement outside of the loop.
> +		 */
> +		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> +			     :
> +			     : "r" (_addr)
> +			     : "memory");
> +
> +		_addr += MTE_GRANULE_SIZE;
> +	} while (_addr < _end);

Is there any chance that this can be used for the last bytes of the
virtual address space? This might need to change to `_addr == _end` if
that is possible, otherwise it'll terminate early in that case.

> +}

What does the code generation look like for this, relative to the
assembly version?

Thanks,
Mark.

> +
>  
>  #else /* CONFIG_ARM64_MTE */
>  
> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
> index 9e1a12e10053..a0a650451510 100644
> --- a/arch/arm64/lib/mte.S
> +++ b/arch/arm64/lib/mte.S
> @@ -150,18 +150,3 @@ SYM_FUNC_START(mte_restore_page_tags)
>  	ret
>  SYM_FUNC_END(mte_restore_page_tags)
>  
> -/*
> - * Assign allocation tags for a region of memory based on the pointer tag
> - *   x0 - source pointer
> - *   x1 - size
> - *
> - * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> - * size must be non-zero and MTE_GRANULE_SIZE aligned.
> - */
> -SYM_FUNC_START(mte_assign_mem_tag_range)
> -1:	stg	x0, [x0]
> -	add	x0, x0, #MTE_GRANULE_SIZE
> -	subs	x1, x1, #MTE_GRANULE_SIZE
> -	b.gt	1b
> -	ret
> -SYM_FUNC_END(mte_assign_mem_tag_range)
> -- 
> 2.30.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115154520.GD44111%40C02TD0UTHF1T.local.
