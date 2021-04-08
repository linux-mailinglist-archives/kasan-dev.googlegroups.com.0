Return-Path: <kasan-dev+bncBDAZZCVNSYPBBCNTXSBQMGQEWM55YBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3877935879E
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 16:56:11 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id g7sf2258003ybm.13
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 07:56:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617893770; cv=pass;
        d=google.com; s=arc-20160816;
        b=gESI/air3vtlq47SJDQs00Ng66ktFRh+MmBcNWiYihwmJl2z2CDDM6SNf6iRhIuHEY
         Bpu2EwDeIY18F+ALEGfW7iFWyRvgoXyBr7IuCpoh+5fyGzRo0pUIaBzu1qbBgqy1B9dE
         dfZFhT1c3S1VIYYZ53P7HKGoLm9/LNG9e4puXKMOLkyvhVDiIWv0tMu6tzIPvT1w2fQg
         yMtiS0F4TrVUaPoDxbu/xH2z2tvtipK5jeeFhi74uhlVhhm0dGfEQSssL2S+dOejAL4i
         0UqjdvlnOm7fD9Q2Gz2cnDfAndTFgvr1oJ/N7BcgrEtkKWi25UAvv3crQ2abhSR/fJAh
         dv5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=eFEhsp0xd+5PNcQza4NvxIGcxqGXYj0FaNxU9aH3XO4=;
        b=HM2zCWU3I3ljGdmYLPtLOV3j7gRm5KVb1E85UJ+LRPFGTIhUGqKO3AFfY7bVxGsfFF
         Jq2Ly9d/BpySO4xnmCa7ZNld0gifqcwWxZmWZvo1oSuhM1SYy6n935j6bfeYP2x3bQ0U
         QiUSPY8+Y3mUX8nyE3287c6zncs0Wwm420B5pV8sCvMbn0zHZTg4i2f591n3dXjOzlYU
         yfFYDX4AqmuUcBjrpkbad43BKOvJpGdi1ou1qa0zsUnof6b26BboLJXh0k0+8PkxZyDL
         aSaoI8SwC9+YYdOa8pllr7Oy7NrLFKvpXVyxL13Gl/wvsBmWZibp2ETqStQsDxqvrIf5
         OIDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Tl0OUXv7;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eFEhsp0xd+5PNcQza4NvxIGcxqGXYj0FaNxU9aH3XO4=;
        b=aXVNjUzMX/5IcwHSX2LsIagcdCP2xaxyeKPSECqtAEa/UjN4zeAzApxTjCqYp6GO9M
         Li2PU8jcHVMQ4s/cctlL04SzjnnIxdnA0zZHkaRlKDsqQGPsSX5Zbhn1jlCzqCPSdrro
         tXYzJAPMaW0o8uZEJ4D34jFSGsnvxXq1JXSqq+pxAT0+rU1USFqgbVxm0gxljAQeZjfj
         BHlFIxfDVuz3dxO4eLPZhmTaPfDImx9wVZ+cWLp7VrzjgqnaNtgjj7Cx6aEnrEd5VrNt
         LlQ+ISoS3QwLQzezaeXyCcdD4PXO8neSD/gRLG7/pFgnsiw4KNZthhG+GdFNjPYrWF8S
         su7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eFEhsp0xd+5PNcQza4NvxIGcxqGXYj0FaNxU9aH3XO4=;
        b=cqwpaFIEl3oeygjS1ZUiAElGNy9R1FqW3Rm/CYkTNqf9i/8SBTUWqlBHm+IGz2aaJF
         ydk6cX+onErH9u0O6N5kLsK2Z1NxaamENcf2FJfObFuLNn2PBTm7mZT2lxJd47md1sWb
         cAwUXShYN8m3Rwh8XzdM04QRevivkcDcmXq5PndRjWK1mtqFvw+MkuKp0apny9V+5M2i
         7JuWCLW9Xwkhmwjf5QK2UyT0g+Lh6An1OXJIbn97hWDCa1cylarFJ4v4xEqKiuIiz1Cd
         1xvirNHK4kEaGtlsXRPjhOXrbSHzrkjU5jBNseEISgK0/V5xsnSHHmedhPdjnKcJ8sI3
         Hk+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eJoWOemNIDqp9w1iP2MSimPrVgBAvBXpJ4g8IWm0ayS/z/NYS
	L9ypmF08+MX1Lus+RjO7z9w=
X-Google-Smtp-Source: ABdhPJzYMol0cEQScMLjEZaCmadthFr9vZppoq4JkRfUUfzigbVurO1YPPthco1LH/sH11KILJ3qbg==
X-Received: by 2002:a25:d956:: with SMTP id q83mr11700619ybg.35.1617893769952;
        Thu, 08 Apr 2021 07:56:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:bc3:: with SMTP id c3ls2590406ybr.6.gmail; Thu, 08 Apr
 2021 07:56:09 -0700 (PDT)
X-Received: by 2002:a25:41c6:: with SMTP id o189mr3052921yba.39.1617893769574;
        Thu, 08 Apr 2021 07:56:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617893769; cv=none;
        d=google.com; s=arc-20160816;
        b=YkBsdMnSAvhMp6mscuI6h4JDXP1fR6Ya6AUH8q+CzBLkFtCLCYualIlXzBKG1JCHS3
         EXicPslR1s1PAoTHpk//wI0qCwZLFrYxLlZoAH9lcUbz0jjcmT5EWYJTDsbMu0hB9PMa
         wPT5/JhMzDrJqoWlDXJlVsjCMNSO7fxNQi3MbHzwcLnngg6CwjM1gr7hp+9zSSEIZmHx
         ihmfKlmn21OieN8j3g5YuXfW4HOLN/j73QPQY/H/IcusLfTmqX5rMOSzsp3pCizIBPXr
         9ua18PjHIXkHHvFmzaYwCH5C2bNObmOzCkoM4hl8oWqERA79JH0Bw/RFwF/LAWLQMCSS
         vnkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/HIWlnwEo4YLD1xLBod5jttoU1M1FcspNfG7zYpZ64o=;
        b=C2ujlmPySMp9djm3K9arExqqTZTsJHbGrmLcMlhec+AzfN3T6aJN2N/gKfnFz49Yeb
         vOVkjIe5CZe8fV33UmxhDFyNQPRm6V0F/cUesDAQMNN1efw0IruzGGduEEsAohnPCCgk
         karqem/1ZYSLLvTLE79SCHzb+3yh7g7IYzWlYYcM0GX2FnAJQQxiTV+SiW59xL7+OSGV
         ZFHDwhOQ0U8KLzMgcWVQhrluayz3LC2S+EwslyaicyOEMYBEt1Hin07GBnrWEfnZVs42
         4Y1c76nnwJi3MV/z4Wz2L2MxIOoN69ml8jG7Ih/H21XF/jpimPkiK3eJTJEPSPlN4+13
         NlWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Tl0OUXv7;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i1si2053041ybe.2.2021.04.08.07.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Apr 2021 07:56:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 92784610F9;
	Thu,  8 Apr 2021 14:56:07 +0000 (UTC)
Date: Thu, 8 Apr 2021 15:56:04 +0100
From: Will Deacon <will@kernel.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <20210408145604.GB18211@willie-the-truck>
References: <20210408143723.13024-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210408143723.13024-1-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Tl0OUXv7;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Apr 08, 2021 at 03:37:23PM +0100, Vincenzo Frascino wrote:
> The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
> race with another CPU doing a set_tsk_thread_flag() and the flag can be
> lost in the process.

Actually, it's all the *other* flags that get lost!

> Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
> exit_to_user_mode() to address the problem.
> 
> Note: Moving the check in entry-common allows to use set_thread_flag()
> which is safe.
> 
> Fixes: 637ec831ea4f ("arm64: mte: Handle synchronous and asynchronous
> tag check faults")
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Reported-by: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h     |  8 ++++++++
>  arch/arm64/kernel/entry-common.c |  6 ++++++
>  arch/arm64/kernel/entry.S        | 30 ------------------------------
>  arch/arm64/kernel/mte.c          | 25 +++++++++++++++++++++++--
>  4 files changed, 37 insertions(+), 32 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 9b557a457f24..188f778c6f7b 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -31,6 +31,8 @@ void mte_invalidate_tags(int type, pgoff_t offset);
>  void mte_invalidate_tags_area(int type);
>  void *mte_allocate_tag_storage(void);
>  void mte_free_tag_storage(char *storage);
> +void check_mte_async_tcf0(void);
> +void clear_mte_async_tcf0(void);
>  
>  #ifdef CONFIG_ARM64_MTE
>  
> @@ -83,6 +85,12 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
>  {
>  	return -EIO;
>  }
> +void check_mte_async_tcf0(void)
> +{
> +}
> +void clear_mte_async_tcf0(void)
> +{
> +}
>  
>  static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>  {
> diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
> index 9d3588450473..837d3624a1d5 100644
> --- a/arch/arm64/kernel/entry-common.c
> +++ b/arch/arm64/kernel/entry-common.c
> @@ -289,10 +289,16 @@ asmlinkage void noinstr enter_from_user_mode(void)
>  	CT_WARN_ON(ct_state() != CONTEXT_USER);
>  	user_exit_irqoff();
>  	trace_hardirqs_off_finish();
> +
> +	/* Check for asynchronous tag check faults in user space */
> +	check_mte_async_tcf0();
>  }

Is enter_from_user_mode() always called when we enter the kernel from EL0?
afaict, some paths (e.g. el0_irq()) only end up calling it if
CONTEXT_TRACKING or TRACE_IRQFLAGS are enabled.

>  
>  asmlinkage void noinstr exit_to_user_mode(void)
>  {
> +	/* Ignore asynchronous tag check faults in the uaccess routines */
> +	clear_mte_async_tcf0();
> +

and this one seems to be called even less often.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408145604.GB18211%40willie-the-truck.
