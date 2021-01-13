Return-Path: <kasan-dev+bncBDDL3KWR4EBRBWWY7T7QKGQEJQU3P3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id A78782F5108
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 18:22:35 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id i20sf1987403qvk.18
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 09:22:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610558554; cv=pass;
        d=google.com; s=arc-20160816;
        b=ck+oWNVRLheUD/W3WdJB80d+FjyFAE038/zU85UalUNcY7tHtaEqUtZbd8wefxfjFC
         i15C+mw1EvJIoClxfZHRNyk3Ssx0ab+nybLXZTd69SB5M3F9jsMJ7qCNrYFX+Vt4d67U
         IlKYrx9nZzq5Pk0rmBQuvBQ/wq43iA+57NqByBFIw7AN7jofWalmku8xAUayIMHebGhw
         KOAEFCgesG1gH39XwFvTYI2yIoQnlytp3NsPNG8Hg0fcbtP646HuJGHw2a/eU6/8GfxG
         Uuq9qly6YQeK0X/acFgU2ZLdrQiSeHADJxZbXaJPhRGnqNLg8g8tbuS8m+irQqFNa/Nw
         C3bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Uhd/kbp6NfvDxCT6yuHWJeda8fsf04xiljUxt7kiIIo=;
        b=O3yQd3iq/3In4twWC7gljhFl2a3WVpKHRvKsu6/SNCYp/XryeeGV1OKyfbQdA63z6f
         pjWEay+WfNp6hy1VZDmkTjDWzj00xNcrORA3P3GFGFwGZ3jPbusjLaPm6sR+F2QSLzBH
         8vkMCtaVHKobP7UbfJykRMvMtIVxDvfIQp0/1ZMqQ0OA81vPXl0QseJksVZ/3r+dHWrk
         ShyLIobnWzxcuYxpZPd/bfw67K/H8e45IMWRA1UAXGsu0hshZZ2dIXGzvJZa9qo9wya5
         fca0OMrroKcx3/sWVngTzt0zOQ5U6sZZCEC89nwRJzbSK2V0Uj45R9Qdag5VHLnFYgR2
         MLhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Uhd/kbp6NfvDxCT6yuHWJeda8fsf04xiljUxt7kiIIo=;
        b=sE+w4nqN3rIiL74WSGXVtkXVAKTopyGTzopGE0E1oZzkjPVkI6zPjKmDrEfCYTxVwj
         bntIbkHHjLtjSSjMmcUkJZzBPP2qEs1DuOwnTQE1q+7yZ4Vh40tBxdq/2JkXlGHCU41N
         CMKQEp0rOjnbknxVm1LP0iMTVyjbHI5XuMu8/WbUvakEcTmuarRUyp01js1R/kcyOb1t
         eisqHA4k0RbeQjApI4yrwHAAWaomN1fBXbW+ZJ4cYz0kTuh35NCKLrZP3JAgB3flvBA7
         9vAF3qyKWXNIjpz16KEngD+24vZIs5k7GjKhNAD2hZZ4GsA2fI9YPBF+rzfzL7HW5XPr
         ETyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Uhd/kbp6NfvDxCT6yuHWJeda8fsf04xiljUxt7kiIIo=;
        b=nc0ZkRadaI7jLeHT94en20xDARfEj8aExR0/EiAfIrX1xzJp45hlaaVcobKnGFABJM
         MsicNIoToBitvPh+SFXou6feOiVguLmEaVI3ibcr6d6UG1WWAFhOn4fYrHeNNSTEMFXc
         OUuXQyeulpzHB1+nK6nfnDFXkCsALYBOiUKc+R+y7Szl0dLwSCZfnNaoS8yTKWIhO1a7
         K//VvlRrZPSmlRE4RR0DlI4WgLmO2CQOv0lRGVQvD8MjNMgDemvj8wqOfF418gJTvRuI
         G5BR0nbACeGU4Fh8IW8pHRM4nX8/X0nDxOdzPZBHJnen1SKL7yBSRelyavT4izvlUV+J
         tmTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334/5TAEVQkjto+WTXBa6UQoBThEL1LZqRqMhAfkr5YgNF6hwLJ
	6GwnN3DFf+b8PgxgyZB12e4=
X-Google-Smtp-Source: ABdhPJyn6KpRpl/U9LMhLsEQN24iGs1CmqrhUQTH3DNLqTsz78gt37sWx3sHIlTydTf0UzGi5GgJOA==
X-Received: by 2002:ae9:e909:: with SMTP id x9mr2996154qkf.166.1610558554810;
        Wed, 13 Jan 2021 09:22:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4644:: with SMTP id t65ls1419874qka.5.gmail; Wed, 13 Jan
 2021 09:22:34 -0800 (PST)
X-Received: by 2002:a37:d13:: with SMTP id 19mr3156779qkn.93.1610558554318;
        Wed, 13 Jan 2021 09:22:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610558554; cv=none;
        d=google.com; s=arc-20160816;
        b=X2V2Ge7b07npipx2ZPUYzgQ0dAdWleu6v9pbg0sGe7AChgn6yfcBqP9WV6MVhOLdTy
         RcX093NlqjvqIoB8gju9Bp3hrFvX1BdWkTnZ1VEBRpQkflqn6IJO72SYCCctPa4zU95Z
         fVSBTWRTcZDBxpRwOTEeKT2vtlVks5tj4WpNRclALfDGmrwikT96um10XmJmiCiTMaKj
         kL/7Nx1Kk8xl8DTCD/p+q0DmA4ai+gnrbvzAkqCJY1UsCIXaNRCvwMxqiUfxt25CF4mT
         WQjQth71itg2O+kp9OYM0WwwunbReZ7h1Z+0xxUU4XBSqVKt4TsdwvLKbU2rfjgh+Q8H
         2IjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=98F3nAX0LvltoTawbbePQqygopSNJZ9GZGDh9PhKb2Y=;
        b=HOMitjWelYEHvaM93E4NBDELqhvOSnsLcFgnLzTVS59Mq57ZTaHppXL8JzEjnCWaQF
         DZ1B6yfFNjUQ7kcynwXsVEvYKfZ5EqYYZOFHMRqPjamFsb6z4JzMrArLVfrFguL5gUSC
         gBShSX/hu6KLc4XShirv1vU9E8gezi9e8W5KZSSsu8woxEq2TqVFv7v40a7bq2JqBbpA
         s+VpkyaPTL1EMXUxC3BNfUNnKxRzErXXWd5e2L//xmmqxNmy0TG4vx0ZZdZVIgLtsIna
         zzNe8HYQHzMxSsPJE9eoHmxDClcTmDZY02zimzNl6Mnpn0RhYNgY0WQ/Y7MlEjjjeAj7
         JeMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z25si188077qth.3.2021.01.13.09.22.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Jan 2021 09:22:34 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2CDA423437;
	Wed, 13 Jan 2021 17:22:31 +0000 (UTC)
Date: Wed, 13 Jan 2021 17:22:28 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 2/4] arm64: mte: Add asynchronous mode support
Message-ID: <20210113172228.GE27045@gaia>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
 <20210107172908.42686-3-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210107172908.42686-3-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Jan 07, 2021 at 05:29:06PM +0000, Vincenzo Frascino wrote:
> MTE provides an asynchronous mode for detecting tag exceptions. In
> particular instead of triggering a fault the arm64 core updates a
> register which is checked by the kernel at the first entry after the tag
> exception has occurred.

Just rephrase the "tag exception" here as there's no exception taken.
Also we don't check this only when the kernel is first entered after a
tag check fault, as per patch 3.

> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -153,8 +153,35 @@ void mte_init_tags(u64 max_tag)
>  
>  void mte_enable_kernel(enum kasan_arg_mode mode)
>  {
> -	/* Enable MTE Sync Mode for EL1. */
> -	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +	const char *m;
> +
> +	/* Preset parameter values based on the mode. */
> +	switch (mode) {
> +	case KASAN_ARG_MODE_OFF:
> +		return;
> +	case KASAN_ARG_MODE_LIGHT:
> +		/* Enable MTE Async Mode for EL1. */
> +		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
> +		m = "asynchronous";
> +		break;
> +	case KASAN_ARG_MODE_DEFAULT:
> +	case KASAN_ARG_MODE_PROD:
> +	case KASAN_ARG_MODE_FULL:
> +		/* Enable MTE Sync Mode for EL1. */
> +		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +		m = "synchronous";
> +		break;
> +	default:
> +		/*
> +		 * kasan mode should be always set hence we should
> +		 * not reach this condition.
> +		 */
> +		WARN_ON_ONCE(1);
> +		return;
> +	}

I guess the switch statement here will be re-written as we want kasan to
drive the actual sync/async modes as it sees fit rather than MTE
guessing what PROD/FULL/LIGHT means.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113172228.GE27045%40gaia.
