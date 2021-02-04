Return-Path: <kasan-dev+bncBDAZZCVNSYPBBAGZ56AAMGQEVD37MRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 99D4430F351
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 13:45:53 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id t18sf2065588qva.6
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 04:45:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612442752; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bk/tqpz1b5mplmds2CUjaOKYKG6uRUAPua8TEJ8S7diW5RPiW7C0yHJsWqP7+ww+ax
         7z5rDieJLByEC2pYfX7rnosrvY5XPGGNlrGq0v6e2vWbiZHHWNu3nwFbE+FfWD0YHW44
         HfHfo3UmMvKAlQM0pVE4DFwCONBVtpeQ8ixcntMsnb2as24KO4Si8rCwZDJYVrPkfO/H
         CA2nFDW7vOjcBw7SJUO9LQ1JO1WHzqlh4llTv4N/sX9SL26sbEewOJMJgsEuAT7Ig333
         TYR6R0N1LHIePdJ/ZrJTyB6NQyIMjoUoMcTB+vhpdcr8TGTMtNNU997boHgZ916Bp8cy
         I5cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=22e93CoU6MqKHS5KWUeGL7ovsEcyHi+FfjxG3togmTk=;
        b=cqvQFEh5bX9YOjYTDlXScFh7R8OD9hvQJ9pBwsyjxhsv2917Fv/LtQdESSHvl00F6l
         5fJrRKf8A/ORFqUHYa9f5vc/YZt3lksaRSloT96ISEfx66XpNhi1a75gSBVqr5TM5lDv
         kvQE4IWF7Oc6qVO4xTmzLusxzPHRId2aXVF8YJjvDeNPWpgsXH5rnqYq1Jfj3YmmdjAP
         yeK+hT8vr+wlKI52/dSLGO7NEfVAP9mjVgYb9mKYj9R26va8Q9cbmUyFMINBOohbuSwx
         s9VZdcnkcqLd/k3NMg3VWzF/Uuw6VVLhY/DnU6t9tC5IcDTVCD5zofP1OZnjg5fYt/sA
         Zu0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="dG/U0a+x";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=22e93CoU6MqKHS5KWUeGL7ovsEcyHi+FfjxG3togmTk=;
        b=b7dRvrf5A2rlZTpbfIblrn1SChht5o0hSZSxddDPqD7QJJcp3QLDOkl9SMpFM1HKWH
         F4rjNMxz9AGJet2d+2LtZMl7wddExkeTQkmUsd8Fqf55jZiWqWGNz0VlaOkMgj+ng0qM
         7F2HRfJFoxKpC5am3F8zNZdgzpOqb6YKMQPMatLLoosUq5b2GUBw/wgA6Ij+oT8OSm9G
         obhxhC8IC5GZZISZE7DuaV0nAP3j7gGZ+I9YtuSP4iMwpWjiTEdicfQQ1FEQSK/CH27m
         7/SF1Gkq2hUWAecHGNx4Cs8JOSkdmhcQS0UB/Gs1Zm7lpRbrNrG76kr2jwP10MwjJoF1
         XMNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=22e93CoU6MqKHS5KWUeGL7ovsEcyHi+FfjxG3togmTk=;
        b=bBJzkjUJdZzhGglc6E4xjAHgQuvjEC6FVRzop3jecCEFd892m/fYMDWvcf3Bw7d/PF
         9JxXnsgw+vy80i8byFeg5Bf3dnG1csLDM9bTS524aVwvq/3cMoFNK6jCgAsTGpTdPttj
         X1vjR6N9bSARUZhB7T0RkSIIYEMvwlp+JJu5VGXOy9/LHgGYlQ2Ly2X4MnffpOUmMzww
         tJ+OM3x9qG5eGhaZM75RKpoTeuaZjoC70o2mZYCz2DN9Ol+BPLhGxyao8Z7zsryCoZvi
         XxGrKnzsc0bSgXwtritpc864wVC6TjFYQMwdm5oM+sQ0IiuU+t0KXLtrXDM5eq9K2LPO
         azzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PDN9BoUg/jmNHrdCK1YThcuR+rRZUY7AmN4Iat/1N8wGU5zJ4
	iCJyCPiVySXfXtEyl0bPVDg=
X-Google-Smtp-Source: ABdhPJwRg5h2zRg7Dgox4Iq+VM+yQOHJT4qZPTloBFwj+IgMQR69xA4PlkI7LtbkAOfuRqPUhTrdYw==
X-Received: by 2002:ac8:7cb3:: with SMTP id z19mr6745421qtv.209.1612442752553;
        Thu, 04 Feb 2021 04:45:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:12cc:: with SMTP id e12ls2961409qkl.10.gmail; Thu,
 04 Feb 2021 04:45:52 -0800 (PST)
X-Received: by 2002:a37:9ad0:: with SMTP id c199mr7392053qke.112.1612442752256;
        Thu, 04 Feb 2021 04:45:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612442752; cv=none;
        d=google.com; s=arc-20160816;
        b=Yj7NjgffrcdPIvgLP4GTs1UbKqY9qf12F+sZ3uSU6+8qCYGR6xhDUX90I6X43j1MC+
         1+AnALPhggq+WTKpRk8L3gKwfl0NuHdvGpp6XO5rlC6ojEv1FcLZqaFLbeQts8iJ0c/g
         slwNus8AevWpBxZbyyJnQ5ju1CPXsoM8IrLBiaGGlWHuskxxy47Cir4/I6lOc9Z5dwCH
         aTlsBDtn7opTzZenNbcv1AFnw7hF/xmkwsPcklMA4HKbKStH2niynEwDTuM6dqlxLt7W
         HKn5sjPnF/QfVJIVl9PXWsprOXsvn7VFh3ngiGVMcLKBjaInZfg3glauGFR48Ui966N0
         vgeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=M5+oo5EveXYeOrjEcv82yrlKlC8EOf+mbY19yJHI1PQ=;
        b=L+5a86eTZN2v/zgcZS6RsmCZCLLn3TbsTT9Q62R9f0REmrtsscWhCvxDD/S/jUuf+H
         Jhb1S5Vu+bRxVDBN4gRhQE7J1HWNbJZlUFF8O4iVsPDOPU9gMdMUFJb6B6JeCZrTPysR
         wsoDZQGDDfSY8DvkvtbJJAoc+gxA9AAQ7gVEhu5V7C2n531s69BLGLng+P73nrjIy+Xj
         R046Q5kdYPYGTbGD62GY0uiwl8nRTdcRuuFJ567/e3EBdKjcL9LxDAYnomVpgHfH/f6i
         jleczPMwn63n9P2nnicrHkhYrBweJHtKHvj3l/lQr42b3PeATqKmxikMoL/8QtUf8pU9
         FaVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="dG/U0a+x";
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p6si264787qti.1.2021.02.04.04.45.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Feb 2021 04:45:52 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4FBF664F41;
	Thu,  4 Feb 2021 12:45:47 +0000 (UTC)
Date: Thu, 4 Feb 2021 12:45:43 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	dan.j.williams@intel.com, aryabinin@virtuozzo.com,
	glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org, yj.chiang@mediatek.com,
	catalin.marinas@arm.com, ardb@kernel.org, andreyknvl@google.com,
	broonie@kernel.org, linux@roeck-us.net, rppt@kernel.org,
	tyhicks@linux.microsoft.com, robin.murphy@arm.com,
	vincenzo.frascino@arm.com, gustavoars@kernel.org,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for
 CONFIG_KASAN_VMALLOC
Message-ID: <20210204124543.GA20468@willie-the-truck>
References: <20210109103252.812517-1-lecopzer@gmail.com>
 <20210109103252.812517-2-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210109103252.812517-2-lecopzer@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="dG/U0a+x";       spf=pass
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

On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
> 
> Like how the MODULES_VADDR does now, just not to early populate
> the VMALLOC_START between VMALLOC_END.
> similarly, the kernel code mapping is now in the VMALLOC area and
> should keep these area populated.
> 
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
>  1 file changed, 18 insertions(+), 5 deletions(-)
> 
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index d8e66c78440e..39b218a64279 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
>  {
>  	u64 kimg_shadow_start, kimg_shadow_end;
>  	u64 mod_shadow_start, mod_shadow_end;
> +	u64 vmalloc_shadow_start, vmalloc_shadow_end;
>  	phys_addr_t pa_start, pa_end;
>  	u64 i;
>  
> @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
>  	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
>  	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
>  
> +	vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
> +	vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> +
>  	/*
>  	 * We are going to perform proper setup of shadow memory.
>  	 * At first we should unmap early shadow (clear_pgds() call below).
> @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
>  
>  	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
>  				   (void *)mod_shadow_start);
> -	kasan_populate_early_shadow((void *)kimg_shadow_end,
> -				   (void *)KASAN_SHADOW_END);
> +	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {

Do we really need yet another CONFIG option for KASAN? What's the use-case
for *not* enabling this if you're already enabling one of the KASAN
backends?

> +		kasan_populate_early_shadow((void *)vmalloc_shadow_end,
> +					    (void *)KASAN_SHADOW_END);
> +		if (vmalloc_shadow_start > mod_shadow_end)

To echo Ard's concern: when is the above 'if' condition true?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204124543.GA20468%40willie-the-truck.
