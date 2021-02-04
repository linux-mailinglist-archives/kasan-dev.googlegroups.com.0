Return-Path: <kasan-dev+bncBDAZZCVNSYPBBNUY6CAAMGQETWU3YJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id AC65B30F5AA
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 16:01:11 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id r82sf1108508oie.18
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 07:01:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612450870; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pv9ReLGndxGmY/syIhgaCtzmLEuKg06r7PXvjE/CbfTNFy8d77BhJ6tHqiVvSkOMak
         HJeljdoWofTXcjEGtRoohsZDDKvTWLVojFiYPLJGNUZ4ZXQHao5fNrZc9V09nQqO7nSz
         +hxmG2R1hc5HeDnGBjNgL19hWBW8mWOArwHyZLSAEQY6ip2ba28If+ryv6Vq+Qt/JcDA
         Lv5wuRtprbSjSHlKv+nvVsrLNyGEStQBQcNPDSI1thvGS/oXB0mCPpR0ZXKfJBPlbftj
         9dBimE8CuzAaT6AUXoef1W1wsfkGUHsmKGaiM9zWZb1U9p8tTEAYvC6orsegdiptDMAX
         YJVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=JjjnwGpJmW3o7+iGEXkt6/ngVtkek3uBF/8VcYVkiPA=;
        b=ZQ5JH65tetdsojuffO7L6een8uQhTfSzZlFXnPgl/KmxECQZKbHyeF/eltASdDADmH
         w6G9bSnc/3wBcuZAv0cTXvg971TwcN/gftCqciclI2YEPxlSpziRZP/yoYeEOEhfwQh4
         ki/yKPr80IL3eB73J4HH0fpyW7vlYSsNAvCpmywdRbp1m47GL2n1NWhTELF7BIeYOqlR
         cMXPdfmvuKIj90WQQ+4JwdDX6a0N3GUYZdCIs6JbmO54aJZn7ERT2dHP3L450IKotqr0
         3KxWTPtNjGmMfflti1RvYIuVIjf398PF6deHEu29k6L7EFY/sod0OIL6LLNsIEv7I54r
         edsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mg4bHqG1;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JjjnwGpJmW3o7+iGEXkt6/ngVtkek3uBF/8VcYVkiPA=;
        b=baSXJbPbRAKNzmMlwgOElyqQNhBtKnjYrLg1tg/mdMfB5ZHzDpYAfYYvPh3MZRy6Ox
         y5UA4NDeKXX+qpBCxWcnqz5dNvBMkFvJwkG214NBbJe4OePDtqcwU0duEjvdw6OF3WtU
         JjLtPRILITr5Xa0Iiq+8nE23Do3/bGdsIgEmepKyJk81+FomF1Ap2E7lMlU+wYZGSlLG
         kyyEIkpWdnO/tGAs/T0EhIgbp65u6moPxD9aKXjZLjExF5NdQWedlSdF1BwCqj8lU1vm
         eBllVu9qQG8SbmxuU/lbV8X2ajrZw3CHfhEcMB5Fu6W69IDiLQBhkiGtvbUUP+xaBJMg
         Mtnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JjjnwGpJmW3o7+iGEXkt6/ngVtkek3uBF/8VcYVkiPA=;
        b=ZPghskkMly//hv5kImG6c8Cu9+K3LbtpbkD/QkqA7wKrX7WTjpO3XWfFXXbTyQ7+ff
         SZJImikDXub78VHiCigTjyGjuuSO9KVDv/eZHUA33rSruqa69JS2kJiHaVoaNU4T4PHg
         b2B1yHSyAYdZmtrJvv4wnbuBsIQnywLsk1RxkSverKAqKxqKY4Wfjl+gLI+x3uOUAdNP
         GBJZhx+GNvKPdzXMd8tAstvgRaa9vyXEeMvASqzQzDATFCiq7rcs2j6U4xVcyH4rvd5b
         lZHOYyFKyK72vfoQlpJ7BJjmIs5Bt5pEHqs4G9k6F2CVcnq8SlIS7njWzgM6h/OnJ+8R
         L2jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533//gYMki+Tc2oUS/Dwn5HIoP+npeuLXzUt74j3f/AJV9QHTs1k
	0GrCw/i/fXEsrYOM8sgnzgI=
X-Google-Smtp-Source: ABdhPJy/NYdzHPGXEwHwnRuZ0KlGqpB+dq+ySvqGvrq8cSe+LG+FN2JtE1zaaqBQKsFBrI7D9RQdlg==
X-Received: by 2002:a05:6808:6d2:: with SMTP id m18mr4314970oih.32.1612450870705;
        Thu, 04 Feb 2021 07:01:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:14a:: with SMTP id j10ls1408623otp.4.gmail; Thu, 04
 Feb 2021 07:01:09 -0800 (PST)
X-Received: by 2002:a05:6830:1bd5:: with SMTP id v21mr6226764ota.125.1612450869647;
        Thu, 04 Feb 2021 07:01:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612450869; cv=none;
        d=google.com; s=arc-20160816;
        b=bEzIWY4vRWMYlpcEkFDYvu/4+J3qHkjdtfO4UoqpB00DxUJa8VuUGCQM/BcLHsBxuQ
         2SZ2u8F7Zf7a9rj8F+XBCW9t0DIn0h0Sbt7sA8+dVpaZTOZZKiRJZt4cmf66uOxlqgJL
         gQA8u98m6N+ylIayVliMqhOpw8ImMw10URp5+066J9IVgJWvuB35sDVi4DuPUusurGSw
         IjHEBan/OmTC4sb9b/oBE+fZgZx0sUbH0AY0uJoMB/QyMayMiKwxZ3NARKs/qJhwAfx5
         QorzoQwu+m3y6S1YWZmfoR1ZAV/L38Prw9CRjyJ6mILgJMBZN8nnsW3nyB6oJBp34QjD
         qqBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=J3b6lVRYB/ygzZL14zTZQv+zDl+j8Np8Tj5a0JRncGg=;
        b=awFWftGBNPCeA51EfqleVCuxAJWpr9qVTxdEkHXm3MlhdkzP84xY7CNHH7PXzz3iww
         oKf/T5DPREjned4PbCNZpVZeB7FF6DolbaCAeIh95eI1CyrGx842EH+iVl0QOlvv06PW
         uUCzuBPV71UBKy7Sji34qyUr7YzX1a+6hDQUBekTynoYn2c+QuTpmg51pGst+ztlqU1J
         C0OPEGDSJ6jPtY8LO4YugAKCG8dSm72glQVtlqPMXdpwprcTpFMdIq0akqwuNpxA+h0E
         9IpFk/OGHgQCA1KM2/mn3DnlZ5H0TUdZLY4q7+dMM6xRynBo7qmRSkTZvsG3eIDuNqWh
         L25w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mg4bHqG1;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r13si353246otd.3.2021.02.04.07.01.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Feb 2021 07:01:09 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4F1F364DBA;
	Thu,  4 Feb 2021 15:01:04 +0000 (UTC)
Date: Thu, 4 Feb 2021 15:01:01 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@google.com, ardb@kernel.org,
	aryabinin@virtuozzo.com, broonie@kernel.org,
	catalin.marinas@arm.com, dan.j.williams@intel.com,
	dvyukov@google.com, glider@google.com, gustavoars@kernel.org,
	kasan-dev@googlegroups.com, lecopzer.chen@mediatek.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org, linux-mm@kvack.org,
	linux@roeck-us.net, robin.murphy@arm.com, rppt@kernel.org,
	tyhicks@linux.microsoft.com, vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for
 CONFIG_KASAN_VMALLOC
Message-ID: <20210204150100.GE20815@willie-the-truck>
References: <20210204124543.GA20468@willie-the-truck>
 <20210204144612.75582-1-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210204144612.75582-1-lecopzer@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Mg4bHqG1;       spf=pass
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

On Thu, Feb 04, 2021 at 10:46:12PM +0800, Lecopzer Chen wrote:
> > On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> > > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > ("kasan: support backing vmalloc space with real shadow memory")
> > > 
> > > Like how the MODULES_VADDR does now, just not to early populate
> > > the VMALLOC_START between VMALLOC_END.
> > > similarly, the kernel code mapping is now in the VMALLOC area and
> > > should keep these area populated.
> > > 
> > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > ---
> > >  arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
> > >  1 file changed, 18 insertions(+), 5 deletions(-)
> > > 
> > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > > index d8e66c78440e..39b218a64279 100644
> > > --- a/arch/arm64/mm/kasan_init.c
> > > +++ b/arch/arm64/mm/kasan_init.c
> > > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> > >  {
> > >  	u64 kimg_shadow_start, kimg_shadow_end;
> > >  	u64 mod_shadow_start, mod_shadow_end;
> > > +	u64 vmalloc_shadow_start, vmalloc_shadow_end;
> > >  	phys_addr_t pa_start, pa_end;
> > >  	u64 i;
> > >  
> > > @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
> > >  	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
> > >  	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> > >  
> > > +	vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
> > > +	vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> > > +
> > >  	/*
> > >  	 * We are going to perform proper setup of shadow memory.
> > >  	 * At first we should unmap early shadow (clear_pgds() call below).
> > > @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
> > >  
> > >  	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
> > >  				   (void *)mod_shadow_start);
> > > -	kasan_populate_early_shadow((void *)kimg_shadow_end,
> > > -				   (void *)KASAN_SHADOW_END);
> > > +	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> > 
> > Do we really need yet another CONFIG option for KASAN? What's the use-case
> > for *not* enabling this if you're already enabling one of the KASAN
> > backends?
> 
> As I know, KASAN_VMALLOC now only supports KASAN_GENERIC and also
> KASAN_VMALLOC uses more memory to map real shadow memory (1/8 of vmalloc va).

The shadow is allocated dynamically though, isn't it?

> There should be someone can enable KASAN_GENERIC but can't use VMALLOC
> due to memory issue.

That doesn't sound particularly realistic to me. The reason I'm pushing here
is because I would _really_ like to move to VMAP stack unconditionally, and
that would effectively force KASAN_VMALLOC to be set if KASAN is in use.

So unless there's a really good reason not to do that, please can we make
this unconditional for arm64? Pretty please?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204150100.GE20815%40willie-the-truck.
