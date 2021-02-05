Return-Path: <kasan-dev+bncBDAZZCVNSYPBBLUH62AAMGQEK56UI2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E64D310EF1
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:43:11 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id e62sf7858709yba.5
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:43:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546990; cv=pass;
        d=google.com; s=arc-20160816;
        b=mKGmwABc1IANKmCLMwjr8Mz2kOsl1g0W61bc+PcQXTf2i+2g9KZvJ9XR5Deh6G/9AT
         Mof9VM/EQwCntpgk4zkhBjcaGo9NHV6YPkyFTZjXzMa48em9wopeDw69Bxdl0v5PijGp
         e/WScEm7fneuSSsk++tNb2mZGbn8nW2kRWlsGA6iQyvIsAi1fIZmOTaU7e0hThYfe7Ey
         VtG/1meYr9Rn9Yjf5uzrdsJwMIdpgCCpXZf5ynJRbSAtXxgDPpWQJS9GqluWZ76ZyxkX
         GFmKHvlFiyooKEhAdcA6CXG7r7L/okBpoQQ1DIGwR+G7/bRbgX5NLEwqW0+B0zrgmnP9
         EkWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=sUWa3p1ivm+hOZSuKxLXr2e0Q7ThgpLTM2sqUITAVwU=;
        b=looI1Ev21XW3kTbqGubta+ckU/Gt09DDwERdCCaYw58ZZ3FUV+24aUgaf2vHl8i4IO
         bW7dPieBdeeCEZ7x0f0AaFzN8CktO0L0XWeOJ6zP1LzPWZV5dOL6ELUc7XsmffgF4sHd
         O+ait4lkt4yXtAlKLZgr0M0zh/ASpGCOIHsFTEj+AkDg0klq8Q/7qXBTYmZ/LoIHutJT
         AhYV0wJfwSBSW+aMPQHFKgdNDcuL7viIRt5uqJoYlbBz5pyFXGl1fwNO6xiyLtO7leeb
         H0dZkw22y48b5PV9H4FFlqOFQOII2iFKr2CNsuOG6Q4o1TIgyldrLQ3CwrPEg+Cn+tEF
         ybHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LAPnZVJ3;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sUWa3p1ivm+hOZSuKxLXr2e0Q7ThgpLTM2sqUITAVwU=;
        b=XIyOJPcVj9MkKzj0BEJl34nlQwd4UaeQaS3mSVpCfB4BMXYUx7CzYRhOOidYB+/OqJ
         N3eY18wfeOz0KUv2S9+xtubqAy/GSRHJCCdvwkV/1V2b0fhgdsnTsVxSCiQOc6ZAYwXF
         LUwD0Sb+gfP65y5/yp6qOmpP4m9xjMJpPHs/MtdIsSq2nHnzcrOn8mHt1+pgafjWOWQu
         FtnzLTjNf8MUaiTt5RmdT92qGuQQiHv2qSKxLXb/CoFbOpimBwdROjjcGfvQt9FWaZLY
         u4syTiyAO2clG/3VUd4n7j12s1P4ewdRqwBWlApHmCodDonA3BdJ67xoIDZdqybRcVep
         003A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sUWa3p1ivm+hOZSuKxLXr2e0Q7ThgpLTM2sqUITAVwU=;
        b=pSEBwCAxHhyCLUXj6B7lbrmkrRLIRxzxWTltn/hPR3kMgbhZkxld/S5tCAqa5lOX7y
         1RGtrSMn02ptGeXsL/nLK6XJSwEvsqpaqOqgIZS/iWzUvagV85NAhj6Xu20SkXA6smxB
         U2m3ZNE42n43RasdL7yOBZkIjMwfDXmJNcOpcdtSHpzs4eX9z1CCSD7cEsvQ8Kow0DqY
         chOrh5kJDd7Hylg8UBJgWK7+pEiI7+hbi1Fi1WbU9hH3PchJpyiGDFpza4fuI6Y4pbTo
         3rI37Ev9lk/H1hXNfo/7tGqZq+0qiJLDTZF9OsiXqsBwKGL0yCYGiKQhB9rLA3KwI9l+
         TQWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hyEuNxNWTqt0o7MUQvfxVuli1++sIk7klKc634GGg70wKyNd2
	SFE9qlBuWqgpiYMpsB/N9Zo=
X-Google-Smtp-Source: ABdhPJwrrIPRMemptT90CYFz57mJQ2zzSjBMQXeg6o5fRew5w8xsDW4xCdKLrYmD69EUn8a6kEGJvg==
X-Received: by 2002:a25:cc85:: with SMTP id l127mr8428258ybf.248.1612546990294;
        Fri, 05 Feb 2021 09:43:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b325:: with SMTP id l37ls642248ybj.11.gmail; Fri, 05 Feb
 2021 09:43:10 -0800 (PST)
X-Received: by 2002:a25:cb92:: with SMTP id b140mr7250816ybg.433.1612546989982;
        Fri, 05 Feb 2021 09:43:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546989; cv=none;
        d=google.com; s=arc-20160816;
        b=NM3KwJKjyNnFDTe/uUcXWZPHwO7p8aF5pXryVqFCA1SxLjK0UhO4iwLEgdyGikhPtw
         chyXCEs1wUb5p1LkrcFNQ1vO7HPxjV4pwsRFPgvWmt/Dprn9eWo08KaMUoblV4K2N76Z
         /x39X1S6rHBzTyLoRjylnwV+hLuaR+YL+yRNro5g/cG0OSYHqxnQeF8s+RN2ySf6Wkd2
         vrf6jRpnxA9mMWzBeYw79s9RdrKirVATKciDN0w8S0+aNghATrntvUqeaWG8R2bny3BS
         RP7gSG70WsrNqAgTX5BZVpEOZ6Aj14oSvnieR6OJQnbuc6B8GLvSTIIpZCyUs/ynMNSR
         OZcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+iwZmbreH1tXV2MUPlF+0UrmRZ6n3noCnfBzDZngFwo=;
        b=uorqxLwMKnhSFnrReCMTwOYkUvntzKZ68xnGUWEnv8rwB4gWeOX91b6NZRbzvDdRl0
         4XzJYmKuuUQ80KJhJKyAijym6YR7pYoxx3ne/lTUK6LcAghYzulcEqB4vWRnuLUrMdbb
         tzJ35d2hOE1eB/SY5jsvEVg7e02+opMIvxgrkoQs5S2JKYSpCLNiBbsLjooiFKv5wt/a
         n4bPbfuYnGy9KZwc01M0Q6pFfGk6WMkYXnYwiMj4VkxSeThfI8bA2yl6AfWV/L5al3IA
         mINFL0m80zfv3amfU+reu7s2a57poLLCNLEhPrH8TCtBaeS/StIBk4Cq3KN9MK9PwR9K
         0afQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LAPnZVJ3;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b16si594705ybq.0.2021.02.05.09.43.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:43:09 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E93E464DD8;
	Fri,  5 Feb 2021 17:43:04 +0000 (UTC)
Date: Fri, 5 Feb 2021 17:43:01 +0000
From: Will Deacon <will@kernel.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Lecopzer Chen <lecopzer@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mark Brown <broonie@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dan Williams <dan.j.williams@intel.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, gustavoars@kernel.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Robin Murphy <robin.murphy@arm.com>, rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for
 CONFIG_KASAN_VMALLOC
Message-ID: <20210205174301.GF22665@willie-the-truck>
References: <20210204150100.GE20815@willie-the-truck>
 <20210204163721.91295-1-lecopzer@gmail.com>
 <20210205171859.GE22665@willie-the-truck>
 <CAAeHK+zppv6P+PqAuZqAfd7++QxhA1rPX6vdY5MyYK_v6YdXSA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zppv6P+PqAuZqAfd7++QxhA1rPX6vdY5MyYK_v6YdXSA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LAPnZVJ3;       spf=pass
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

On Fri, Feb 05, 2021 at 06:30:44PM +0100, Andrey Konovalov wrote:
> On Fri, Feb 5, 2021 at 6:19 PM Will Deacon <will@kernel.org> wrote:
> >
> > On Fri, Feb 05, 2021 at 12:37:21AM +0800, Lecopzer Chen wrote:
> > >
> > > > On Thu, Feb 04, 2021 at 10:46:12PM +0800, Lecopzer Chen wrote:
> > > > > > On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> > > > > > > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > > > > > ("kasan: support backing vmalloc space with real shadow memory")
> > > > > > >
> > > > > > > Like how the MODULES_VADDR does now, just not to early populate
> > > > > > > the VMALLOC_START between VMALLOC_END.
> > > > > > > similarly, the kernel code mapping is now in the VMALLOC area and
> > > > > > > should keep these area populated.
> > > > > > >
> > > > > > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > > > > > ---
> > > > > > >  arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
> > > > > > >  1 file changed, 18 insertions(+), 5 deletions(-)
> > > > > > >
> > > > > > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > > > > > > index d8e66c78440e..39b218a64279 100644
> > > > > > > --- a/arch/arm64/mm/kasan_init.c
> > > > > > > +++ b/arch/arm64/mm/kasan_init.c
> > > > > > > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> > > > > > >  {
> > > > > > >   u64 kimg_shadow_start, kimg_shadow_end;
> > > > > > >   u64 mod_shadow_start, mod_shadow_end;
> > > > > > > + u64 vmalloc_shadow_start, vmalloc_shadow_end;
> > > > > > >   phys_addr_t pa_start, pa_end;
> > > > > > >   u64 i;
> > > > > > >
> > > > > > > @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
> > > > > > >   mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
> > > > > > >   mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
> > > > > > >
> > > > > > > + vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
> > > > > > > + vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> > > > > > > +
> > > > > > >   /*
> > > > > > >    * We are going to perform proper setup of shadow memory.
> > > > > > >    * At first we should unmap early shadow (clear_pgds() call below).
> > > > > > > @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
> > > > > > >
> > > > > > >   kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
> > > > > > >                              (void *)mod_shadow_start);
> > > > > > > - kasan_populate_early_shadow((void *)kimg_shadow_end,
> > > > > > > -                            (void *)KASAN_SHADOW_END);
> > > > > > > + if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> > > > > >
> > > > > > Do we really need yet another CONFIG option for KASAN? What's the use-case
> > > > > > for *not* enabling this if you're already enabling one of the KASAN
> > > > > > backends?
> > > > >
> > > > > As I know, KASAN_VMALLOC now only supports KASAN_GENERIC and also
> > > > > KASAN_VMALLOC uses more memory to map real shadow memory (1/8 of vmalloc va).
> > > >
> > > > The shadow is allocated dynamically though, isn't it?
> > >
> > > Yes, but It's still a cost.
> > >
> > > > > There should be someone can enable KASAN_GENERIC but can't use VMALLOC
> > > > > due to memory issue.
> > > >
> > > > That doesn't sound particularly realistic to me. The reason I'm pushing here
> > > > is because I would _really_ like to move to VMAP stack unconditionally, and
> > > > that would effectively force KASAN_VMALLOC to be set if KASAN is in use.
> > > >
> > > > So unless there's a really good reason not to do that, please can we make
> > > > this unconditional for arm64? Pretty please?
> > >
> > > I think it's fine since we have a good reason.
> > > Also if someone have memory issue in KASAN_VMALLOC,
> > > they can use SW_TAG, right?
> > >
> > > However the SW_TAG/HW_TAG is not supported VMALLOC yet.
> > > So the code would be like
> > >
> > >       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> >
> > Just make this CONFIG_KASAN_VMALLOC, since that depends on KASAN_GENERIC.
> >
> > >               /* explain the relationship between
> > >                * KASAN_GENERIC and KASAN_VMALLOC in arm64
> > >                * XXX: because we want VMAP stack....
> > >                */
> >
> > I don't understand the relation with SW_TAGS. The VMAP_STACK dependency is:
> >
> >         depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
> 
> This means that VMAP_STACK can be only enabled if KASAN_HW_TAGS=y or
> if KASAN_VMALLOC=y for other modes.
> 
> >
> > which doesn't mention SW_TAGS at all. So that seems to imply that SW_TAGS
> > and VMAP_STACK are mutually exclusive :(
> 
> SW_TAGS doesn't yet have vmalloc support, so it's not compatible with
> VMAP_STACK. Once vmalloc support is added to SW_TAGS, KASAN_VMALLOC
> should be allowed to be enabled with SW_TAGS. This series is a step
> towards having that support, but doesn't implement it. That will be a
> separate effort.

Ok, thanks. Then I think we should try to invert the dependency here, if
possible, so that the KASAN backends depend on !VMAP_STACK if they don't
support it, rather than silently disabling VMAP_STACK when they are
selected.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210205174301.GF22665%40willie-the-truck.
