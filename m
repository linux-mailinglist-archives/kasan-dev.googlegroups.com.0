Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPXRSD6QKGQEGO45XTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF622A8513
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 18:39:11 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id p17sf1724634ilj.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 09:39:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604597950; cv=pass;
        d=google.com; s=arc-20160816;
        b=G5AgMfszk0dl6N65v6m13sdv505oijaAvsa0CuatXRZrnlWvYbOweOum0fhOFjpC4W
         F6iajCo6f+2c0nj2WXxoTqkKybKeimcvAjlF/pvTmskQxfUZnZFiyRlGZxd6YRL45noj
         oPreeingP0fYn/WeRbOssUdL1gweddrPS3Sln9hrF3M6AZ+PEbT5h40egQzBHd8ffRQ4
         OXM1WY9li1RAX2DTW16ocjOkMd/Gzl+PZ/gVyIDoWohh64AcvjO1BBbl3AXyKRsISLqp
         Ituen1HEs4sAA9eyGhpn01QPty2fPqnSm94ch+WjOqVdSX+pirH2VejADOvFkZj0l89A
         P2Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=5aN4ZhBXnadc0itSDsYEkgpN8duDtlxHke5GwfRFlLo=;
        b=XYRx+R2/IeVn0Z7QufN6EE2x2dd4kEaB6NylB4wHgap1a6ORnnlvZFjkMGjNjcvpLV
         HsbWhzED4Tf2aus1s+ypG/APc2bOSEB321uzAKAeMvSGUr1t8FSFPRJN8f2sIPOaWcAI
         yglqCjvZ6lODjdmtnSun6fULJdcLeQY7yLNdPsiWW1/RZylzRlMh6YX/D0TduZW4h8ZT
         ii+Br0+umgCQozBvQJIXBAXqebRc/ar4jy5ZkLIfL17vlTxczgqKY8UvRg2LjiOsQkbR
         OZGB2/r4juo3cu8yjo9ul6YEXzboMLBBPK5kQ/QPoY+KJNvzzx8m3gcDA3pEfoUX1Ncc
         vNJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5aN4ZhBXnadc0itSDsYEkgpN8duDtlxHke5GwfRFlLo=;
        b=ZB4UkCDGqzfN4TNgxpdx1bcA/Und6M8wwdPtaxauuvO25amOr2GApzqFSyKRyUzMc8
         81SdHUcX4eXnW7ForKncHUyW4kE+7SkpaFrvKLTxx31jnGKOZOY1aIK1IPLK63H9skR8
         MPmSn6m0KkcoUbRgoFGKBFQbylakrTJvDMAdtBAAcgNZ+MUSpqt7DX8p1CT8uZnDWhK9
         q+sXY0o2Ls8qgMGcqqhwwYZKt7AUNhYYd3jGnSiWj5LFO2KrBl6XpPmzwiydlgE6J1R4
         /tqfG8hve+st7JHUobeGxEcp0/Cap4mUIAR+HaDg0im+7seDP3B7SdPE6pwM59n7Rgde
         eFvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5aN4ZhBXnadc0itSDsYEkgpN8duDtlxHke5GwfRFlLo=;
        b=HxqIM/Q1rvl/7dAhxoks77/i7MH05dixrgF56tsZMb/TwZ6J9gFUd0HjvOZhH2pi11
         hoLtddmQ8XYue1AVdGvKZ8HTgP9l+ZfcafpsW4b4tkGpiiukA+nt3hP7HxG/l17hbPmC
         IjvGu+AO91aAs55t5WhLk9mhOUyQbDuP2nEwDUnuTBupHlbU0NJA7kRmPKJLXhGxavbz
         3y/TfoA5+z+CAvfTNu9Isk69sWfUOZcV8zv6uL1FMhFlZy1vHHHrN3uKgfQnEEVnUysh
         Gt3ODnHUEplv7PpzjExd0H9VvHjcmg8dovRx6ZGtHrU9IpKgyZFRLjMdd9UPuoiQnKgu
         JQEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ui/ppU7ucdMNuo+zctuHwcdjY9Ko2/Xx5U6oMl4HnaSRN2DfC
	Tx2imLonGqk1NNCU0PtuYh4=
X-Google-Smtp-Source: ABdhPJyJXgwXWs0RsapeLv8nF7GF1PsD0r1Kyk7Dvb8Nup6dsOGqkSeVrvyfZRj87vusaZ9YF5Ahwg==
X-Received: by 2002:a92:da92:: with SMTP id u18mr2706289iln.266.1604597950579;
        Thu, 05 Nov 2020 09:39:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:50c:: with SMTP id d12ls453583ils.10.gmail; Thu, 05
 Nov 2020 09:39:10 -0800 (PST)
X-Received: by 2002:a92:5e9a:: with SMTP id f26mr2638471ilg.129.1604597949990;
        Thu, 05 Nov 2020 09:39:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604597949; cv=none;
        d=google.com; s=arc-20160816;
        b=NHFwv0s5TmQ/YQrOJAz48FmAi6QQkSwuJNZ7iqneJc+ZkSaNtXZ2QCYn/K/VuMURoT
         p4pIUis4huiDSfGqphPRIizIv1RD3ggj8D6/SZ0SbaTU4BWk6NygjeKdkmYuZIKauUzx
         Wu89ZzpfrKki+R6MA1oJ34U76iKnpoHav+F4IBUwnIsZ1JakHfEvKQhfhjMg+211p0hd
         xGdRyuVXW3rNcOEuL6t7smzEdrMVViUXJc0T2D/9/haEmOtSf3B9tVmMR0GHggRBixom
         OlKRM9hsmEMXSG5ETtgkFazS+KyN4Bug1FVV9BGvznF6uSBxJjLuWRuyDDfMz88z/rYJ
         mB7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=dGBre1Wc682Ydj4gYAiCG/zL4HrEoWdf4lmHT3KWEHk=;
        b=yWbf1GGzwrDv/kx9B3H3dMRyJyVoRyQvbWnqL/nETa8FvshQHvZSQcKiqGn7uL27r/
         qfRPHVhXVwPAjwCzPGK15x6R0ss6UeVcoBMOk+RLVTrQxJjvOfb5IFfxz5fzZhxAS0ai
         44HOiHDKbOpiAbLLv6hU0KJUcoRIWO+6GXSSLXbHWnEr1vk2TMNDRQkbaM5CXjWVZTo0
         vBbMqapePw/ZLCJi532tFpbAyBbxugS2FgmBa0DGtXxqn2J5KYViFhcNIOKjjE5UOt+0
         oIczA+8/kJGipX/+HhLke/mqz1rf0gHlu/5KICVQ6hyEVfy/kpc+3YW2itecjhvi75yi
         r9zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p5si121562ilg.3.2020.11.05.09.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 09:39:09 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7A230206CA;
	Thu,  5 Nov 2020 17:39:05 +0000 (UTC)
Date: Thu, 5 Nov 2020 17:39:02 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
Message-ID: <20201105173901.GH30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <20201105172549.GE30030@gaia>
 <CAAeHK+x0pQyQFG9e9HRxW5p8AYamPFmP-mKpHDWTwL_XUq7msA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+x0pQyQFG9e9HRxW5p8AYamPFmP-mKpHDWTwL_XUq7msA@mail.gmail.com>
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

On Thu, Nov 05, 2020 at 06:29:17PM +0100, Andrey Konovalov wrote:
> On Thu, Nov 5, 2020 at 6:26 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> >
> > On Thu, Nov 05, 2020 at 12:18:45AM +0100, Andrey Konovalov wrote:
> > > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > > index 06ba6c923ab7..fcfbefcc3174 100644
> > > --- a/arch/arm64/kernel/mte.c
> > > +++ b/arch/arm64/kernel/mte.c
> > > @@ -121,6 +121,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> > >       return ptr;
> > >  }
> > >
> > > +void __init mte_init_tags(u64 max_tag)
> > > +{
> > > +     /* Enable MTE Sync Mode for EL1. */
> > > +     sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> > > +     isb();
> > > +}
> >
> > Is this going to be called on each CPU? I quickly went through the rest
> > of the patches and couldn't see how.
> 
> Yes, on each CPU. This is done via kasan_init_hw_tags() that is called
> from cpu_enable_mte(). This change is added in the "kasan, arm64:
> implement HW_TAGS runtime".

Ah, I got there eventually in patch 38. Too many indirections ;) (I'm
sure we could have trimmed them down a bit, hw_init_tags ==
arch_init_tags == mte_init_tags).

> Would it make sense to put it into a separate patch?

I think that's fine. I had the impression that kasan_init_hw_tags()
should only be called once.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105173901.GH30030%40gaia.
