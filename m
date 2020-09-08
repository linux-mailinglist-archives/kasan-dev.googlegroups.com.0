Return-Path: <kasan-dev+bncBDDL3KWR4EBRBK5Q335AKGQE4T52M5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 98D652612D6
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:41:48 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id w128sf2237451oia.10
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:41:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599576107; cv=pass;
        d=google.com; s=arc-20160816;
        b=wTnhQUZs4fhXAOnf64trrV36e8f1JV4Erya7ZQgzw7VeS31adTXBjAVAuvj7DIjAzx
         1Q8bZNg2Okoz0/g7tELGuv2yEaBjLrzjqRr2kzMaBjnAn64EFOnd9ZMzakJPnBEM72BX
         f2RKvmxCakn1uAB8zA09cPOvGS68Gi0RWPMOgG8LNgNIZXxRVk0+445Tj4FO3nT5oLg7
         msQlXjIBLwAH56B8/5qnVGwMOOxLF4yQY3E6Z6x8NWHf1ZqiFgnz3aOW12YQUbe7jFPw
         IwdVJf11XoaoQ/G+hUXA5qcAHf0NOrrSXz5ug5YZpfMJAznMv7ENGdWgdWoH0QtQUlYv
         2tCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=FIXWvDFco0IyE5tl69QoCOPhz0Bcd9/VTaRAxHUd0NI=;
        b=s+uV24RcGoipOqy7uo6tup2L+SRiLmAFdHXb9RWwjr9AfJHdFm1K6og9VkdzGnM7P5
         /3YYMPbVTNakNBiCY9K/hAS4nysKlRObPRS8/RqPV5QV6/yEcJTDC/0RAFhNorinJBic
         ughRjQ6vp8zIjpmNKATbfmucXy2umJHYqIJkc2FbK3RwVVa/3k45pwjtgDbTuQvbCmuN
         3Zc0Fd+O5g3kDljtH90dqn1nHVzODxX/ikPUqZxn7WGHN+inN/pbzZEE9G8c3VqYez1s
         u+m/9wDKLY8RKbpFUOO62Vf5xw/FYdvdRpqrYpnZD5HvpfZKkVkSHFDyzhCpWbaYoSFN
         OpVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FIXWvDFco0IyE5tl69QoCOPhz0Bcd9/VTaRAxHUd0NI=;
        b=FKpRSlBfOLNdvOgwatUB42ZsdDUtzkZoQfm4GOBnf3BzzkhP1D5dE/GNC9cxvDJM1S
         YpnTGdqAyQYVFfaYRpfbsqCc/X6mij4+oJrf+nv6M3KUWOY03YTr3w7bB8kiycRESe1f
         K9jLXQoc2WgGoj80CJjb86YlzBsjGNqoK5RIDF5A1G29icIYEnRCus37O9pmHDJyUURs
         vWzZP8PSBukG+tSt8qXNOc8MSWLytQwQD5gM8Rn/aS4C5Z6rNUGUHPT6XZeX4T/Ag+cQ
         dlhKAlrPg2j8dGpGi6atFLcq9bFV4OTQ1w/pI+FX1meWWzJM0oiN/So9PxGjiwaKYwfi
         nr7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FIXWvDFco0IyE5tl69QoCOPhz0Bcd9/VTaRAxHUd0NI=;
        b=n3GT1+VYDOx0mMtSlwJSjBwhgSAlMvNlT1F8tzYK3OKjYJniBG7WReTRevbxUSl+EJ
         Eyo506oXaIMM6NW2d76qiE8EwuFLIpTIHDd3t8B8IaxE+1A1pmTwrehEdW+C8V8AzF2A
         5kmcn3MdNiDYSJ0S7IgsoMZNrO/Qo1B46mo0DlohxdQX8ZzuIpW4jAKarppLJpg2i/iG
         tk5zzPVeTGQsAqf+gFDIrqLzHOVwaCE/oQ8pi7/qh2cTzGnekCtEEQF3wpP2vdDBQQyW
         HHuTZtmwBNXvi3HGRLdj8EhZ7z9vr5vkhhXZ8jxiS6yX88aJb/jJA0dhM+Z92ZcYiTrX
         r1EQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531g+7eOGyt93ve+8I/8xUOOTil+BTbkvfPQs4lfRpKv4vpoXk29
	otR6sv4hpogzsf6t5lVdJAU=
X-Google-Smtp-Source: ABdhPJzVV2FjZwjATOBbnU4MLxO4U2xUMBYS3fZZoxyas8JwT+iIRskNDhkaN5eRwKyfM62+18mN/Q==
X-Received: by 2002:aca:1205:: with SMTP id 5mr3046257ois.23.1599576107580;
        Tue, 08 Sep 2020 07:41:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2513:: with SMTP id g19ls1344504ooa.0.gmail; Tue, 08 Sep
 2020 07:41:47 -0700 (PDT)
X-Received: by 2002:a4a:9833:: with SMTP id y48mr19112654ooi.73.1599576107214;
        Tue, 08 Sep 2020 07:41:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599576107; cv=none;
        d=google.com; s=arc-20160816;
        b=IHPyB53jRTPVi3Nz1ky5CXz+XeewmV1iENJe0zKr8LQ0Y11VPPpxqmdibEbKUarNiw
         JBpV5HBwtygczKkoQkFM1i4dDiEjIprWglFLrFKXtOkfrzkAmVoYtvjzEzUd4wuu9z8E
         BIpZzL7vrMjKPM1zMtvzKBUmBrxAAXtPXEYaizBJTLCM9IMwu2hlOoc5vL62mXR1e0HJ
         Rz8u+CivvYFrg0y/ikr1W3Hnp1Y4RhNSrRMXrtw+7p4Nfl3lKL8Of8kX6BssJCI/P5oc
         6QdHhaxjEpewS84hrt7GbZf4/JDcynwldflnbNhgoxQBnFKodl/RyZWQlZP9SZDrJaHJ
         LHxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Pq4J2NnfUd+1Pc40yb24NgBzbHzhJ0SXNWzcle1Fztw=;
        b=0yV/KACFsWXXxRaQYAAec8jKeSDHTmNL1XmMzuTgwgcqpIibl31QQh8TRXf+Rlw2hm
         EITcvudYcRp4vskJiWizZNIneJ2JcmgDCqXFJJudr2A88CeuEhN3XI0nEFn9LAUVBqvs
         uv7LQWJx8nX44++CWGwCbGpD+CHjBfFgEBhoqP4vUN+/D0Kp/13t83YsW12dLQLS9xe0
         Cd/j2mRvvTZToo9SfQkLRbFw9ecpwN4Ho46Ks/whoVcSM+zCwrb0bIPq2HmmSzoMIqXo
         Ilhf8r3kwC1Iby+pSAT9qc70PhehC97+RejaG8pqL6I9Z+YCMRElX7kxUKcpG9NSMCGN
         72Ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i15si705606oig.1.2020.09.08.07.41.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:41:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.48])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E1F6221919;
	Tue,  8 Sep 2020 14:41:43 +0000 (UTC)
Date: Tue, 8 Sep 2020 15:41:41 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
Message-ID: <20200908144140.GG25591@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia>
 <CAAeHK+x_B+R3VcXndaQ=rwOExyQeFZEKZX-33oStiDFu1qePyg@mail.gmail.com>
 <20200908140620.GE25591@gaia>
 <CAAeHK+zkWojbbq1WgoC2D6JuR=Jy+jSU78PF74qdmD0aTg6cQQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zkWojbbq1WgoC2D6JuR=Jy+jSU78PF74qdmD0aTg6cQQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 08, 2020 at 04:12:49PM +0200, Andrey Konovalov wrote:
> On Tue, Sep 8, 2020 at 4:06 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Tue, Sep 08, 2020 at 03:18:04PM +0200, Andrey Konovalov wrote:
> > > On Thu, Aug 27, 2020 at 12:40 PM Catalin Marinas
> > > <catalin.marinas@arm.com> wrote:
> > > > On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
> > > > > diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> > > > > index 152d74f2cc9c..6880ddaa5144 100644
> > > > > --- a/arch/arm64/mm/proc.S
> > > > > +++ b/arch/arm64/mm/proc.S
> > > > > @@ -38,7 +38,7 @@
> > > > >  /* PTWs cacheable, inner/outer WBWA */
> > > > >  #define TCR_CACHE_FLAGS      TCR_IRGN_WBWA | TCR_ORGN_WBWA
> > > > >
> > > > > -#ifdef CONFIG_KASAN_SW_TAGS
> > > > > +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > > > >  #define TCR_KASAN_FLAGS TCR_TBI1
> > > > >  #else
> > > > >  #define TCR_KASAN_FLAGS 0
> > > >
> > > > I prefer to turn TBI1 on only if MTE is present. So on top of the v8
> > > > user series, just do this in __cpu_setup.
> > >
> > > Started working on this, but realized that I don't understand what
> > > exactly is suggested here. TCR_KASAN_FLAGS are used in __cpu_setup(),
> > > so this already happens in __cpu_setup().
> > >
> > > Do you mean that TBI1 should be enabled when CONFIG_ARM64_MTE is
> > > enabled, but CONFIG_KASAN_HW_TAGS is disabled?
> >
> > What I meant is that we should turn TBI1 only when the MTE is present in
> > hardware (and the ARM64_MTE option is on). But I probably missed the way
> > MTE is used with KASAN.
> >
> > So what happens if CONFIG_KASAN_HW_TAGS and CONFIG_ARM64_MTE are both on
> > but the hardware does not support MTE? Does KASAN still generate tagged
> > pointers? If yes, then the current patch is fine, we should always set
> > TBI1.
> 
> No, the tag is always 0xFF when MTE is not supported.
> 
> Should we then only enable TBI1 if system_supports_mte() or something
> like that?

You could add it do this block in __cpu_setup:

https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/tree/arch/arm64/mm/proc.S?h=for-next/mte#n429

It needs a few changes to have "mov_q x10, TCR_..." before the MTE
check so that you can add the TBI1 bit in there.

system_supports_mte() would be called too late, you want this set before
the MMU is turned on.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908144140.GG25591%40gaia.
