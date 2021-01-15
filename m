Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5NGQ6AAMGQE3TLVVTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 73D9F2F82A2
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:40:08 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id b11sf1847217oib.23
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:40:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610732407; cv=pass;
        d=google.com; s=arc-20160816;
        b=d5rUjAACDLfVZxLkqYpH90AQFuiePVcWEv8WVBwqwGFbvue2nZM9nXTv+/YVvC5H04
         TnMTp/3VJ4h7YfrHESs9PROtxxAY/fr0DkmQPKFo8Jr6YbmJTrTbqXouzme6hNcd8Zxn
         ZFSSdGTif6e2ua4/Tu0ZZKkuVsFdfWIK9KbFiDxc3NCe1NKxPo7FbX2K26f6gW9iEM2w
         PfrfVDlCSz4s0tksFpvTBvVqkntp4MJyzRh1TTBcSin9LVkM/EHt4pfzcuWW9eblGsYx
         S9C9vU0mZMOVzGcisv3soAQ+Ex7aFFTATqzmps9XzeUAXBwM1mkYEwcoAwPpU2zRnv2M
         fYzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zKr9+Y20MdQ64EhbeyOEBSdl6cKYq/74CJLcJi1b8QM=;
        b=0+vCtTlVAp4WDTjneoqpq9lokmGlf8uqHZwfIG9qY89R448YDXcYoSESQwKVsDLoNp
         fjJ2k9d6AVa/w82xAkmx5bC7MANB+HhohCRLybkVXSRxyoW8HaG7MBFByxbUcc+4LZom
         YbiIuoKxFH+Z9O7Xr13CJwgzX9juwlWIA67cdJ4e3aEHjj5zEf+ZW2NHgbimF0ztro0K
         yniqzmM1uyqYd3MP+aPYKofGgt6LHKwBU6g3PnTZp3IMKiGaJWKTo2l3gbN0kllOrwqA
         onzwGRvvTnXZQydScZ23U91HDzloc9zVpS/z+k4c7UPgFHvT+6ai7wqa+QqxQ3ea3lLe
         HzRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gJTpyu50;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zKr9+Y20MdQ64EhbeyOEBSdl6cKYq/74CJLcJi1b8QM=;
        b=Os3/Fsu+8iVoirBkOxKokzjhvMflPXtRbIdo4dLoOHpr72U3FsT6yM+P7T4FsmFavK
         +4aeXrTI+txamqQLEoeym3xvmptKNt9cJH3EWmvObi6gI9MP3i6Ti8ZmK+apPgOYotlH
         Cboxi2Oe2ge/fpK9YDFHr3LoMWfnXxyuNtHGais/oX189VRFGQbXTbkjU0/NJ4xWzyuk
         mADaDEg4YbhQAeTMhgCiki9ws5KHyZqMNqWw2zAdkVf1mYPP9/LOQ7iwSA16am0JPExS
         ILZekg8c7DCIizvfpiE3y7v4z5BGaOsrXYaDFW3WhT9qtAmAZTxsizZY/PQpmbKEUxCi
         AcdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zKr9+Y20MdQ64EhbeyOEBSdl6cKYq/74CJLcJi1b8QM=;
        b=ZkdWR6bmRraKIIyGgppFJlJC2MgwuCRDGBGs6s7YHvsG98m1NgQjfd4xSF1WNmOw7b
         zAonI9wI7vhFsrSTYud4RM87tViHuTS5+cZGpNlKy49juCWxhVydhSvm4HI2TLe4v4y5
         nXao5d3SndwoYU7BhQomB9aAvWwcW5KRXgMc0t1FtkeSH36FzupjbpVKhasfXPF1ZGbF
         5CCo4PPyp7TXtznmgW4VWJnAWZij6wF6ctO0bB1gE0UFnts/DWLn1M4zD9EwbCCP19OL
         NUpP6jCVzMXrMwieOUwvft/hHrS4xlEuZ277K5SNlA91DWK+ovM5gCMyd1bnvNYHoSCd
         f6Yg==
X-Gm-Message-State: AOAM533eoNvX2DuIYeB4EqzqZm87BZYwqeP0YhDI2h683jo3IsZP+/Ow
	oZY/WFV4YRKeVB78w9bBClY=
X-Google-Smtp-Source: ABdhPJxuZOn3CeLQiGseKaji4eeuyHH3gA4TH0UrPUTA0Gln7WNmlbZ5rTN8fl7Mi528ppw0qoYloQ==
X-Received: by 2002:a05:6830:1306:: with SMTP id p6mr8866852otq.244.1610732405932;
        Fri, 15 Jan 2021 09:40:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d15:: with SMTP id o21ls2469692otp.2.gmail; Fri, 15 Jan
 2021 09:40:05 -0800 (PST)
X-Received: by 2002:a05:6830:1210:: with SMTP id r16mr9167562otp.343.1610732405451;
        Fri, 15 Jan 2021 09:40:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610732405; cv=none;
        d=google.com; s=arc-20160816;
        b=HpkS/UwvuDd541BgbeOViANzQxqsq9qNLxSlSilh8qNuim/EIdjkqu9HYG1DqloT3+
         nXiEmSxXafnxDp+MyHBj7XO1FvvnFe3ZE4RDhdyJatj0aXsD+b6FRJ26rbT8NzA7fL1N
         wIb/GmAmTJf+UARP0w1gkCw3Blx1ygQtlDaVnyiSoAOLuh17sUiNXHxVusoOs0J/VKMI
         ZyMf4+wUpEqVJUkRyW/Ent3inhiKuFp4/LNpe9VInMS/cNxlkzi3v8WAGl7S84Pm7D0z
         kWW9Oy4TaQqwGJKH8kHazba0tnBVcXK6mANF24KYmllSJxwxtG1qMDctGZs8+N3dIMC4
         bJ2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SGVXpiw8I6lb3z0yqBCK7I13Qcilt0rv1FBT0p51gDE=;
        b=Q0rO2EgHgraXrhrg2KDsSfQ8glus2tyaT9ZYvyagChhxZhveI2Hk3k8abCVNbZP+wy
         jal0u4afaA+GqsyHy4UAwOly7PhAiEklkzQZpD0tkkbuVuxGhrmFCTyqXifFTIvNusp7
         rbIPV2PwstvT3zb1z7I6omb4KTTwVzB1Xo5h/+SLipad3lOcRkUhFoN1+y8IKdgPFs6D
         A546rQm/gLIXOGZwzEg7SGC+bJ9q8A0WSCwynMb3CNsR3pQbSL6rrkrDls6REWZvq1WL
         UqJw5f+ut/3em4CqeFaYQ7h7GM3iplzoMt3tOya7+Ou91Ute/rySKUGyLg4pijrnOpKY
         BXVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gJTpyu50;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id u2si866418otg.1.2021.01.15.09.40.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:40:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id x18so5060689pln.6
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:40:05 -0800 (PST)
X-Received: by 2002:a17:90b:1087:: with SMTP id gj7mr11467727pjb.41.1610732404627;
 Fri, 15 Jan 2021 09:40:04 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610553773.git.andreyknvl@google.com> <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
 <20210113165441.GC27045@gaia> <CAAeHK+y8VyBnAmx_c6N6-40RqKSUKpn-vzfeOEhzAnij93hnqw@mail.gmail.com>
 <20210115165558.GF16707@gaia> <CAAeHK+wNOcA4Zgi5R8+ODMuDkLuMSYHoLinPhoeGstd78TsPjQ@mail.gmail.com>
 <20210115170556.GG16707@gaia>
In-Reply-To: <20210115170556.GG16707@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 18:39:53 +0100
Message-ID: <CAAeHK+xxWVGd6K=hc-s_VT3iS3_wNg5=LohPLWQmW=MZ0PmKKw@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan, arm64: fix pointer tags in KASAN reports
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gJTpyu50;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Jan 15, 2021 at 6:06 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Fri, Jan 15, 2021 at 06:00:36PM +0100, Andrey Konovalov wrote:
> > On Fri, Jan 15, 2021 at 5:56 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > >
> > > On Fri, Jan 15, 2021 at 05:30:40PM +0100, Andrey Konovalov wrote:
> > > > On Wed, Jan 13, 2021 at 5:54 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > > > On Wed, Jan 13, 2021 at 05:03:30PM +0100, Andrey Konovalov wrote:
> > > > > > As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> > > > > > that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> > > > > > while KASAN uses 0xFX format (note the difference in the top 4 bits).
> > > > > >
> > > > > > Fix up the pointer tag before calling kasan_report.
> > > > > >
> > > > > > Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> > > > > > Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> > > > > > Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> > > > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > > > ---
> > > > > >  arch/arm64/mm/fault.c | 2 ++
> > > > > >  1 file changed, 2 insertions(+)
> > > > > >
> > > > > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > > > > index 3c40da479899..a218f6f2fdc8 100644
> > > > > > --- a/arch/arm64/mm/fault.c
> > > > > > +++ b/arch/arm64/mm/fault.c
> > > > > > @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> > > > > >  {
> > > > > >       bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > > > > >
> > > > > > +     /* The format of KASAN tags is 0xF<x>. */
> > > > > > +     addr |= (0xF0UL << MTE_TAG_SHIFT);
> > > > >
> > > > > Ah, I see, that top 4 bits are zeroed by do_tag_check_fault(). When this
> > > > > was added, the only tag faults were generated for user addresses.
> > > > >
> > > > > Anyway, I'd rather fix it in there based on bit 55, something like (only
> > > > > compile-tested):
> > > > >
> > > > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > > > index 3c40da479899..2b71079d2d32 100644
> > > > > --- a/arch/arm64/mm/fault.c
> > > > > +++ b/arch/arm64/mm/fault.c
> > > > > @@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
> > > > >                               struct pt_regs *regs)
> > > > >  {
> > > > >         /*
> > > > > -        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
> > > > > -        * check faults. Mask them out now so that userspace doesn't see them.
> > > > > +        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
> > > > > +        * for tag check faults. Set them to the corresponding bits in the
> > > > > +        * untagged address.
> > > > >          */
> > > > > -       far &= (1UL << 60) - 1;
> > > > > +       far = (untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK) ;
> > > > >         do_bad_area(far, esr, regs);
> > > > >         return 0;
> > > > >  }
> > > >
> > > > BTW, we can do "untagged_addr(far) | (far & MTE_TAG_MASK)" here, as
> > > > untagged_addr() doesn't change kernel pointers.
> > >
> > > untagged_addr() does change tagged kernel pointers, it sign-extends from
> > > bit 55. So the top byte becomes 0xff and you can no longer or the tag
> > > bits in.
> >
> > That's __untagged_addr(), untagged_addr() keeps the bits for kernel
> > pointers as of  597399d0cb91.
>
> Ah, you are right. In this case I think we should use __untagged_addr()
> above. Even if the tag check fault happened on a kernel address, bits
> 63:60 are still unknown.

Yeah, I keep forgetting about [__]untagged_addr() too. Maybe we need
better names? Like untagged_addr() and untagged_addr_ttbr0()?

Anyway, I'll do the explicit calculation with __untagged_addr() in the
next version.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxxWVGd6K%3Dhc-s_VT3iS3_wNg5%3DLohPLWQmW%3DMZ0PmKKw%40mail.gmail.com.
