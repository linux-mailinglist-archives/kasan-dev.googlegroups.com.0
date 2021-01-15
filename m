Return-Path: <kasan-dev+bncBDX4HWEMTEBRB24DQ6AAMGQEKDED6TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B8D62F80AD
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 17:25:17 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id w26sf15592115iox.21
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 08:25:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610727915; cv=pass;
        d=google.com; s=arc-20160816;
        b=oCVFUcYy4Cp2I9BaiySoL20g9dWBZlyqZYzjIU+DexnjyXPCvS1uPsCf8wfwurr37a
         rue7+GsfY2pN4MGCTufs8eJW3WLW6pKmv8BHrLcT2rduSbOaG2TlkA4PS0Kl22Y5onLF
         iyBYR96UwWxh/JN5yOLJQvfstDfIgi/RRMNcGMs/9stxVmar+cY2eyeiWizqnQLQQryQ
         ntHo9LwTJkYi03dEh3QVBB995411+daYNASjv41HlMqh/e6LQTjtG2AC8iYIhEoeZWSR
         7+43pJO+JJx1S8VTvgpR1XXvz/TRlUclFq9GUyyUziIZjzUOhwUywix/NVPv9ZmUCGUz
         Tmxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/sDWZUqfY61xNKpb/cmBnDLL4MFN7Z3lTb6Dr4tr0dM=;
        b=LmHSazix7BYHGp8z7udMEu5Ph51b+GpqgvNQP7xtkc7PJY5rNmYaY0mV1LSbzL7duT
         qWtT2Qa2PcsxLQ1mRVU3NU92nYqcdgsg+71Ye+GTADYkj1hbLfzzczVGIiuY7TQC/ETt
         APHMiawZWpzC3V/9OdrZ5bq8Di4JcG3GQJLfAkECmXxIR0OLKY3IdtXIULQVBehg7haG
         Vnzl4i0hvvzeHskrsxiEkW/Nn05xHolHNQTtMKAcS54/vgS++FKrA7+EUfvE8x5A1r5R
         iXj7+hz+yevQvgN/m7xsHoMJWNbATVw/dxfHciMCUe+iMJ8iVLXcB7Go4wMUOEOw7XFc
         wquQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bDO0sh8N;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/sDWZUqfY61xNKpb/cmBnDLL4MFN7Z3lTb6Dr4tr0dM=;
        b=msO8ysNY0SBA24b1GoFBKIOuh71wTAjRet36SRzFh4ggxMGYczu5Tba0IvRWYJqBii
         uddApY/n4/JaGM6wZXr+jvK5rUGWFPBWMkNCctQXerD4DxCMQX/GCgKLh3WJ9rgoc1jC
         F8pHrUqZoXVlGUwmag1KJGweiWjeWQ95gktFFdkEfPMEOXKX5GXxRjRZKF/60WL6ed+D
         AveexZ8qTM4Hp2ENzfam8qbk9Db/D3ytKbXGntjJEjGC1zfDRY4o4ZQw+C2fE2Az9f/l
         dYCt3yiZynyC7Qfiy8NPCfcNr4Nxj1FRIC2zSVzTN5CnEhhxem0KiDA1O5p35ILJkbU/
         JGPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/sDWZUqfY61xNKpb/cmBnDLL4MFN7Z3lTb6Dr4tr0dM=;
        b=MdakrvQFAOkhMie4KGOf+jbPS04siWq4XRRx6YUT+jaZUNhoMIHZ1XEEfGYxNL7yXJ
         BML3dEhw64HMdN3AuZxbOb6jP5H2q9iT4cKeej320UgcR9fy/B4YBRzDzfVbKU/lsHyK
         SDAI4n5Sjv/BjabgRblDIKVdMhKJzoXLMhjN4WyePLNtKfNZpG9E4bavAhpRw6lVNT5Q
         Aweo6R3bVumReP2AAdDX1FA4Lr9rtq5mbzFOlSiuhDMx5D/WmFW5R3/KhhkWzeogztHD
         E0AW05KFhUfH4O0eOXQ+j7RcbqrBMuatrDyMHlQC1ZHiSlXNgB8AyyLsvYGLz1TRU9LE
         z/pQ==
X-Gm-Message-State: AOAM532/gyMqDrcpDqjXFqbgKxedVUkE1wvIU5/oR9AlOflk+IcDI8+a
	GWOCCPFqkKHY5eA/6sORoC0=
X-Google-Smtp-Source: ABdhPJzNM3KGAklKo/nJwyTc7dWtBdan8UWnUydL/29lCctmjaD+kkbSZu4Nphyq4NMdQPvl4XT/6w==
X-Received: by 2002:a05:6e02:12cc:: with SMTP id i12mr6112255ilm.113.1610727915819;
        Fri, 15 Jan 2021 08:25:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:48c9:: with SMTP id j70ls2687032ilg.6.gmail; Fri, 15 Jan
 2021 08:25:15 -0800 (PST)
X-Received: by 2002:a92:358a:: with SMTP id c10mr11399884ilf.258.1610727915518;
        Fri, 15 Jan 2021 08:25:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610727915; cv=none;
        d=google.com; s=arc-20160816;
        b=THybJVUNo+PL5AeqO0A+l0k96RmMxiNYvlfpNcdh4gr05r3vCOFHT3wYqwF8l+Nlts
         1IVZUrMU05QCGPDo51XDyF+DqMLPs4C/0Wx3OGnOrZBrMENuVOpo1EJycaf+g6zyM/8i
         XtAcS5L1x7BPZ8wsRAfurhpPIjVTQtimXarSi3qvydXUYNFiV1OwvObecaS41i7jSNQq
         9R1uwE7DkQzdrV+EPJ0pn4lGI3PhBtshTizMZhbhQ5l2lhPyDAFBFX0BbiIVyrq/m31/
         HnzyeSCxoVUY94n1Wvi3oAh+cXbKp9ndUXpnaLatMrZvc/FH2I5vhFzJkyS7LlbC3OlB
         9PxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cfexXFziwrKRfOX4l3+6YvZjjwRLIjObzMGfUtSVyeM=;
        b=UdabiSmDzPcE96WuzI8hCYwyvzqvDS9YimDOlyIE//u96gbDJjEnqPByVwq4MTLRu1
         Y6QgiZVdzzgmQt8U14ZlfzkoLkIe+pS+gQ7E/QuxyolirAG2BB+zZHzZ+BuEi04ZDpno
         vvBvjZcS5vyUTZAjnA/NeI4C+CsRkGdCdhbSk6q995WxOHG3NcHeB5LTupmjZOxORWPx
         2OWJyogrjvHJo4WXw71wsjaXXd1zFqJ2zlg61DSLKqPO9rr28j4OdXoeUh4HdrbKTAP0
         Qz7An3mubeRtjkHoZG7MHQwiMrCe8UTGd2eXAq3DofnGFmqIiiBaahFU87xT4jxPGPbV
         2GOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bDO0sh8N;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id c14si1015311ilk.5.2021.01.15.08.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 08:25:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id q20so5800604pfu.8
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 08:25:15 -0800 (PST)
X-Received: by 2002:a62:115:0:b029:1b4:c593:acd4 with SMTP id
 21-20020a6201150000b02901b4c593acd4mr1100547pfb.2.1610727914773; Fri, 15 Jan
 2021 08:25:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610553773.git.andreyknvl@google.com> <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
 <20210113165441.GC27045@gaia> <CAAeHK+zThyq7ApsRTu-En7pL9yAAOrEpV45KOuJV3PCpdjVuiw@mail.gmail.com>
 <20210115150658.GE16707@gaia>
In-Reply-To: <20210115150658.GE16707@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 17:25:03 +0100
Message-ID: <CAAeHK+yZdP7d5nrZDKnk_Drezs7pr07_XH10wtjKe87BjEpiQA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=bDO0sh8N;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430
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

On Fri, Jan 15, 2021 at 4:07 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Fri, Jan 15, 2021 at 02:12:24PM +0100, Andrey Konovalov wrote:
> > On Wed, Jan 13, 2021 at 5:54 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > >
> > > On Wed, Jan 13, 2021 at 05:03:30PM +0100, Andrey Konovalov wrote:
> > > > As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> > > > that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> > > > while KASAN uses 0xFX format (note the difference in the top 4 bits).
> > > >
> > > > Fix up the pointer tag before calling kasan_report.
> > > >
> > > > Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> > > > Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> > > > Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > ---
> > > >  arch/arm64/mm/fault.c | 2 ++
> > > >  1 file changed, 2 insertions(+)
> > > >
> > > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > > index 3c40da479899..a218f6f2fdc8 100644
> > > > --- a/arch/arm64/mm/fault.c
> > > > +++ b/arch/arm64/mm/fault.c
> > > > @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> > > >  {
> > > >       bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > > >
> > > > +     /* The format of KASAN tags is 0xF<x>. */
> > > > +     addr |= (0xF0UL << MTE_TAG_SHIFT);
> > >
> > > Ah, I see, that top 4 bits are zeroed by do_tag_check_fault(). When this
> > > was added, the only tag faults were generated for user addresses.
> > >
> > > Anyway, I'd rather fix it in there based on bit 55, something like (only
> > > compile-tested):
> > >
> > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > index 3c40da479899..2b71079d2d32 100644
> > > --- a/arch/arm64/mm/fault.c
> > > +++ b/arch/arm64/mm/fault.c
> > > @@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
> > >                               struct pt_regs *regs)
> > >  {
> > >         /*
> > > -        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
> > > -        * check faults. Mask them out now so that userspace doesn't see them.
> > > +        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
> > > +        * for tag check faults. Set them to the corresponding bits in the
> > > +        * untagged address.
> > >          */
> > > -       far &= (1UL << 60) - 1;
> > > +       far = (untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK) ;
> > >         do_bad_area(far, esr, regs);
> > >         return 0;
> > >  }
> >
> > Sounds good, will do in v3, thanks!
>
> I wonder if this one gives the same result (so please check):
>
>         far = u64_replace_bits(untagged_addr(far), far, MTE_TAG_MASK);
>
> (defined in linux/bitfield.h)

No, it zeroes out the tag. Not sure why. I took a brief look at the
implementation and didn't get how it's supposed to work - too much bit
trickery.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByZdP7d5nrZDKnk_Drezs7pr07_XH10wtjKe87BjEpiQA%40mail.gmail.com.
