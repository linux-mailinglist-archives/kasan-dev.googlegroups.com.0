Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJFUW75QKGQEFB56JDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id A0951278651
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:53:09 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id r24sf1969599pgu.23
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:53:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601034788; cv=pass;
        d=google.com; s=arc-20160816;
        b=jyjggxaowLiqvK5Eiq4ZpGz5ILDWhCPl0Z1P1pmmNvW0VKqhBIAJlkFXIkbK1GvUeH
         PrnvR4EGy9H1h0S+nczTGbkaz85R2RnP1b3VUfguGT5/IkIrnIqH9cXZztPK6+xqSRs9
         re3VZPCxD5OHiySbgWyZsVMD1KhgNLAns9acVbyK3khZVLG2OlxsQGY0U459ibeogN9p
         P4BSCV9YPXLRW24BIzu7DXzrd7PrudrPYHGUl/KZy8wBpBrnLUdw74IdDRG7PJ0jy73m
         qTdZygAf8OcK/NZr78w+l1cUEmlJxi8+q+o01QxXr/yKipXPlzP0jUftqLUGDzZcAxgU
         5PCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=w536bqJanEPm/De3qAVW3dLZ99l7km6KIexzulpV0Ws=;
        b=eBmfyp2Q/4Km5Vc2MtPw1jPB89pPrO2dCJLoGVu967vuVfKUWtyAWRvFJSqKQN2eDp
         olqhRp9w4QCMDPcsvocw6xZyAOBE/01JmREU3275JrFE+MFD5C+nEMqC29N3d7livgFc
         9vLPdlVr+MnX47KRYp1+j9us9SZaGD650J6leRhsZsC4fuzC0uAmPVzPtrPlOGpQZkTO
         yISMOr6VyrY6zsj4eNA10JMyYC2ZS4AFIDyDGYGfKrVIruEkfYXnl2Q2BMe1+vfS4w3t
         6X6ov9ErOnIb6uJmNFRZ4TBAQKu7lHcwEm8FDxYf4eH8eGpG8sLTcpBbi2BQQDhww72U
         x4+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VNgZuBxU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w536bqJanEPm/De3qAVW3dLZ99l7km6KIexzulpV0Ws=;
        b=RFXF6zNAPKGMk65zUYfQ5vbLr0c0LHY2qZWhlxXLgbPm3l+ly6Y/EX6altaBkNvSzN
         UWC97O9EZZE936KhKrU7ORXjKbdv5i8Y8v+/elgQsk2bHDeTkwH+Mupsq9CjcYh3wcit
         1tKr0EjVQ2Mw+WiD+Szt6H2gE3Ftzpe/xINUBax+9cdd7lI34eakm2ni50dYm5QgNKx6
         uZkK2DKJjr8w+jggVvvNPbiB+n5L72MMNZm/iA+q8VJVoiTeEETUntl24EK4g6jeHQxZ
         M7KLLu80VdEawvPOcoVLDXT1wG3iwVV/7TxF3XSsbpbbloqV+M/iHLSdESeqSlZ2r0mW
         K7Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w536bqJanEPm/De3qAVW3dLZ99l7km6KIexzulpV0Ws=;
        b=NR4yWWcm+wgcbqFJ4+JBLn9IcSfEPbRS7mTVBTG+DufP+Q0SqaVee4yJQSAFgPPln+
         A2C5/WgSmE3mJLTfxnNE1JH95GBDCJE8B6/3VHzGvQl63KZvN8F/OCVk9WfbcerSnex3
         VUZKdeqMK56k6/qhBLceR7LGnE8hFv8Nfk6YWFCTSXehFCKqJb32BX+2IgiPcJb9HpLu
         IlSCwCpyYbUR7Bxfqq9LK1aiPp26/Xz9/KnGLOM33HpDyMkx3LRQrjh59eW+0w9uo2ps
         IefiwtsH6ZgXyKLy3iF0VUxZHPOx32WeobaDKEMeVz4gMdaidkIzcjSzTRDFZPWcAHaG
         JX4A==
X-Gm-Message-State: AOAM530bhkkeExp1V6Fw8TD5Qf4CVocAcRJfms2G4Rtbo0qEDO7DvHmT
	NP+mnvpDSdy2d8+58AkcLhA=
X-Google-Smtp-Source: ABdhPJwbg6HwKFbEb2Qr9wqY2sN1Y9ro9hUvuIFKDrpi3P0zcfflB3tMBUKEuH85tH5fxDNePYk57w==
X-Received: by 2002:a17:902:7041:b029:d2:635f:65b1 with SMTP id h1-20020a1709027041b02900d2635f65b1mr3462330plt.17.1601034788317;
        Fri, 25 Sep 2020 04:53:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4812:: with SMTP id kn18ls1197281pjb.0.gmail; Fri,
 25 Sep 2020 04:53:07 -0700 (PDT)
X-Received: by 2002:a17:90a:448a:: with SMTP id t10mr2362811pjg.19.1601034787750;
        Fri, 25 Sep 2020 04:53:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601034787; cv=none;
        d=google.com; s=arc-20160816;
        b=VVEgDaoK/HzFn0NwMGK5VIP+vqjkGVVGoeSIoemZqNIsDnF58uSRao710uWsMe7d1u
         ctrFELurSqCNmHHEBbHzXxQHZKKpijNB1+Ob62w9na5YtWB63rcRRrAV5XRHgh0UM8cW
         PLBgLI9Y5ZPmM837Dxnps6LS0QSd3oiBf079wScFKwFpYNrlBa/xv/20HFPJwm3saguQ
         yZgJEX0hkNy+w0b2az6CrYwQJ5DOg5VhVGCDPgaDa0fyXcJeanIPlRwckIfwcVJbsmWg
         ocD82CRPpDpD3L+Lua7Mv4cp7gR1Wi50hioMAS3kQc4gki0tXyWoFaDTnl8NLPUw13ux
         oT1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A1oOkyfsqFH1LfQrqPkW7aNFfIeXKev/R5cazxL0aFM=;
        b=o4dCSkpPvK79kabENvhpr/XPKp79jZ+LWEwgoOp+IFmFRZHRvB3rG4GYGPOGk1f+oQ
         1HB7VJPQ+3STHUnmdyyG7ulVUe8DEbs0a6OXtT87wwuf7Y0hFM40QbH/d3iw86R/tR9e
         OMOGH3sqtWKkt173GrNz0u6oFbF/9qLjGwJcgkpp+J7HQOmy6vhHw+iSP33k3PURqW3Y
         PgUqVTcdjmm0Dh7BjO8ff69r0/PJxh2ynB4W2l3mAtSaidyJnzAt3KJDmEIBWwMP/hUl
         8wCnuLB0F0ZzzS5X79tonFWyvwsCBgKWWzCgFGePGZ7yHw2p1bUaH66vtLdbN7gVGfNm
         FgsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VNgZuBxU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id d60si220474pjk.0.2020.09.25.04.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:53:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id k13so2950714pfg.1
        for <kasan-dev@googlegroups.com>; Fri, 25 Sep 2020 04:53:07 -0700 (PDT)
X-Received: by 2002:a17:902:b117:b029:d1:e5e7:bdf5 with SMTP id
 q23-20020a170902b117b02900d1e5e7bdf5mr3803333plr.85.1601034787254; Fri, 25
 Sep 2020 04:53:07 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com> <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
 <20200925104933.GD4846@gaia> <CAAeHK+zLFRgR9eiLNyn7-iqbXJe6HGYpHYbBXXOVqOk4MyrhAA@mail.gmail.com>
 <20200925114703.GI4846@gaia>
In-Reply-To: <20200925114703.GI4846@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Sep 2020 13:52:56 +0200
Message-ID: <CAAeHK+x=bchXN4DDui2Gfr_yNW4+9idc_3nQAyjRTwMN6UuvHg@mail.gmail.com>
Subject: Re: [PATCH v3 26/39] arm64: mte: Add in-kernel tag fault handler
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VNgZuBxU;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
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

On Fri, Sep 25, 2020 at 1:47 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Fri, Sep 25, 2020 at 01:26:02PM +0200, Andrey Konovalov wrote:
> > On Fri, Sep 25, 2020 at 12:49 PM Catalin Marinas
> > <catalin.marinas@arm.com> wrote:
> > > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > > index a3bd189602df..d110f382dacf 100644
> > > > --- a/arch/arm64/mm/fault.c
> > > > +++ b/arch/arm64/mm/fault.c
> > > > @@ -33,6 +33,7 @@
> > > >  #include <asm/debug-monitors.h>
> > > >  #include <asm/esr.h>
> > > >  #include <asm/kprobes.h>
> > > > +#include <asm/mte.h>
> > > >  #include <asm/processor.h>
> > > >  #include <asm/sysreg.h>
> > > >  #include <asm/system_misc.h>
> > > > @@ -294,6 +295,11 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
> > > >       do_exit(SIGKILL);
> > > >  }
> > > >
> > > > +static void report_tag_fault(unsigned long addr, unsigned int esr,
> > > > +                          struct pt_regs *regs)
> > > > +{
> > > > +}
> > >
> > > Do we need to introduce report_tag_fault() in this patch? It's fine but
> > > add a note in the commit log that it will be populated in a subsequent
> > > patch.
> >
> > I did, see the last line of the commit description.
>
> Sorry, I missed that.

No problem!

> > > > +
> > > >  static void __do_kernel_fault(unsigned long addr, unsigned int esr,
> > > >                             struct pt_regs *regs)
> > > >  {
> > > > @@ -641,10 +647,40 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
> > > >       return 0;
> > > >  }
> > > >
> > > > +static void do_tag_recovery(unsigned long addr, unsigned int esr,
> > > > +                        struct pt_regs *regs)
> > > > +{
> > > > +     static bool reported = false;
> > > > +
> > > > +     if (!READ_ONCE(reported)) {
> > > > +             report_tag_fault(addr, esr, regs);
> > > > +             WRITE_ONCE(reported, true);
> > > > +     }
> > >
> > > I don't mind the READ_ONCE/WRITE_ONCE here but not sure what they help
> > > with.
> >
> > The fault can happen on multiple cores at the same time, right? In
> > that case without READ/WRITE_ONCE() we'll have a data-race here.
>
> READ/WRITE_ONCE won't magically solve such races. If two CPUs enter
> simultaneously in do_tag_recovery(), they'd both read 'reported' as
> false and both print the fault info.

They won't solve the race condition, but they will solve the data
race. I guess here we don't really care about the race condition, as
printing a tag fault twice is OK. But having a data race here will
lead to KCSAN reports, although won't probably break anything in
practice.

> If you really care about this race, you need to atomically both read and
> update the variable with an xchg() or cmpxchg().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx%3DbchXN4DDui2Gfr_yNW4%2B9idc_3nQAyjRTwMN6UuvHg%40mail.gmail.com.
