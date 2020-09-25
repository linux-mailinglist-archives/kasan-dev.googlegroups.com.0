Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVVHW75QKGQE5P2CB6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 348212785BA
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:26:16 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id a19sf1896907pff.12
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:26:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601033175; cv=pass;
        d=google.com; s=arc-20160816;
        b=wgJYcdHp3YGGapUXRxbxqv/+DwwtBnbcuAgwNfTYfaZc+ZdPsUMDmhuhWoiNbk2Uqa
         wu1va/QYMMZy/gZiYtzsrPC0wtKvLwDzt542a5Bt8odqXuIWlm/lgp94EUm9NCs9KejJ
         ciEIIBAHSWDemyxRjncKvXt41FOXiHrzalrIbBdvJb/vkbQ6wKV9zZUYDdt/SZmt6eoz
         vOEmqN3X2IvI1uFFA6zHfdGLlaGS1dJjsFUK4cv0d/jvk4I4EinIGW8eib3CnF1N1OKy
         cmj8sIWDGxKl7i3uqEebLg3jiFIg8jDYnFqkdi+ksSHepfE1TfUPpUxiJoMYoki3/JvS
         mohg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gsn92Ndf25TLwd1ueGluMthqdRKTAGbNpVnWfMH7Zso=;
        b=EXTu2l9p4gGV4Ir4ociOigy1TmMIJ750o+3tb6ZoFbXRrOLXySXU85zDzZZlJR4E9I
         Ybt7lz5k/ywKC2U/3SdpCCsT9JrybVXiFT51nhKDod9+v4iXTy172d+lGG/qmNV7RMMl
         Gedl4nL6VZimic6y4lNscWiDKdtqllrikcm6rtlmQugRDbOfurJsHVGQHez3laxtmRFX
         5kk2hserr/YhSVV1k3I6rn4mAELNadGbuQ0fVO0nn5drjFY/ppA6sau5rsOX1jXDFbMy
         SRASn5cSPmV9QnK7HS1SLSLzBHuxCCNxuiv/zP9OW2HvxMLVNo4mZgyrO+RCv9qtVSYi
         AEmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AQUMaA2m;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gsn92Ndf25TLwd1ueGluMthqdRKTAGbNpVnWfMH7Zso=;
        b=AqC96NJSZ3twjlfFGlABB4tNVdHDjr/7F7MoCxvN+8O/oihusUONHsUwKq1gORiTCW
         FMhH2KUM3oxo4I74h039eg9aJ3dZ4XUjpBDp3xSs6IQ/atmSsrOPDS1VBt+5U7EjCDiK
         Gmwl0PcmeHj5c5cT9QpBTZWUUcfwjP/6z3K/bY/hxROlc5WgntQkgzGqZB1V/D8sCSyq
         YnzOupx4wWMTBj60bWa2nBOjXgDiAa7NGkSVvxkm2g2w1h7GIm2HWMPLSYk7QgWN6etg
         MrRWJmQMS8hhJA2yLRfIKOAgR0Cy6KC6Wr5oG8z/yxPByfRIgTd9d5tYfJCrCLFN1Hpp
         nZIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gsn92Ndf25TLwd1ueGluMthqdRKTAGbNpVnWfMH7Zso=;
        b=pY8kBRP7z8HaZvCasVCAG/zirkLnlgn6Gk+rVPxPhKIzVPpfzc/uvUYrwjabjanIHa
         JCwbStQng0+Uqe58lHX3PPAkKs0pqZlfbMTsgn9mK3Wz4DXwBiNit6Bzqf0GyfJwNOdl
         adU0aYyp/LZXpbTOv5DNbGiND2OP5k0vL7q/nP9fbeiaC3egR6tG2km2pEGTI1efRz1g
         yGtwm0fa/SZ7+nQQFLMz72lWAmaCnmEZlSAQr1AtoS7ptdUPQI/T6QyS10Q3lwlLPFUq
         CguSGF1lr//l9wiNiWxXZw81rqUf5Mu3GTPI26PKCptZ5jauwe2143+LiZdc4UaWaBqP
         3uDA==
X-Gm-Message-State: AOAM530i+f7co/Lsc/6sCigsk11yp/lk+X6j8k0hRCqdvu03Q1JWrQyO
	alGcFJ2hyjmjBPqEX0ryae0=
X-Google-Smtp-Source: ABdhPJygzKX0URODzgZn9SyJCgJe8qCwPUUKuQBn9qTgrp5Ziz5t68x70nQM/1ZbNBF+Xk73CGymzA==
X-Received: by 2002:a17:90b:f01:: with SMTP id br1mr2310305pjb.2.1601033174761;
        Fri, 25 Sep 2020 04:26:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:95ac:: with SMTP id a12ls975405pfk.5.gmail; Fri, 25 Sep
 2020 04:26:14 -0700 (PDT)
X-Received: by 2002:a62:7511:0:b029:142:2501:35da with SMTP id q17-20020a6275110000b0290142250135damr3593001pfc.58.1601033174171;
        Fri, 25 Sep 2020 04:26:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601033174; cv=none;
        d=google.com; s=arc-20160816;
        b=BBXucUWqUMorD9SqewRO9hJ1730xPzEwmWoQVy/geRjSj3wJrAWtRNMdBE1f9cw1Ka
         nvPVXHYDCH0e8+CUYhGkc87KGWmOHJmQy1M1O+Gh8twkVh29Kg9kfYYtp9KwIhX3+gAt
         bFJytiJTGrYJLMMkG5vwk3hn6BY8rsjmh9+OwQUsCmQEkDBIcnPp7x2JJBFIq98Wu1CL
         y6j+1YFAscTU4UCs3KVlcLNb2eiqYJ0GxtJXhwSXtvSX1RmATkpveUE0PZ/6lfT7qAK2
         Ewd467exw0z+K/s0DpVCOl9hL3TZtB+nQlosiD5RBaBSrmbqvELbExIrdozrx5iD0fl7
         4SwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WxOkTxBUdDygkxQk8SSiZ/3m/eISYyIoxaAPO6Ft/3c=;
        b=HcKXXP+rmQUlvmOT7yE9DuA78ycBuToDtiEtuZzqWIU3WyjFU1DK0I4RlJu0Gw7Wbc
         GmC1UNX2K6nyI/P6cuzNeLIsLvOkSy46qZ5LE1Ltl5v0CjZa4Yj0Aw39YwBtlznZA+3/
         pDqbs/YTpPvdXflojmmyjYEbZHQ4d4M5dlarjlTddacA4M4AVxSKLspvQRgfk+VnkQHc
         TSKl1brL3BUse/307VDw0HwZl1PIS8s31oOSAz52S+kNQjv8XMCtkVg/lGaccM0io67e
         R/3VRgH2jaJyFugGt3bTlasond5XRumkoyNx0rB7l/U8iVVSnIDw50R3CeKtula67eXk
         cYTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AQUMaA2m;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id mm16si162107pjb.2.2020.09.25.04.26.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:26:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id o20so2850427pfp.11
        for <kasan-dev@googlegroups.com>; Fri, 25 Sep 2020 04:26:14 -0700 (PDT)
X-Received: by 2002:a62:1d51:0:b029:13e:d13d:a0fc with SMTP id
 d78-20020a621d510000b029013ed13da0fcmr3806915pfd.24.1601033173658; Fri, 25
 Sep 2020 04:26:13 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com> <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
 <20200925104933.GD4846@gaia>
In-Reply-To: <20200925104933.GD4846@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Sep 2020 13:26:02 +0200
Message-ID: <CAAeHK+zLFRgR9eiLNyn7-iqbXJe6HGYpHYbBXXOVqOk4MyrhAA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=AQUMaA2m;       spf=pass
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

On Fri, Sep 25, 2020 at 12:49 PM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index a3bd189602df..d110f382dacf 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -33,6 +33,7 @@
> >  #include <asm/debug-monitors.h>
> >  #include <asm/esr.h>
> >  #include <asm/kprobes.h>
> > +#include <asm/mte.h>
> >  #include <asm/processor.h>
> >  #include <asm/sysreg.h>
> >  #include <asm/system_misc.h>
> > @@ -294,6 +295,11 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
> >       do_exit(SIGKILL);
> >  }
> >
> > +static void report_tag_fault(unsigned long addr, unsigned int esr,
> > +                          struct pt_regs *regs)
> > +{
> > +}
>
> Do we need to introduce report_tag_fault() in this patch? It's fine but
> add a note in the commit log that it will be populated in a subsequent
> patch.

I did, see the last line of the commit description.

> > +
> >  static void __do_kernel_fault(unsigned long addr, unsigned int esr,
> >                             struct pt_regs *regs)
> >  {
> > @@ -641,10 +647,40 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
> >       return 0;
> >  }
> >
> > +static void do_tag_recovery(unsigned long addr, unsigned int esr,
> > +                        struct pt_regs *regs)
> > +{
> > +     static bool reported = false;
> > +
> > +     if (!READ_ONCE(reported)) {
> > +             report_tag_fault(addr, esr, regs);
> > +             WRITE_ONCE(reported, true);
> > +     }
>
> I don't mind the READ_ONCE/WRITE_ONCE here but not sure what they help
> with.

The fault can happen on multiple cores at the same time, right? In
that case without READ/WRITE_ONCE() we'll have a data-race here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzLFRgR9eiLNyn7-iqbXJe6HGYpHYbBXXOVqOk4MyrhAA%40mail.gmail.com.
