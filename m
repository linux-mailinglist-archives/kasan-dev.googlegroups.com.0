Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQVF5H5AKGQEPBPL5AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FAE626499A
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 18:22:27 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id a6sf6064612ybr.4
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 09:22:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599754946; cv=pass;
        d=google.com; s=arc-20160816;
        b=fotUn9/7l6pZZl75GLUXhxZGVhlimqc4PZrtyI+6T8hkLKim7X5W5dR3J/CTpAcRf6
         vcHIEE85Tz0xY9gr8mbRVzq1Ihy/mmPShSLf+nGFRaP4qu42geljIOfgyvg1z/c8FQJ4
         BuoM9icirfAr1p2zn8TUQuxKDzs8kIIGcK6v12RlRXarYNrBpCKKU7etng2zUfiuoqnr
         4CUc/dNZ8m+w6/dnsgafcUmqJpRCWTtClB9M9E8A7cE5zVF2mxDsv+t57jYGVgYdtXtA
         SLC66Nu8ZHWvyTY48omZkVSb4DKXUxMGBPGWqODfD7Y3ASjcsVqVrsOhBtiNhV/yNMwk
         61xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xeoR7GPie6EWeXH3oeYxX95naNQhWcnuooyjXlV32e0=;
        b=L2G1WN9910lILObpxwiyWa9V3q7o8Nbygc04GH7yDpZszfc1zakxydvxV2qxf1HXDC
         ZmyTANe1QLI9d3N9s6rO/8heIj8EgqHleFUQ2zv3ZTT2QksDZhJJtTN/TVu45QqUtmrP
         AhAtZdP+GSeQCWlwKchafTE8TThg7OkOIaLK1AtToo14uEmMQwIJzyaBIIq4XmIOf1Ui
         2iMzDLtCDJnfs0jPN9x2tcQpBuEMi1MIFgHrDDFOYxCmnKJsxxA5UU2EXOZhXVtgFIu0
         qsXRYfxOY+pnok4hPdlyrRS4/TjdaF8crZuDJ89p/+8DfjZ9R4T2g0p6iixq5xcNvQry
         /mww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cIEj1NRa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xeoR7GPie6EWeXH3oeYxX95naNQhWcnuooyjXlV32e0=;
        b=FRrGtyi8+gDcLeJCef8s+fStutwDRcEXBvwyvXTp8Ubcgr7NYp+eEV1WqTZZ5rVcq4
         vWybEEACEQfXfd6WdHS8u1KxxmKy49tQNru3iJJIOxRJrd5veLPO67q3iy476PVMiMoF
         sUyo63yELnzs8Ms+tcgvtdEl7YZI5F5WyENKGvxJcbLPOMxC7NAkLuJozsz/u7t2MYTv
         KgCSxVwPi13sEm0XFtX4WltwWmznN1jr8VWFUpdmkIRL5wf7lZHH6M0q18KH7eIfEY5v
         XHFWjxunP+6is/moWRdjwb6v3NcOjq04tipDzhu5EojdNI1T/BXPS4eHn6UMP7RNmnrQ
         3wzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xeoR7GPie6EWeXH3oeYxX95naNQhWcnuooyjXlV32e0=;
        b=Sa8KfXAQ3AChdI5PyavS7yNwVp60sjddYYVgW6c7quYW8v/kRkovd0bM8XtSbt3PP3
         kyq3rf7yg2/+V2YM7uvgeXNSGn7N8U6ANg3XDOb6sHU9Agpukpmd9OI1QWwpbHAqEdpc
         juF9UKQWKcXa3xhkauJ7ZeJVTs7B58HD5HxevetNhHKsOWJ0HrGyAttIcJssN0WaMTbN
         Hj1Px/a3AKBtEa26qiHm/2ClqRwJxuUcFxo5T8W30H0lo3lFv7+gHmU8ZIl9Ktvadqhy
         /hNyJjJlL7zROWcnl8ZIkKgVIVVSKBcCVhKqdgHXevke25alZVlnVb/XUec9lS429Ln9
         bKTA==
X-Gm-Message-State: AOAM5311I/DdNHcSPq/4kbcCqs4Yl6u7kgeDZoLXb03og2VeRba+tj7h
	taogMw4RCov/DwAxf6NjbAY=
X-Google-Smtp-Source: ABdhPJxtLmIWKEch8SILCJUvCZLgtAg9no5iDaU4S/y2XptHiEaMc9Gz8uhKxz+1LbD/vuxnUMnfnA==
X-Received: by 2002:a25:be13:: with SMTP id h19mr15668327ybk.50.1599754946521;
        Thu, 10 Sep 2020 09:22:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:68c4:: with SMTP id d187ls2969817ybc.1.gmail; Thu, 10
 Sep 2020 09:22:26 -0700 (PDT)
X-Received: by 2002:a25:16d4:: with SMTP id 203mr15038612ybw.20.1599754946092;
        Thu, 10 Sep 2020 09:22:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599754946; cv=none;
        d=google.com; s=arc-20160816;
        b=HrfLhDxZeAr0//fXQd4Ta+XSaImcWIjewe8Y3WHud07b9i3COlDe0sJG2yr5cauP0o
         VPQ/6zcdw3C+JN6H6M/y30HgRadmlDVYq3UnvIkUG0MKPF5rOfAVPG5sGiuXlKJ9sZLm
         xEPbiA2sLkcsltFIRLQ13NDv4rc0QCcT7OtypoduAWN3sugCHKSBMOD9DwsHZZh5nO+H
         O6UggsNca4SVHpE1Rtku0JeC50vdvTgZ/+LloMKsZX567bt9njw+MwOYHrYv+unUVxhz
         XHo9Xlgguc/szUSqtSe6nMr9G74kwg5ksIoWYTOBYhDiAX6+7G1B3HtnP9I8ryRzDdRe
         5dMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G8lEmdXJHmLOdLPgAHRWZC3Ha8HGaj35IzxQ2qyGHjk=;
        b=FMMtAltsI7FMFG3GxXfqySkLnZY9qwzb/F1wfqiyaNIpA5tqAd4/51hZCqgSogC8k8
         jB+02bXjtL9aLXQ5mYCffPd8ANLXu2ZHVe7iierXS4gj8RV16eVn9MqsmJySQLwIDtlw
         TEzK7f9vIXVm48iF3/eT/ibiatqOdFX97uqnaDYqfuTtXZwT20x+76vBmkwnkaW4bKc3
         DH+wqlt47BYZ6SYe5p4KhQSBD36HyEZTzmVfmJSIOfdBE5OpE/s+nuESexVvDXVC4IyA
         K/VoCMU8JEk0dLEqJEWVHa6Ek/Q5CKOs5E/L0lUnkSPbQceY1i2r+dRha5Lgg7C4Jzx/
         sj2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cIEj1NRa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id s9si611063ybk.3.2020.09.10.09.22.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 09:22:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id u126so6423105oif.13
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 09:22:26 -0700 (PDT)
X-Received: by 2002:aca:54d1:: with SMTP id i200mr508579oib.172.1599754945387;
 Thu, 10 Sep 2020 09:22:25 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-2-elver@google.com>
 <CACT4Y+aBpeQYOWGrCoaJ=HAa0BsSekyL88kcLBTGwc--C+Ch0w@mail.gmail.com>
 <CANpmjNN7qAtnUmibwGJEnxd+UcjBM1WeocoLeW0SO24NW3SkVA@mail.gmail.com> <CACT4Y+Z2Nay4mDjnHjooRa7u3ZXf72AFkF=EfkrZjCg9YEduMw@mail.gmail.com>
In-Reply-To: <CACT4Y+Z2Nay4mDjnHjooRa7u3ZXf72AFkF=EfkrZjCg9YEduMw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 18:22:14 +0200
Message-ID: <CANpmjNM53_yGwC1VFybzzZQ8f9wM=cjtmDdUYjWVct9CO1z6Ag@mail.gmail.com>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cIEj1NRa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 10 Sep 2020 at 17:48, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Sep 10, 2020 at 5:06 PM Marco Elver <elver@google.com> wrote:
> > > On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
> > > > +config KFENCE_NUM_OBJECTS
> > > > +       int "Number of guarded objects available"
> > > > +       default 255
> > > > +       range 1 65535
> > > > +       help
> > > > +         The number of guarded objects available. For each KFENCE object, 2
> > > > +         pages are required; with one containing the object and two adjacent
> > > > +         ones used as guard pages.
> > >
> > > Hi Marco,
> > >
> > > Wonder if you tested build/boot with KFENCE_NUM_OBJECTS=65535? Can a
> > > compiler create such a large object?
> >
> > Indeed, I get a "ld: kernel image bigger than KERNEL_IMAGE_SIZE".
> > Let's lower it to something more reasonable.
> >
> > The main reason to have the limit is to constrain random configs and
> > avoid the inevitable error reports.
> >
> > > > +config KFENCE_FAULT_INJECTION
> > > > +       int "Fault injection for stress testing"
> > > > +       default 0
> > > > +       depends on EXPERT
> > > > +       help
> > > > +         The inverse probability with which to randomly protect KFENCE object
> > > > +         pages, resulting in spurious use-after-frees. The main purpose of
> > > > +         this option is to stress-test KFENCE with concurrent error reports
> > > > +         and allocations/frees. A value of 0 disables fault injection.
> > >
> > > I would name this differently. "FAULT_INJECTION" is already taken for
> > > a different thing, so it's a bit confusing.
> > > KFENCE_DEBUG_SOMETHING may be a better name.
> > > It would also be good to make it very clear in the short description
> > > that this is for testing of KFENCE itself. When I configure syzbot I
> > > routinely can't figure out if various DEBUG configs detect user
> > > errors, or enable additional unit tests, or something else.
> >
> > Makes sense, we'll change the name.
> >
> > > Maybe it should depend on DEBUG_KERNEL as well?
> >
> > EXPERT selects DEBUG_KERNEL, so depending on DEBUG_KERNEL doesn't make sense.
> >
> > > > +/*
> > > > + * Get the canary byte pattern for @addr. Use a pattern that varies based on the
> > > > + * lower 3 bits of the address, to detect memory corruptions with higher
> > > > + * probability, where similar constants are used.
> > > > + */
> > > > +#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)addr & 0x7))
> > >
> > > (addr) in macro body
> >
> > Done for v2.
> >
> > > > +       seq_con_printf(seq,
> > > > +                      "kfence-#%zd [0x" PTR_FMT "-0x" PTR_FMT
> > >
> > > PTR_FMT is only used in this file, should it be declared in report.c?
> >
> > It's also used by the test.
> >
> > > Please post example reports somewhere. It's hard to figure out all
> > > details of the reporting/formatting.
> >
> > They can be seen in Documentation added later in the series (also
> > viewable here: https://github.com/google/kasan/blob/kfence/Documentation/dev-tools/kfence.rst)
>
>
> Looking at the first report. I got impression we are trying to skip
> __kfence frames, but this includes it:
>
> kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32,
> cache=kmalloc-32] allocated in:
>    __kfence_alloc+0x42d/0x4c0
>    __kmalloc+0x133/0x200
>
> Is it working as intended?

We're not skipping them for the allocation/free stacks. We can skip
the kfence+kmalloc frame as well.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM53_yGwC1VFybzzZQ8f9wM%3DcjtmDdUYjWVct9CO1z6Ag%40mail.gmail.com.
