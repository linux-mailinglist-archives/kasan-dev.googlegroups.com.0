Return-Path: <kasan-dev+bncBDK3TPOVRULBBRXERX2AKGQETHXGTKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id C55D0199BD7
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 18:39:34 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id d8sf3547216ljg.15
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 09:39:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585672774; cv=pass;
        d=google.com; s=arc-20160816;
        b=oDljmmyddERqRKZZH8Ga6jO2aRMJRgDO48A3vFNeNzG53zUIpYEtsT/2M8gnKenIRF
         RcYJCVytNmMctkFEKzrYvsMuEI4NUa2d+CrPXCx2nYNvxs4kj4SSzVCiQWSkItVbOTKL
         b5hCz+Wzz2lpAa0iKDpAZ3rgVsbfIYStSexaFnuBcrjQgnxI9LanTEaDBEQmvqQWuYHl
         gZeLQg/mRCBUaEO5CSvfSxtZ/MZJhz4SEeZwdE6w76Pleirsy9kEPoumVBCwVOfZzywX
         8q6NbTcG/KN2CpYXU6QTROq+qQYW8U9BYLaGmcbmSLscGYgwmHtDFMxwsF7wDU3wV4xq
         GO8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uIwA5Z08jDMn6wb1KAL5aP9jjAFiOJWAUUlMrU0RmWI=;
        b=BKBqpQdvjD1SaFd96cWtGU9+7qhTRgxRquDYV+EyCK6v64n06tpUUBtMLbwvtKszpY
         6W4OroApe3bFQHN4kHhpNHFWwhS0lLdU6gLF7EXmdf2U3Z80la5nWOSKeQ3WTG8q8QP5
         dn2cw4H+YVno24bvCgXmcPwXEXHRxHn7tGTbIWdz8/wROxBwxW9/FiwLS/OaPj3CoAfi
         qE6AwI1ZEaunVLh2gMhYlhylFzEWHHJ15Aprti0NuobC2xVln7KKLBvOO/pJOHBlt5zB
         /AgTl+QcyWFb2HRXMvoiqV3yonwrWnEAUwh1xumPTxj8sT7P94TJryCYVbfSv0Gycr15
         Whiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MOyCc4Pg;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uIwA5Z08jDMn6wb1KAL5aP9jjAFiOJWAUUlMrU0RmWI=;
        b=Hu6+BssBqF1xZdm55WpZVBxehRtMVrkiAD4lXIThs1Gunh1t1LOiJ9P9ONBiTmCN27
         3NywBOupFKiwf3Zq/60e8tSmQFaMQluw6KuYJhIzFL97uDWKAR+yGyX9/iBS8/Ar/Jjq
         +7QVigcXijzYzqPprv5bT2YgLbMtDp2qltFr/JLxDh6raruN5+jDiEwCpwfOTnnwPtLF
         s2NLFzqJ4urTPGll7b+jHgOxwWUuOvo8401149XR92NZhqDAjwmUIqhf2P/FcV0LI+wo
         C3AO35gtIYv0bAXrMb1tPEuxeu20o8OrYFMir605e2fhSd8BwIDJqVODbA0KF3LjpwBw
         tKsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uIwA5Z08jDMn6wb1KAL5aP9jjAFiOJWAUUlMrU0RmWI=;
        b=mPVQ8p9yUDiqZuFj6JQvgiP/56ohF7/pmhYOhw9JyqakHdJTPKotnXe8AEuc9pcKEu
         f6wT4X3vDHTOwdPeoZkQ/r26nWlMICQD0h6A9Jn+LCgmu7imlJljUHDPYGbK18VZ4Kqx
         t4v8hWOwvgR2x5tosAJ0Fd9WM/ss1lQL8zd5efNe3fDFoenL5GMEH1GYHTv/66Ajc9/s
         T32x53UDifb+H0EE43tJm+GMXCh9qyHRgvdI5sE2ZmoJ4yRxDt0H0Q6oetuQMXznpHdB
         kq3yBhQMSnoy1pf2HH9J2ltAPQDmo7h8WHBxf7A20r7HBXOOPSc1RcwKdDBRJgmiHg+p
         ylsQ==
X-Gm-Message-State: AGi0PubIN5l0A3HuwhWmwPYKGfHZkWbNW0kpZAED4IbWGfMb/UhYM/A9
	gWRayFfpKSnittjxTK7vng4=
X-Google-Smtp-Source: APiQypLG5CdVn1Ky4y1WQaif3yC1YjxMZDq2UXJDINCwMViAgUVbragQtZqXL5uTPKhjjNYNhD3NiQ==
X-Received: by 2002:a2e:b018:: with SMTP id y24mr5949970ljk.268.1585672774217;
        Tue, 31 Mar 2020 09:39:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e90:: with SMTP id b16ls1253174lfq.4.gmail; Tue, 31 Mar
 2020 09:39:33 -0700 (PDT)
X-Received: by 2002:ac2:42d9:: with SMTP id n25mr11641591lfl.97.1585672773517;
        Tue, 31 Mar 2020 09:39:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585672773; cv=none;
        d=google.com; s=arc-20160816;
        b=TIKSGtuXwRZvAf+mrzM39y7iZWy0BsyXlc8r+COqScGlw4yuT5mhEBFlqrrpT2Suj5
         nnSniMhbX2BrCQT9gKkCCwMhOj9UvVf8YOurZ2iU+CrvjsNc8ol/N9OmgidpdJcOBHl3
         GO1mB2THPLiClaU9QLJt1y+QuD0QX1ubfFhvJe/GlPPWvFj4pmob0G7rT9bsqO8yC2Fm
         f+YiV4bPkvX9jmIeFfu3Qg6tikB6lqcW7uIXSFI6NnxNkrpAhRd2OJrs56dJi3XluPWW
         dUsS+oW66WhjC5Btsab7BHE+FIo5z62QsckmIhuaICWPuMndNtG9wpXzpOA+q89zc1dz
         mESA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QgoMF0cL9ZUADYdGprv6AZfHS2idq4rpQGViQrbTh3g=;
        b=uHUm/hFKEtmS+HXkR9ZG+V33KtX5DJWYuoMM2HTRSfiOaac23lvkX4Xf+uwP0ora4S
         lOz3KRyPlA83/oF7AwnhQJnZ1jeMl7HT/k9RcOa7pWrvaL0penwvWD8cNi+4TuTDW5ZQ
         Y7w7SpTVcFchqFXREliJ/ZnvdLrPzuF+dsx2JpeMqTN+QKKrC3Xm8QGuobA8rXFDxwjz
         ZTsQegO4EY1Ita+Im/jDiWZutK9OOZfMbz6ZT6av/I7QcDizFijCr26gstrOIozGBGFQ
         boPGEa64j9vFTyMkgB2qBzEb0sI+RVjXnI+BCU+blr4mI45d16O9p+j2HQqIa4pFXk22
         ad2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MOyCc4Pg;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id s4si966186ljj.2.2020.03.31.09.39.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Mar 2020 09:39:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id j19so3564336wmi.2
        for <kasan-dev@googlegroups.com>; Tue, 31 Mar 2020 09:39:33 -0700 (PDT)
X-Received: by 2002:a1c:62c5:: with SMTP id w188mr4444781wmb.112.1585672772708;
 Tue, 31 Mar 2020 09:39:32 -0700 (PDT)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
 <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com>
 <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
 <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com>
 <2cee72779294550a3ad143146283745b5cccb5fc.camel@sipsolutions.net>
 <CACT4Y+YhwJK+F7Y7NaNpAwwWR-yZMfNevNp_gcBoZ+uMJRgsSA@mail.gmail.com> <a51643dbff58e16cc91f33273dbc95dded57d3e6.camel@sipsolutions.net>
In-Reply-To: <a51643dbff58e16cc91f33273dbc95dded57d3e6.camel@sipsolutions.net>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Mar 2020 09:39:21 -0700
Message-ID: <CAKFsvULjkQ7T6QhspHg87nnDpo-VW1qg2M3jJGB+NcwTQNeXGQ@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Dmitry Vyukov <dvyukov@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MOyCc4Pg;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Mon, Mar 30, 2020 at 1:41 AM Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Mon, 2020-03-30 at 10:38 +0200, Dmitry Vyukov wrote:
> > On Mon, Mar 30, 2020 at 9:44 AM Johannes Berg <johannes@sipsolutions.net> wrote:
> > > On Fri, 2020-03-20 at 16:18 +0100, Dmitry Vyukov wrote:
> > > > > Wait ... Now you say 0x7fbfffc000, but that is almost fine? I think you
> > > > > confused the values - because I see, on userspace, the following:
> > > >
> > > > Oh, sorry, I copy-pasted wrong number. I meant 0x7fff8000.
> > >
> > > Right, ok.
> > >
> > > > Then I would expect 0x1000 0000 0000 to work, but you say it doesn't...
> > >
> > > So it just occurred to me - as I was mentioning this whole thing to
> > > Richard - that there's probably somewhere some check about whether some
> > > space is userspace or not.
> > >

Yeah, it seems the "Kernel panic - not syncing: Segfault with no mm",
"Kernel mode fault at addr...", and "Kernel tried to access user
memory at addr..." errors all come from segv() in
arch/um/kernel/trap.c due to what I think is this type of check
whether the address is
in userspace or not.

> > > I'm beginning to think that we shouldn't just map this outside of the
> > > kernel memory system, but properly treat it as part of the memory that's
> > > inside. And also use KASAN_VMALLOC.
> > >
> > > We can probably still have it at 0x7fff8000, just need to make sure we
> > > actually map it? I tried with vm_area_add_early() but it didn't really
> > > work once you have vmalloc() stuff...
> >

What x86 does when KASAN_VMALLOC is disabled is make all vmalloc
region accesses succeed by default
by using the early shadow memory to have completely unpoisoned and
unpoisonable read-only pages for all of vmalloc (which includes
modules). When KASAN_VMALLOC is enabled in x86, the shadow memory is not
allocated for the vmalloc region at startup. New chunks of shadow
memory are allocated and unpoisoned every time there's a vmalloc()
call. A similar thing might have to be done here by mprotect()ing
the vmalloc space as read only, unpoisoned without KASAN_VMALLOC. This
issue here is that
kasan_init runs so early in the process that the vmalloc region for
uml is not setup yet.


> > But we do mmap it, no? See kasan_init() -> kasan_map_memory() -> mmap.
>
> Of course. But I meant inside the UML PTE system. We end up *unmapping*
> it when loading modules, because it overlaps vmalloc space, and then we
> vfree() something again, and unmap it ... because of the overlap.
>
> And if it's *not* in the vmalloc area, then the kernel doesn't consider
> it valid, and we seem to often just fault when trying to determine
> whether it's valid kernel memory or not ... Though I'm not really sure I
> understand the failure part of this case well yet.
>

I have been testing this issue in a multitude of ways and have only
been getting more confused. It's still very unclear where exactly the
problem occurs, mostly because the errors I found most frequently were
reported in segv(), but the stack traces never contained segv.

Does anyone know if/how UML determines if memory being accessed is
kernel or user memory?

> johannes
>


--
Best,
Patricia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvULjkQ7T6QhspHg87nnDpo-VW1qg2M3jJGB%2BNcwTQNeXGQ%40mail.gmail.com.
