Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIXZ6OJQMGQE4NGSEKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B37F4524CBA
	for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 14:25:07 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id n6-20020a254006000000b0064b2e352561sf4479675yba.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 05:25:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652358306; cv=pass;
        d=google.com; s=arc-20160816;
        b=CvDLTqgldeHtywLGQTqRaYD9rRNM5ZeDxly6xi5quPgDhj5Tmt/CGCwo0FGQQX1W7b
         0LCtYJ+OV8D8JMRsJuJKHg7PX9uzeGwNyfJNfpo1XVw1l0U/UowYDpJlnJYMTPDBSweK
         yphkbihEt/7exIAHP0QPickm7neZo8LF3st0m2oa26QIzMpLH5aCw4oymctGxJT1sSNa
         3H1HB75yOZFRX92fJ2Cn960l4F7vJgefySuK/OGdizkP0DzgjOq8LVjUkmme3towDJs5
         Ry20at5UoKiy29a7OSsWgpgTIORuu9IZW1meSYQ463aJaVJwp74eFvp4rpyEL37gNIcB
         DKXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6CoeN3dG0wmjbpzpaw3vtujyqelm7txr1TpSjajG5ig=;
        b=RYtyHjQxj2VdbRjBF3GbR5NUXhHeBH74T/XJtDbVTMzd+AcaUXV0/1+HdSNFdcVB9E
         6eXyV/ptqec3ia22yOC5agyHfNCttywq8nrXYAqu2Ayxqk2NMsnbIrSSMgSxgyHAEeqJ
         tgJEuw9M+GfzAUR0jUWbsNG1xXiL6CYBzGnRwGLO25jez4piobHfwq+10kyirRrs8Xis
         tEsHlqjbIJ7wA95GbERPSCOnfNrSBPh6RoYymd8xeHakWII3HvdrArupPZpQsbMZWm+k
         +/Vpw1kH3SiK70BNdJnK4IHWWENFd/BUxDl9mnPPPy85H7Ny4XP4oj+8e3qdrDKQ9LvF
         DGmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sXaJnq0W;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6CoeN3dG0wmjbpzpaw3vtujyqelm7txr1TpSjajG5ig=;
        b=jkiWB2QmbFjVl8E1eE+tf3kRprJcLis3FrGd/odJHEhoT3JcuoqwIkNf92PoZPD81r
         gRSymkxMMfZe+g/RW7uPfrgAd5uJhCdrXNNbEmAi2uxXpY5525sHjHkf/B5ub7PUDvQh
         sah6z4OlXUSIcRD2BDm98BwMBAXKe1wT7PDjnm/ccZ7EFCCyCzDBactmBApEJTQktD+M
         nlGxL0n9cekU7Zlw3tXyur8jUcYLFHpEVPc8t0rE4VxkRdf+NeSr+84qTOv5+PhI1Cnt
         nkGduWI46GfQihFBRYKIq8f2nHHwJfoaV/O6KxvRPeqzkubNQieesxa5FNfgojA0E7Qs
         Ws/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6CoeN3dG0wmjbpzpaw3vtujyqelm7txr1TpSjajG5ig=;
        b=tFH1skQN2+y5p4mrJI/zI6gylIcDyCKGyo1JF7ED4MQK9UI5uE3utEamQaPsaVsdSz
         ZUbsEqeMv09OAi75q2oDixEK+E368sMvMabM9YOJfVgU4APJlYoj0//AhLaMO4kqRu4R
         Exzj15yXMEBT9DG+/PCXUx4YdDAhwdeNFYxvGm/+STzspOxCg1QCGBWKkIhhWBp4sF22
         +MGXs76pgCDi5NgxU9/bHc/RrLw+NA4EvkbgiDqxQ2HprOUs6OFbsqqn2YWfKzZlxyJ4
         h6HVRDndYUyOqu/8WhNenpC7Pmw/142FN6hboyw+um58VGdL4gpPmerI7ao8FwEeCvTq
         lR5g==
X-Gm-Message-State: AOAM533QWJfwseEOXBz4QgWiKCyWmZL1I7FUj76EncbexuyqOULMrKmZ
	4AEHWBCl1s0g5j8i6mYH95A=
X-Google-Smtp-Source: ABdhPJwu7VUxobxRi3c+sw6Q3pFhssRnw1N1w8ziRLh6jEXSt6XDYhuHbJKZZjp89ZSlCbd50+nfxg==
X-Received: by 2002:a25:a0d4:0:b0:645:77c8:979a with SMTP id i20-20020a25a0d4000000b0064577c8979amr29340670ybm.484.1652358306544;
        Thu, 12 May 2022 05:25:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:721:b0:64a:b88e:63c8 with SMTP id
 l1-20020a056902072100b0064ab88e63c8ls3691391ybt.11.gmail; Thu, 12 May 2022
 05:25:06 -0700 (PDT)
X-Received: by 2002:a25:9e06:0:b0:63d:8ede:4595 with SMTP id m6-20020a259e06000000b0063d8ede4595mr28716494ybq.408.1652358306042;
        Thu, 12 May 2022 05:25:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652358306; cv=none;
        d=google.com; s=arc-20160816;
        b=Tr0TMBrZFGiiNRKMqPpZm64z0b7XZBgnFK97E8L5D/KadvTgTHhX2ytc9sPIwHOf5t
         vp5rID/DGyhhk1hmq4oYV/v2ER9EHic0J7lx+VO8Q8SlmzZUJ6eBj8GWe0LdmkP9Z/wo
         E6wYmry1mmSg9vyassXQbKQI1sBG+nx3ArYFL1i83Io/AQVOA5jZi6vbsyJfL7hSHMsV
         jJsm7wMXsPsu3w65x4oH4M/z8RW6s5nYbLCzLJXTAba6K+EyDf8GUV4aLcpJvIeet1/Z
         9uL9LIhA05E2aVbWP32xWfVpWNugCW0uPKn1xqCMxbAMffSciQZg+PO8ZtXDMVE+vSEy
         PyWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=D4KhC5f7akNZCYIX8CtlWMuJDmlYSG1ZIcg9H4X+0cs=;
        b=jpBHe8YQHfj9q4v04vZliP+ZZvZUKRT2kWggolhuUOiGrALLWwV3SoqR+IoI0Sk4nG
         FAbQLQQUgRXzihp/ESPOaIlVBTSLYsv0QSPaLyj/b9ynmT0JQ7bB5gUinerR7TQbZ8ZB
         H6GlBG17P/KPqmz30evR7l27qSkkNTV+ZNOEzpdwaMBdxJeKkPQaJIlStBftzGxWlSZs
         Q8Wl3xPV2Fxu061KindsGo3Y2abeZZcvm0xLi70H9wF/aFj8WNtPodC0eNklMQ+rDCvO
         cA6iliBrrU8apbudZMS54EUKEhY6R7lX2Uqpjm1ltggBYSiq7boCBrNd4ny2dkVENtTT
         jgNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sXaJnq0W;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id z18-20020a258692000000b0064b34627fb4si521013ybk.0.2022.05.12.05.25.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 May 2022 05:25:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id m190so9424051ybf.4
        for <kasan-dev@googlegroups.com>; Thu, 12 May 2022 05:25:06 -0700 (PDT)
X-Received: by 2002:a25:aa62:0:b0:648:590f:5a53 with SMTP id
 s89-20020a25aa62000000b00648590f5a53mr29319927ybi.5.1652358305516; Thu, 12
 May 2022 05:25:05 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-29-glider@google.com>
 <87a6c6y7mg.ffs@tglx> <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx> <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx> <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
 <87k0ayhc43.ffs@tglx> <CAG_fn=UpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D+4Pttc9dA@mail.gmail.com>
 <87h762h5c2.ffs@tglx> <CAG_fn=UroTgp0jt77X_E-b1DPJ+32Cye6dRL4DOZ8MRf+XSokg@mail.gmail.com>
 <871qx2r09k.ffs@tglx>
In-Reply-To: <871qx2r09k.ffs@tglx>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 May 2022 14:24:29 +0200
Message-ID: <CAG_fn=VtQw1gL_UVONHi=OJakOuMa3wKfkzP0jWcuvGQEmV9Vw@mail.gmail.com>
Subject: Re: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sXaJnq0W;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, May 9, 2022 at 9:09 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Mon, May 09 2022 at 18:50, Alexander Potapenko wrote:
> > Indeed, calling kmsan_unpoison_memory() in irqentry_enter() was
> > supposed to be enough, but we have code in kmsan_unpoison_memory() (as
> > well as other runtime functions) that checks for kmsan_in_runtime()
> > and bails out to prevent potential recursion if KMSAN code starts
> > calling itself.
> >
> > kmsan_in_runtime() is implemented as follows:
> >
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > static __always_inline bool kmsan_in_runtime(void)
> > {
> >   if ((hardirq_count() >> HARDIRQ_SHIFT) > 1)
> >     return true;
> >   return kmsan_get_context()->kmsan_in_runtime;
> > }
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > (see the code here:
> > https://lore.kernel.org/lkml/20220426164315.625149-13-glider@google.com=
/#Z31mm:kmsan:kmsan.h)
> >
> > If we are running in the task context (in_task()=3D=3Dtrue),
> > kmsan_get_context() returns a per-task `struct *kmsan_ctx`.
> > If `in_task()=3D=3Dfalse` and `hardirq_count()>>HARDIRQ_SHIFT=3D=3D1`, =
it
> > returns a per-CPU one.
> > Otherwise kmsan_in_runtime() is considered true to avoid dealing with
> > nested interrupts.
> >
> > So in the case when `hardirq_count()>>HARDIRQ_SHIFT` is greater than
> > 1, kmsan_in_runtime() becomes a no-op, which leads to false positives.
>
> But, that'd only > 1 when there is a nested interrupt, which is not the
> case. Interrupt handlers keep interrupts disabled. The last exception fro=
m
> that rule was some legacy IDE driver which is gone by now.

That's good to know, then we probably don't need this hardirq_count()
check anymore.

> So no, not a good explanation either.

After looking deeper I see that unpoisoning was indeed skipped because
kmsan_in_runtime() returned true, but I was wrong about the root
cause.
The problem was not caused by a nested hardirq, but rather by the fact
that the KMSAN hook in irqentry_enter() was called with in_task()=3D=3D1.

Roughly said, T0 was running some code in the task context, then it
started executing KMSAN instrumentation and entered the runtime by
setting current->kmsan_ctx.kmsan_in_runtime.
Then an IRQ kicked in and started calling
asm_sysvec_apic_timer_interrupt() =3D> sysvec_apic_timer_interrupt(regs)
=3D> irqentry_enter(regs) - but at that point in_task() was still true,
therefore kmsan_unpoison_memory() became a no-op.

As far as I can see, it is irq_enter_rcu() that makes in_task() return
0 by incrementing the preempt count in __irq_enter_raw(), so our
unpoisoning can only work if we perform it after we enter the IRQ
context.

I think the best that can be done here is (as suggested above) to
provide some kmsan_unpoison_pt_regs() function that will only be
called from the entry points and won't be doing reentrancy checks.
It should be safe, because unpoisoning boils down to calculating
shadow/origin addresses and calling memset() on them, no instrumented
code will be involved.

We could try to figure out the places in idtentry code where normal
kmsan_unpoison_memory() can be called in IRQ context, but as far as I
can see it will depend on the type of the entry point.

Another way to deal with the problem is to not rely on in_task(), but
rather use some per-cpu counter in irqentry_enter()/irqentry_exit() to
figure out whether we are in IRQ code already.
However this is only possible irqentry_enter() itself guarantees that
the execution cannot be rescheduled to another CPU - is that the case?

> Thanks,
>
>         tglx
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/871qx2r09k.ffs%40tglx.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise
erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie =
mich
bitte wissen, dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by
mistake, please don't forward it to anyone else, please erase all
copies and attachments, and please let me know that it has gone to the
wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVtQw1gL_UVONHi%3DOJakOuMa3wKfkzP0jWcuvGQEmV9Vw%40mail.gm=
ail.com.
