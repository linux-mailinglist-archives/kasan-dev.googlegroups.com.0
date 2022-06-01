Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYM23WKAMGQEIITI7WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id F2AE353A40D
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jun 2022 13:28:34 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id a64-20020acab143000000b0032be948df74sf930210oif.2
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jun 2022 04:28:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654082913; cv=pass;
        d=google.com; s=arc-20160816;
        b=soMxHAZRBq/z6DfY//iK0THQQRuJ5kZaQJ5RKm/5mGqgVM1R0BYk4cqkq2fx22ZbRT
         XU2kse6ALQQixS6BE1hVPCm7c2ASxhuWpb9dPzcK2YiWQ2SWf2c0I8Bc4GjouqCl8X9Q
         A6oh5ZuqgEj6TUSyQbl2GaZBJVtfATB1iCYaiD+JjGOKYeqwaEBFmcEbskExb9kVqlOG
         zWGaB8NS7tIvL+RXHc6VSWBlhmWVA7oFtPH4NAVtFsGgvceGkfVeEyHPA+sKfQfna98T
         GejQzMk8KcHtMsZzMfDmbOtBjijG1gSY6fUhtr9KMWE1mf7+4dOuqCRfmZRvMsI7Yq7i
         3adQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0Sd0O1+TAd9s2jwQ7cnEyj5ZErKhnEhzgLfPNkP9gCQ=;
        b=VEHBbTYU8zZOYuD7cxHQy6FbfeQ72e+OFfQlg8IeBbMzEHhGWaAcdrSZ+D4n75s53S
         hP8N5DPFtyMDf8jiaM/nXNEo2maEQRty2NTg1GYTxK0evWUyM8v1MEb8Vi5yQxiRQIt2
         /sir9usV2VjBubkPM4sJSku1EuKB1D4Akek3l0GGXkY4ALwZQE5f/Dn5m3ZkQZXbN/gG
         dlKQtxBQVE86TnMY3mILXmP5AYggr2Ta6Ptnx/lqiaGENbJJF++kwrTH505FCBkdSolm
         bll92TREUGmrrdKMQ89kF8EYxJTb+ZN7M1QfSixRwb0Hfog3B0APj0SLbtATNCYcv580
         LogQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qZ4wk7dY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Sd0O1+TAd9s2jwQ7cnEyj5ZErKhnEhzgLfPNkP9gCQ=;
        b=WiI8Q9/chvtkGmM5LemXN4peM0GV015JGvGkM0NV6BJlz6jpO2Ou/5GsdCInSratcm
         +emdb/WjwYw62/os3VSA+jYJ7HKHzFk+I9SiNJ2ARsocI6IV1zbaayL4xxN428HY+kef
         jfstYJvPNAIc3F4H9KcFnmP+p3iW1IefElZxaTLLFSf0S2jsqs12kIRbZVS4OFat6Ykw
         kRItPd+QYtK0R6HsdykDeqwp0ebsqzltjt87vEJz4DEdgvaKibPr9P96XdkbBo6LbZWm
         AqgBjlg/KmZf4P54ABTu1Y3fjBsytZz482gZSctE8ITwpV3RAgNfI1uCzW77Hi8yCwW4
         YlEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Sd0O1+TAd9s2jwQ7cnEyj5ZErKhnEhzgLfPNkP9gCQ=;
        b=Y/QKGUSjOxOhwR5QFdfsfGx0suwWIAx1mpSKZc5tg9QSsTtBVev6yH1Dor2/zSgO8b
         bDB0o9cbpegi4pxf0T2TRS/EOsqYz46jAbir797tVsz9Zk+4w9TivttWNPCFjD/5XCFg
         Gh6vrJRHU/2TjGvWa5rvY+c1AD25zNB2v7tB7CY1U9UNluy0j8NRcnsvwXQyMgK324FO
         BeLm6r3yq5DQWsBtSUaoO6FX6d5JY/mjHCIJHXXaVhbblI9L2bH4Ed1odsvc4JnLhz5t
         QSbxOwDQg3FVksT4ddEKXRIMFrltq2IrRS7JdAUsdvVf0bgvAe/giPs1PY0vZAdblJmE
         8ZZw==
X-Gm-Message-State: AOAM5334O7dsu+e5syKS2lfcHDc9j+VryRjMy9Kw/iuo/XNZY6q0IWQC
	vIZe3os+tro6VzPjSVUNZ0M=
X-Google-Smtp-Source: ABdhPJwtgw8NDJwAfk7/G1EwtwAxKn/0mlyxQyXE3538bUegxyGQjtGL8syFCDaZ5/rtqG1pLmEVLQ==
X-Received: by 2002:a05:6870:79e:b0:e1:f5bb:4627 with SMTP id en30-20020a056870079e00b000e1f5bb4627mr16383052oab.74.1654082913350;
        Wed, 01 Jun 2022 04:28:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a9a4:b0:f2:dc5c:8024 with SMTP id
 ep36-20020a056870a9a400b000f2dc5c8024ls1195396oab.0.gmail; Wed, 01 Jun 2022
 04:28:33 -0700 (PDT)
X-Received: by 2002:a05:6870:339a:b0:f2:d065:be1f with SMTP id w26-20020a056870339a00b000f2d065be1fmr15938726oae.69.1654082912899;
        Wed, 01 Jun 2022 04:28:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654082912; cv=none;
        d=google.com; s=arc-20160816;
        b=tfpVGdjAOyIa4ODVPoddxsXygCFRhUPMUGTqjmWLnF0FJiEqsCIWFYug4yudwL++Ns
         GDzEAR1FLd1wQrNR2jMRJvlpzHeuZ62L3aYgL5Yq8UorF/NaEihVw4ck9Ecq8xSk5zza
         iVn81a+CHCDltdQG12vl8KDrBQDFlJ2VMJpi0BG1LaUKQR3Vqd3ifzvMVmPAOAAphzjv
         00IXtqTDqLVURZ/yFtb8ZsB60ll6eIv12OVlVDHKCSUv9b6oeZJJy8/G819DneA+OCje
         oi/9g6RU4llxADHDb+1c+DdoXMBytw8Clc9r3hHlUc3dtMMUtiYVlcvEaKdCOoDtQwQG
         b7QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tDA6PuH6NICvxSpkxUN08aIv7E1lLbWtwbYMOmp3DFc=;
        b=AogO1CE4Z1AsRdqlQVH5GKq8nwGOglKPBYI/D8N22cmGnRJ6oJiCaztGraRhbMa+hW
         PxbpcM5cywR8HXlhhyXgt9053J+IIn9VldQS6wjsY4TG++YfXx4kLF5AMaXH+ZxiGSUZ
         JCWX8ceZWBVJrDpFGv8ppugzPltqSyY4IMofNtLv87Sa5ZUT694f9y9NaiD1mCANRRGM
         TUJkOoSEDkmicxOgBWPxzJYsC+VPSgB46bIsbTp2D4SEM4cc0BnxkDUohIxXAsnN8UFw
         NKwc3e/LcHqfKrovDJrt0FCYp6bhiVwOIPlc+wEsuB8aAhg5eLnIAz3K0NBtW04hIy7w
         OTqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qZ4wk7dY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id m29-20020a056870059d00b000e217d47668si99616oap.5.2022.06.01.04.28.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jun 2022 04:28:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-30ec2aa3b6cso14694087b3.11
        for <kasan-dev@googlegroups.com>; Wed, 01 Jun 2022 04:28:32 -0700 (PDT)
X-Received: by 2002:a81:1f8b:0:b0:2f8:5846:445e with SMTP id
 f133-20020a811f8b000000b002f85846445emr69247959ywf.50.1654082912126; Wed, 01
 Jun 2022 04:28:32 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-29-glider@google.com>
 <87a6c6y7mg.ffs@tglx> <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx> <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx> <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
 <87k0ayhc43.ffs@tglx> <CAG_fn=UpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D+4Pttc9dA@mail.gmail.com>
 <87h762h5c2.ffs@tglx> <CAG_fn=UroTgp0jt77X_E-b1DPJ+32Cye6dRL4DOZ8MRf+XSokg@mail.gmail.com>
 <871qx2r09k.ffs@tglx> <CAG_fn=VtQw1gL_UVONHi=OJakOuMa3wKfkzP0jWcuvGQEmV9Vw@mail.gmail.com>
 <87h75uvi7s.ffs@tglx> <87ee0yvgrd.ffs@tglx>
In-Reply-To: <87ee0yvgrd.ffs@tglx>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Jun 2022 13:27:56 +0200
Message-ID: <CAG_fn=XP9uFKA+zvCp_txBO_xGwH10=hhF9FDQL107b4YUh6sA@mail.gmail.com>
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
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qZ4wk7dY;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Thu, May 12, 2022 at 6:48 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Thu, May 12 2022 at 18:17, Thomas Gleixner wrote:
> > On Thu, May 12 2022 at 14:24, Alexander Potapenko wrote:
> >> We could try to figure out the places in idtentry code where normal
> >> kmsan_unpoison_memory() can be called in IRQ context, but as far as I
> >> can see it will depend on the type of the entry point.
> >
> > NMI is covered as it increments before it invokes the unpoison().
> >
> > Let me figure out why we increment the preempt count late for
> > interrupts. IIRC it's for symmetry reasons related to softirq processing
> > on return, but let me double check.
>
> It's even documented:
>
>  https://www.kernel.org/doc/html/latest/core-api/entry.html#interrupts-and-regular-exceptions
>
> But who reads documentation? :)
>
> So, I think the simplest and least intrusive solution is to have special
> purpose unpoison functions. See the patch below for illustration.

This patch works well and I am going to adopt it for my series.
But the problem with occasional calls of instrumented functions from
noinstr still persists: if there is a noinstr function foo() and an
instrumented function bar() called from foo() with one or more
arguments, bar() must wipe its kmsan_context_state before using the
arguments.

I have a solution for this problem described in https://reviews.llvm.org/D126385
The plan is to pass __builtin_return_address(0) to
__msan_get_context_state_caller() at the beginning of each
instrumented function.
Then KMSAN runtime can check the passed return address and wipe the
context if it belongs to the .noinstr code section.

Alternatively, we could employ MSan's -fsanitize-memory-param-retval
flag, that will report supplying uninitialized parameters when calling
functions.
Doing so is currently allowed in the kernel, but Clang aggressively
applies the noundef attribute (see https://llvm.org/docs/LangRef.html)
to function arguments, which effectively makes passing uninit values
as function parameters an UB.
So if we make KMSAN detect such cases as well, we can ultimately get
rid of all cases when uninits are passed to functions.
As a result, kmsan_context_state will become unnecessary, because it
will never contain nonzero values.


> The reasons why I used specific ones:
>
>   1) User entry
>
>      Whether that's a syscall or interrupt/exception does not
>      matter. It's always on the task stack and your machinery cannot be
>      running at that point because it came from user space.
>
>   2) Interrupt/exception/NMI entry kernel
>
>      Those can nest into an already active context, so you really want
>      to unpoison @regs.
>
>      Also while regular interrupts cannot nest because of interrupts
>      staying disabled, exceptions triggered in the interrupt handler and
>      NMIs can nest.
>
>      -> device interrupt()
>            irqentry_enter(regs)
>
>         -> NMI()
>            irqentry_nmi_enter(regs)
>
>            -> fault()
>               irqentry_enter(regs)
>
>               --> debug_exception()
>                   irqentry_nmi_enter(regs)
>
>      Soft interrupt processing on return from interrupt makes it more
>      interesting:
>
>      interrupt()
>        handler()
>        do_softirq()
>          local_irq_enable()
>             interrupt()
>               NMI
>                 ....
>
>      And everytime you get a new @regs pointer to deal with.
>
> Wonderful, isn't it?
>
> Thanks,
>
>         tglx
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXP9uFKA%2BzvCp_txBO_xGwH10%3DhhF9FDQL107b4YUh6sA%40mail.gmail.com.
