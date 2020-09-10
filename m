Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7UB5H5AKGQE3L4P6DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 66392264891
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 17:06:40 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id x11sf1138641pll.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 08:06:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599750399; cv=pass;
        d=google.com; s=arc-20160816;
        b=XLbsnTiDnM/bdcIocIHIsfTPvR1NU9SsusOgBXB/AgS0P5obiJThRq+BjL50cAlIWk
         wmtaWdFVTfJ4tgpqNl9GB/sq4rgfOvVDHGfp1ioMzcgALRK3bo3Lb/vAhJfZtDHFDY+a
         pjv5bCOhOJ4Nswp+LWFybQ3h9J1D68GUUoqTvXk/6q9rysUTrlKAMbM/RrIGeQe8hUio
         1T+en2g72Nwwazj7eQPHMyzUvgYfp3209EmyXKkBgB9c3DMH+T9I9i1/qR/F99rd5rEv
         mQN26QFuE2UPY7stcsLgpJBU+7Rg6zlhRTKXO84JVlHIMhk20lzYwaY06tiUB/TIYoLw
         d5mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IDQFUGPwPt6Yq22yv2AoA5QE3SJmGsKveHfQkfuuqF4=;
        b=K7vVToNLaVBRLbT5nVH1iEvuVdifa4u3g1uI1JsCMMJOYeS/HhEkO75inu0/Siid3D
         CMXeOJmHilUWa9aywz1raIm9jwP4/12SzwoAIygFRcJy/KmOvC9yeUHKkaZcsrIdAYDg
         Epq77+6N6YqaqFxZooDBocgP1H9vhXW6CMlQRdeXgfHBxgMFlwB9oI+/SQnU51q0L95v
         8IA+gxFItOaAqOk6p8G1IaflGzA3ghfHKBlcHt0tEbq0smi6ba8ZoQaYWzQRA16FVw3I
         cHyUEVsVQ1uZlCsJDzE/3cyOeRIr2NiSTcfMial4iCGz8EHjhmPfdUyHr50jddWjvVwT
         PHRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d7rj+8Qp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IDQFUGPwPt6Yq22yv2AoA5QE3SJmGsKveHfQkfuuqF4=;
        b=GC4LOwMWFhZTFWJbE9bW+t05tIws+X3VZ1Cyszji4z1FR4NK3JVu1o6PtoQVVTKzbD
         o/I0kRUxtdY5njx8yJyiF3ktdRY9uT41TvKfNihXGuk1jAl8GbdBD4Glp7MIf3mnzWPg
         brZ7PRwt1nngwuH74pih8vXRvRsw4i4eeoN2L9/+ICJunvbMMddX7ZMILw8qdNHKuIfB
         cpUVNrSQGoiuztmW+nxa370nx5N7SZAHNFvHQuq1HHvb/5AuAvYLsf08T41RPl2nPfpz
         8bqwN369cg6JtWLnQ2lE2CuZ2oYHlaO17kezvk3l3y68aGrmHZ/Iusm8olNSqQMhENxR
         4ADQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IDQFUGPwPt6Yq22yv2AoA5QE3SJmGsKveHfQkfuuqF4=;
        b=EOxzfBUwe4Go+k77y06G6Xv36v2/I2liHFHVh6r9Smas+SazxPegE4XCF3cOQ9kFOC
         1O/qThfNmaAPiLySInNPmt6SE+B7epWNlvoCq6higZFzCmuMrd6AvZwmytvIV/8wlpeV
         Qt8Um7M05Z5OuiiicFrPTsbNGxmy7ufMg5PXGX54FfDfD3qLRS39W3vav2NjiIWdvDHZ
         n4qLUratqglo9hvKms7ZIa52vteXou3/+bVGlnJBllygDL9JlmH7g22cjSe5ZwBFkxyy
         QhZRUte0DRlZGYOjihEnOJuTmVlEnCOml79xWsOGcVJwCofAlHbzhrNMgNr9zxh+hz7T
         Rd5g==
X-Gm-Message-State: AOAM531hB6BB+yZ1+z+RKVlVL2Gi86Ls4z9iauLhrZZejXRYSRBRDREw
	6CGf1B/yIEMBvP63B3Sturs=
X-Google-Smtp-Source: ABdhPJzpW3jHzsGyeuMCsxpY7qbKqfCVYamG4mObeDZj9Qi5SQ9WlZUeczxXHP2/MGgICgQ0MaaQjA==
X-Received: by 2002:a62:8f4a:: with SMTP id n71mr5963388pfd.141.1599750398933;
        Thu, 10 Sep 2020 08:06:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2154:: with SMTP id kt20ls1542241pjb.1.gmail; Thu,
 10 Sep 2020 08:06:38 -0700 (PDT)
X-Received: by 2002:a17:90b:208:: with SMTP id fy8mr345545pjb.153.1599750398221;
        Thu, 10 Sep 2020 08:06:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599750398; cv=none;
        d=google.com; s=arc-20160816;
        b=SjE24RDeY7n3oUWUHDjfPdWo0UA9BH4DmdoqDuoJuh48h9lrXw6Okh7gb5/yC/6DEQ
         8C5cg0GYZKfwatF1+sxPb6xE0AZneJ6hKrmivM+8H2EGwyTM1UYhLv7/lWmehTFNl0pM
         s7ej7r1f3o3TzDQvsD/PGc2xrU9gtNT+8AJcCuh789/uzQSw5Pi+TjrZ8kBWZMZlJc9r
         /cI3ykxD5L5YWkS+i7dJxHcrGbpnpqjdPBsGAkQ2tb11+ODKsBCmwmRj35QSIo6/bYch
         R8ra9kM2Ua+9/7pUDoplNWEyu/ii0i/9Wu2B2ZjwvMlgLk2+WlckK4uGCMq6klSlloIl
         Ak/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2DiBsMVuHaQKweeTOQHLBykKJQg8tEScxOxVWMIr6f4=;
        b=JyF9DfgmXpNI+L+EaZRmoHGQk8UkfOLxix3WiVbov5ynYf8jzoHcb+a+LEfYhWRvNX
         I32rfEHysM0VbhqsGJ9JgEhUdtvxjkE+BxzFCEMbiHHzbA+E72S20UMdjah3+Xr8uPyH
         ivWFEJYB483I/g/woXhUv9ZWFBtBUMS4sAHvgUDzwA+unrt/sXSjrhBv6RIL4/Z/Lgl7
         +piFdUa9wLU9a7ZVzHxKN70aj8yL4PVi6Yl9LBmDIMUmcc0msCVn/jnTIXZu2ybhILl3
         TT7voDZbSX4EO43yDijeIWDAoZOfutmWWdJF2eK6wTjwYt/6RdlJyUne3nxtoxocgmFt
         /9XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d7rj+8Qp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id w136si443541pff.3.2020.09.10.08.06.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 08:06:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id n61so5589308ota.10
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 08:06:38 -0700 (PDT)
X-Received: by 2002:a9d:3da1:: with SMTP id l30mr4426034otc.233.1599750397232;
 Thu, 10 Sep 2020 08:06:37 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-2-elver@google.com>
 <CACT4Y+aBpeQYOWGrCoaJ=HAa0BsSekyL88kcLBTGwc--C+Ch0w@mail.gmail.com>
In-Reply-To: <CACT4Y+aBpeQYOWGrCoaJ=HAa0BsSekyL88kcLBTGwc--C+Ch0w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 17:06:25 +0200
Message-ID: <CANpmjNN7qAtnUmibwGJEnxd+UcjBM1WeocoLeW0SO24NW3SkVA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=d7rj+8Qp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Thu, 10 Sep 2020 at 16:58, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
> > +config KFENCE_NUM_OBJECTS
> > +       int "Number of guarded objects available"
> > +       default 255
> > +       range 1 65535
> > +       help
> > +         The number of guarded objects available. For each KFENCE object, 2
> > +         pages are required; with one containing the object and two adjacent
> > +         ones used as guard pages.
>
> Hi Marco,
>
> Wonder if you tested build/boot with KFENCE_NUM_OBJECTS=65535? Can a
> compiler create such a large object?

Indeed, I get a "ld: kernel image bigger than KERNEL_IMAGE_SIZE".
Let's lower it to something more reasonable.

The main reason to have the limit is to constrain random configs and
avoid the inevitable error reports.

> > +config KFENCE_FAULT_INJECTION
> > +       int "Fault injection for stress testing"
> > +       default 0
> > +       depends on EXPERT
> > +       help
> > +         The inverse probability with which to randomly protect KFENCE object
> > +         pages, resulting in spurious use-after-frees. The main purpose of
> > +         this option is to stress-test KFENCE with concurrent error reports
> > +         and allocations/frees. A value of 0 disables fault injection.
>
> I would name this differently. "FAULT_INJECTION" is already taken for
> a different thing, so it's a bit confusing.
> KFENCE_DEBUG_SOMETHING may be a better name.
> It would also be good to make it very clear in the short description
> that this is for testing of KFENCE itself. When I configure syzbot I
> routinely can't figure out if various DEBUG configs detect user
> errors, or enable additional unit tests, or something else.

Makes sense, we'll change the name.

> Maybe it should depend on DEBUG_KERNEL as well?

EXPERT selects DEBUG_KERNEL, so depending on DEBUG_KERNEL doesn't make sense.

> > +/*
> > + * Get the canary byte pattern for @addr. Use a pattern that varies based on the
> > + * lower 3 bits of the address, to detect memory corruptions with higher
> > + * probability, where similar constants are used.
> > + */
> > +#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)addr & 0x7))
>
> (addr) in macro body

Done for v2.

> > +       seq_con_printf(seq,
> > +                      "kfence-#%zd [0x" PTR_FMT "-0x" PTR_FMT
>
> PTR_FMT is only used in this file, should it be declared in report.c?

It's also used by the test.

> Please post example reports somewhere. It's hard to figure out all
> details of the reporting/formatting.

They can be seen in Documentation added later in the series (also
viewable here: https://github.com/google/kasan/blob/kfence/Documentation/dev-tools/kfence.rst)

Thank you!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN7qAtnUmibwGJEnxd%2BUcjBM1WeocoLeW0SO24NW3SkVA%40mail.gmail.com.
