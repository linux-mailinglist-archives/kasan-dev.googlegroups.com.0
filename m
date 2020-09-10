Return-Path: <kasan-dev+bncBCMIZB7QWENRBXUV5H5AKGQENC2VYUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 779ED264902
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 17:48:47 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id a6sf5956365ybr.4
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 08:48:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599752926; cv=pass;
        d=google.com; s=arc-20160816;
        b=GdUxZWyHkWwZAX3Ysvo/05EJJEL78zTuJwaacmfY7EPZOcrWTpbBoM0UuKiPxw7Mnj
         c6HbdrjnjBUSG6xA9Mc6aK/D8yAfESx6VmFgboAiXkQ1WFvkpTusM9cOcqdsoHUdxDEJ
         VyGobivbx22S5ClZkYeM4+omRz8GhJvc2Ul9BJv2pZlUjVsp0HTfe20UacDKjm4/csLL
         ozufd1ZVmRPTqBccRkJq61iJkBZzgdsIxTmeSmPU0+ACEz5nCzAd2Harul4eJYciqzxs
         ktOdRR4V2LfoxgorreyKcNGHAm2U71tKSZDi+6IhInTh+YfQvRwLFHo/zvDf7l+EfU6k
         yNoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gGINZP8Txk3AumnOYeRt/91uswCWHImXKgtA8Lcx1Tc=;
        b=BhciQ8N3S2QHd53OmN300D4aPTO8cdOctgMdmT8b5IA+I5AnJynYVqkfQ22a9Y7Rwq
         PPP/DTPXnVoKT5s2XNVOd9QCQGcg+aQuyevEik9VSJ9rV2JQ1xcJffRLgXVdxRsLhC1W
         hubTZFrR1rKtngw43S7exrdh50N2w25QtOI+FgEO8LwwDR1XQUFAjSoXboDGjfKx2UR1
         hlNNyQaYsoxKLI0RKwmWcS1dW6jQStoAfR4xRYFTocUyaS01cUml2S7gmUdQNHcaPOkz
         bC8x192MKzVYfWjdlan/jq4RIyETPo6E1yLK4Hnq3yTu11T5Ng8/Y84jPTIdU+e6Ph9b
         oJdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rZS11rVG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gGINZP8Txk3AumnOYeRt/91uswCWHImXKgtA8Lcx1Tc=;
        b=Xdd63aEhVGit+GfsyYh11G4ogsb2EY1vp0BcWjxz35H9AZRVOvLSK5Kuw8yZda1iZt
         Key8ICRNuHtJROrd6MrnMe9BQWm3yRRGHfkvn98CXc60A4ve3m95kOkJ9okXZCJzlLgM
         goUhLVIZXHKnHA2jiYtmN1zaXVqudOQF6Ln95iIX1epI21hEKXSitwvC9kJ7w/hv6glR
         676hC0aA8a593Fl2QMofQS+t2jdoLQjenUbbMjSE60gSUIqtOCr0/SJ4YSdwbAFUGIf0
         hoFnrJKI4ho/+igxXzYR5lXdzHt5FDfcgklkklJ1DMHWseIyKRkzcgp9lrYg34SGBgc5
         1BFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gGINZP8Txk3AumnOYeRt/91uswCWHImXKgtA8Lcx1Tc=;
        b=HfOIV+pL4Qt/PTW0GjEsizlL0qmfN2BRD5lNeQEmFkxy1VTwaKANXTRR1biEe67/3U
         4S21SsZ/tJ8mtsFL5wFledDaNKp3gMYNJqZZ5I3ISLeYXwY6XsplE3i2j+yR5FTK6f4u
         nTBs91Gl6GnYYHljYV9OCtw9KjcQ7A7H0Gf7qvZOIcpDRG4VQ7NGp6YSZF/931wqp8uI
         VLBZ1DWjWBAmIGlrtgwQpC4qzGsDF74kDJoQqa9jRcnYKHwt3d+NGnB2rRUs21Ltf+ou
         F+0c/SKesxiO7vgzZwPG96BcVtDA7gidBxR8w1eMJTbvlytMFMd0j0F8jO0s8xgQW577
         dFqA==
X-Gm-Message-State: AOAM532pc6OejIq5qOSjorREUWfk4s+imkwC5Ob/E4X+ZqPac4Ma4uF9
	ZqszcOmy/S9/N5XxbDvEdIM=
X-Google-Smtp-Source: ABdhPJzVXpcejo2OPTPNMqR9s+NfbnB3266G1IWP2WDygL8zKvLwwA19FbV/bp8S2l4v74xm22UQTQ==
X-Received: by 2002:a25:250b:: with SMTP id l11mr14201241ybl.253.1599752926241;
        Thu, 10 Sep 2020 08:48:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:24d4:: with SMTP id k203ls2920527ybk.3.gmail; Thu, 10
 Sep 2020 08:48:45 -0700 (PDT)
X-Received: by 2002:a25:5755:: with SMTP id l82mr14932198ybb.175.1599752925798;
        Thu, 10 Sep 2020 08:48:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599752925; cv=none;
        d=google.com; s=arc-20160816;
        b=rwalfHb/TC3NuhKCsaZ7rMYxpD1hRnbkS4bvxhcpR41vKwICMZPztixPKeESqv+5hC
         LBL3ut5NYJVVqPhyrmBfvLcp8KSmgH3p+DhHes72iKpjfcugBT7SWWF+/9JKn5V7oAca
         b6O4ZuyD7iHyCk18wa63bZqnnGGy0jrvw7ndybxDwS6FufUw+DVRbrueb4GK68PjcwRD
         gb6FJNICTntSlGU8ztcz/04EpodSpA+8EPwSsydjgKa5qbBaIkgoMVChV0gbX3EFILMu
         dX2Owd6stv3nlbGG45lak//2cxUqalc/cC+Twiyr13A5pKpAmNJTBmZL5tUAjQUUvcIM
         MxrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mzZ2lLN/xoCXQCadMP3KD01lnN0CJF5729OTiX4TA1k=;
        b=Rqpzkm2mp5aP9X8gHkGdTPtwjfoupj7MbpmtdOZzm0698+sRS6ReEE0hNzNMjfSsKZ
         81ldRAyGrHoN8x+gJSPSqNof3VTSDhz9hFGPp2z8iy9yeSpeeInG98EQco8yWlgBSIRp
         93c3Mgw9UA0twCKVfunygsVAI/ZPfIhBA/gGb4HENzseKLrqZ18baEbs3VdO1aD0lEKA
         O0/lV32iR9PuY8Rn54uUYMhN+1K6bOIyUgQeO2cDDOqS3L2H8MIpVoYc6YG1bg+CXc5k
         JcP2XQ3+tlIzdANbNakO2wfuLZHdTFpJriFxZfiZfDCNoSAdKfGh0i9wNqpE7XbitiJa
         KQFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rZS11rVG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id r7si571592ybk.5.2020.09.10.08.48.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 08:48:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id h1so3556032qvo.9
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 08:48:45 -0700 (PDT)
X-Received: by 2002:a0c:e543:: with SMTP id n3mr9296354qvm.11.1599752925133;
 Thu, 10 Sep 2020 08:48:45 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-2-elver@google.com>
 <CACT4Y+aBpeQYOWGrCoaJ=HAa0BsSekyL88kcLBTGwc--C+Ch0w@mail.gmail.com> <CANpmjNN7qAtnUmibwGJEnxd+UcjBM1WeocoLeW0SO24NW3SkVA@mail.gmail.com>
In-Reply-To: <CANpmjNN7qAtnUmibwGJEnxd+UcjBM1WeocoLeW0SO24NW3SkVA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 17:48:34 +0200
Message-ID: <CACT4Y+Z2Nay4mDjnHjooRa7u3ZXf72AFkF=EfkrZjCg9YEduMw@mail.gmail.com>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
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
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rZS11rVG;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Sep 10, 2020 at 5:06 PM Marco Elver <elver@google.com> wrote:
> > On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
> > > +config KFENCE_NUM_OBJECTS
> > > +       int "Number of guarded objects available"
> > > +       default 255
> > > +       range 1 65535
> > > +       help
> > > +         The number of guarded objects available. For each KFENCE object, 2
> > > +         pages are required; with one containing the object and two adjacent
> > > +         ones used as guard pages.
> >
> > Hi Marco,
> >
> > Wonder if you tested build/boot with KFENCE_NUM_OBJECTS=65535? Can a
> > compiler create such a large object?
>
> Indeed, I get a "ld: kernel image bigger than KERNEL_IMAGE_SIZE".
> Let's lower it to something more reasonable.
>
> The main reason to have the limit is to constrain random configs and
> avoid the inevitable error reports.
>
> > > +config KFENCE_FAULT_INJECTION
> > > +       int "Fault injection for stress testing"
> > > +       default 0
> > > +       depends on EXPERT
> > > +       help
> > > +         The inverse probability with which to randomly protect KFENCE object
> > > +         pages, resulting in spurious use-after-frees. The main purpose of
> > > +         this option is to stress-test KFENCE with concurrent error reports
> > > +         and allocations/frees. A value of 0 disables fault injection.
> >
> > I would name this differently. "FAULT_INJECTION" is already taken for
> > a different thing, so it's a bit confusing.
> > KFENCE_DEBUG_SOMETHING may be a better name.
> > It would also be good to make it very clear in the short description
> > that this is for testing of KFENCE itself. When I configure syzbot I
> > routinely can't figure out if various DEBUG configs detect user
> > errors, or enable additional unit tests, or something else.
>
> Makes sense, we'll change the name.
>
> > Maybe it should depend on DEBUG_KERNEL as well?
>
> EXPERT selects DEBUG_KERNEL, so depending on DEBUG_KERNEL doesn't make sense.
>
> > > +/*
> > > + * Get the canary byte pattern for @addr. Use a pattern that varies based on the
> > > + * lower 3 bits of the address, to detect memory corruptions with higher
> > > + * probability, where similar constants are used.
> > > + */
> > > +#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)addr & 0x7))
> >
> > (addr) in macro body
>
> Done for v2.
>
> > > +       seq_con_printf(seq,
> > > +                      "kfence-#%zd [0x" PTR_FMT "-0x" PTR_FMT
> >
> > PTR_FMT is only used in this file, should it be declared in report.c?
>
> It's also used by the test.
>
> > Please post example reports somewhere. It's hard to figure out all
> > details of the reporting/formatting.
>
> They can be seen in Documentation added later in the series (also
> viewable here: https://github.com/google/kasan/blob/kfence/Documentation/dev-tools/kfence.rst)


Looking at the first report. I got impression we are trying to skip
__kfence frames, but this includes it:

kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32,
cache=kmalloc-32] allocated in:
   __kfence_alloc+0x42d/0x4c0
   __kmalloc+0x133/0x200

Is it working as intended?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ2Nay4mDjnHjooRa7u3ZXf72AFkF%3DEfkrZjCg9YEduMw%40mail.gmail.com.
