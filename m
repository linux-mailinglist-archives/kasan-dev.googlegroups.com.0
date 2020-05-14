Return-Path: <kasan-dev+bncBDYJPJO25UGBBWE6632QKGQE4GCLXWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B49201D392B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 20:35:05 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id v87sf4022891ill.23
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 11:35:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589481304; cv=pass;
        d=google.com; s=arc-20160816;
        b=dyaCnF2ePXREbkeo9YqfCEhiVUTZozXmtGfJrrQz+OFB9uIU6FF2tyISkTjfP7+HpR
         HJ5bZAsHD2yodzV3G0ZdC4CDEyQzXy3vpBTVH25Wab+GdauSbx9cs3O4DHN0T1hxnbz1
         FFZbF/YKCIKKc5EyaTT1Om6yjoVf11SSUxMTxXNriZXx94JhORoHcXU3+jfM91URgnIc
         nIBLc4K0NDjMjC9uLEnx9ZkzQ1maiR1I586owsMEG+0MwamDJEbdppWvHBBJuncGON+k
         9q8zdj5iczTnyN+h9Ka7ww3LJQm+6xz3TdKTzzNx3y2tHLHRsvB3Gz5Lu2WMsPSnBBKq
         IB5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MkzKVH66Fk6u7scow77V9wNFhR3Hr5HgZbWoqqhX3Jk=;
        b=xwguKHCypEIn2l97vk8mWlKEJk2tXOipeAzPAuPAsikzmfqORg3qiZ+5sCROrlqGUN
         5j0JDa4BxbyjI4F6udHwT0eournvDG3wXAbNamE0QNCL93/5UfCnilUhZU3xL7GPryLx
         M8ARcUWL6jy9gQtDpMZWTdReUJHhJy6oJbRwn/XQCl3nSmLF9B+WG7ZkyK9uCEWG8t1J
         vJ0CpesYWsF+SpDZxwr7BSgDXTiiGkTeS97r8h8QK9TDiLgzbbTxE6TXaJSDlUbGDPxI
         hznUIoVZQ98BYi+i863erSRUq0JsY/ylAD+O+OSM7gkkRpLI2OqIe3gGZhc87AuIzQHZ
         IAhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bQqLW/BV";
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MkzKVH66Fk6u7scow77V9wNFhR3Hr5HgZbWoqqhX3Jk=;
        b=PFnfotJ4H86dcLphhyzt7/5qqcK59xSpLq9RFqlIqPl0IW4Jg5F1dBh3Q/DYp9QH0i
         gpxB0QvlGN6feECZ/L3RcWfpqyUXgfwy0tCgqViNWrGvQ2R0KOroqdTjd6eSVkVy8ste
         uzNf1wib3J/Yz6MDzAMn2OZ3/qBqNsiSn1Fvq643TnGP2y0AW1YsxmCMkt/1qWDtAsb7
         l1PKKr6fo9/WEfzlTdJ0eXjNvr0/63oEHJIijhZHxb0QlgHsE0uXR7XO5mxNoervX3u+
         scB36TrzUSV+66AqPlGGuGBEpqFa0Uffv0FrHtxsOa9fwzCle3odZAPEdNp1zjwNlmpV
         8n2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MkzKVH66Fk6u7scow77V9wNFhR3Hr5HgZbWoqqhX3Jk=;
        b=Qtjj+u9evAhiTSbEx7rVUh3rYIhoxYOi01L1TwkStORPSjl7URyDbOjT/Y9N9B5e/R
         9EVPSdctf+0Zbh00KwFsJt2w4D4uSLU0KXgsxL829aq20sQYJm+nI2V4UoVyhULbGk/8
         ndwVhJTBYuKYV4tUGoNibORNqrYr/tqQy3g+kRIP3o7LyAlY5lmHueSakFkyrR0RCA6v
         ss19KeUZqRfyBQTmohgTfvEJAN920jFvbwxsjtXN0tJblJ/KjUST69pcZ2ekOLA9eASL
         LEw0Ga84RED9hEgFJFe8Zqwp1/ODDVbphkhQHZmTccyIjJFZ2poCX5kUuvcSUzP+GXQt
         Vb0Q==
X-Gm-Message-State: AOAM533MiV3vOXSGFz4frob87UsKjvvFdEcdjILkLd0BrqdrQhAOAqPb
	ZtbAaJBbRgUW19mw4GHpAWA=
X-Google-Smtp-Source: ABdhPJzfvv5yecAg2o+xbot9qh2N5iAW+3FWAql9gQLxpNT5K0FK6QU8K8C1x3LiPMgTY0XpTfEmuA==
X-Received: by 2002:a6b:ef03:: with SMTP id k3mr5323825ioh.203.1589481304675;
        Thu, 14 May 2020 11:35:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6a2a:: with SMTP id l42ls663013jac.8.gmail; Thu, 14 May
 2020 11:35:04 -0700 (PDT)
X-Received: by 2002:a02:a1c8:: with SMTP id o8mr5909509jah.38.1589481304291;
        Thu, 14 May 2020 11:35:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589481304; cv=none;
        d=google.com; s=arc-20160816;
        b=WyRXk3Kmx0tMVIAxkwZbDC7APDBiDF7PiLQApajTCjQ5OwbdpeXHUNZ4qzwTO8+Z/8
         ZlW0vzTxbsbNHd3V6TXdLkTtRomyGvx2z6TS5buuizP4bhD4l54n4FO8J9mrp531tVLP
         V9grMU91jVm4IESTJb6PVozf1V7FTqxHAqMGxJeSrQHdtsp71/ULMwVvJnkHv3aG2tRe
         Pbzv++Z75sg2HLluz8wHo23yY70Iwi4761JyWjwyV3+vx2tXnZT4UzVQzkt/6wzsjtG1
         lA7Bnjqd1UsALeoRx9CDNqom7pGkuW8uAXkHmBsnDI1LCvttNlb+MEBUwQpnIu4JPwWe
         jV8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mtE5hwcvwfyJVGtyn1TG67y7LoZm45ccVgYKdHYy5J0=;
        b=hBurgkNpvREVFoh2dxmvbjOpxGdmdRgTvj9IJECil6A5yKaueykkkPeRelJuOzrtMH
         gYI2X2cNZMTGCZudhrId4SNJE8ag3peAEN6wQGLod46h2GarrCt82T1PYP+bRlfDZUOW
         zpYWHDn0Kd1wZrLGl1XQYTM5seDSvKhmlMIEBZ051I41oXULZSXUqIQ39MO7Jp8ED7jm
         BKdZlWL1fhk0MY0bFdruTR8g98BZjIKeB6EnQe3RT29wln6aXL32IieJ/sDTZlDM6xN6
         dMh81hwets5jIx8smi0KKen2ZBTjfdYQwiIMPFG8fMYdSkUmR4ArN8riybWqFSd1H+hU
         Q8Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bQqLW/BV";
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id o6si321203ilo.4.2020.05.14.11.35.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 May 2020 11:35:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id u35so1615846pgk.6
        for <kasan-dev@googlegroups.com>; Thu, 14 May 2020 11:35:04 -0700 (PDT)
X-Received: by 2002:a65:5ac4:: with SMTP id d4mr4987649pgt.381.1589481303167;
 Thu, 14 May 2020 11:35:03 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
 <CAKwvOdnQaeQ2bLqyXs-H3MZTPBd+yteVG4NiY0Wd05WceAad9g@mail.gmail.com> <CANpmjNPLgFdFpHzj5Hb_1CfFzPMmqy3z1O98N=wsr8kQ1VS9_Q@mail.gmail.com>
In-Reply-To: <CANpmjNPLgFdFpHzj5Hb_1CfFzPMmqy3z1O98N=wsr8kQ1VS9_Q@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 May 2020 11:34:52 -0700
Message-ID: <CAKwvOd=0Ducgnkf8tzNGH10_UJSk56Ff_oSyGMddBCyG3Xt5Gg@mail.gmail.com>
Subject: Re: ORC unwinder with Clang
To: Marco Elver <elver@google.com>
Cc: clang-built-linux <clang-built-linux@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="bQqLW/BV";       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Thu, May 14, 2020 at 11:04 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, 14 May 2020 at 19:48, 'Nick Desaulniers' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > + Josh, Peter
> >
> > On Thu, May 14, 2020 at 10:41 AM Marco Elver <elver@google.com> wrote:
> > >
> > > Hi,
> > >
> > > Is CONFIG_UNWINDER_ORC=y fully supported with Clang?
> >
> > We're down to 4 objtool warnings in an allyesconfig build.  3 I
> > understand pretty well, and patches exist for them, but I haven't
> > looked into the 4th yet.  Otherwise it works (to the best of anyone's
> > knowledge).  Though kbuild test robot has dug up 4 new reports from
> > randconfigs that I need to look into.
> >
> > Here's our list of open issues with the objtool label:
> > https://github.com/ClangBuiltLinux/linux/issues?q=is%3Aopen+is%3Aissue+label%3A%22%5BTOOL%5D+objtool%22
> >
> > I remember Josh mentioning
> > https://github.com/ClangBuiltLinux/linux/issues/612 which I haven't
> > had time to look into.
> >
> > >
> > > I'm seeing frames dropped in stack-traces with
> > > stack_trace_{dump,print}. Before I dig further, the way I noticed this
> > > is when running the KCSAN test (in linux-next):
> > >
> > > CONFIG_KCSAN=y
> > > CONFIG_KCSAN_TEST=y

(KCSAN_TEST depends on CONFIG_KUNIT=y, needed to enable that, too on
top of defconfig).

> > >
> > > The test-cases "test_assert_exclusive_access_writer" for example fail
> > > because the frame of the function that did the actual access is not in
> > > the stack-trace.
> > >
> > > When I use __attribute__((disable_tail_calls)) on the functions that
> > > do not show up in the stack traces, the problem goes away. Obviously
> > > we don't want to generally disable tail-calls, but it highlights an
> > > issue with the ORC unwinder and Clang.
> > >
> > > Is this a known issue? Any way to fix this?
> >
> > First I've heard of it.  Which functions, and what's the minimal set
> > of configs to enable on top of defconfig to reproduce?
>
> In linux-next:
>
> CONFIG_KCSAN=y
> CONFIG_KCSAN_TEST=y
>
> And wait for the "test_assert_exclusive*" test-cases, which will fail.

For me, all of the tests fail with:
test_basic-02: too few online CPUs (1 < 2) for test
but I guess that's because my QEMU virtual machine only has 1 cpu?
Ah, if I add `-smp $(nproc)` to my invocation I can get past that.

I see:
test_basic_*
test_concurrent_races*
test_novalue_change_exception*
test_kernel_write_nochange_rcu*
test_unknown_origin*
test_write_write_assume_atomic*
test_write_write_struct*
test_write_write_struct_part*
test_read_atomic_write_atomic*
test_read_plain_atomic_write*

Tests take about 3 minutes to run for me, but I didn't see any
test_assert_exclusive*.  Should I look again, or am I missing a
config, or perhaps a patch?  This is my first time running KUnit, too.
Is there a way to specify just the single unit test you'd like to run,
a la gunit, or do you have to run the full suite?

> The stack traces of the races shown should all start with a
> "test_kernel_*" function, but do not. Then:
>
>   sed -i "s/noinline/noinline __attribute__((disable_tail_calls))/"
> kernel/kcsan/kcsan-test.c
>
> which adds the disable_tail_calls attribute to all "test_kernel_*"
> functions, and the tests pass.

That's a good lead to start with.  Do the tests pass with
UNWINDER_FRAME_POINTER rather than UNWINDER_ORC?  Rather than
blanketing the kernel with disable_tail_calls, the next steps I
recommend is to narrow down which function caller and callee
specifically trip up this test.  Maybe from there, we can take a look
at the unwind info from objtool that ORC consumes?

-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3D0Ducgnkf8tzNGH10_UJSk56Ff_oSyGMddBCyG3Xt5Gg%40mail.gmail.com.
