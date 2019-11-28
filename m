Return-Path: <kasan-dev+bncBCMIZB7QWENRBR6H73XAKGQEDZ2PQVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id E7DA310C6D9
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 11:39:04 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id b3sf3422182vsl.12
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 02:39:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574937543; cv=pass;
        d=google.com; s=arc-20160816;
        b=fYITlIGCRcl3rDSaBkM5d1vKFkGcOwUsxoM7bP14N890Ak2gq2Uw2jQ6Z631RZ4Ngv
         M25Gz26fgBWQB0R14aRmAPgYMmtVMuWdq3NRxSWHx7oURUXZZgl3EH3LOHlgNfE1Vf6H
         magA3PvZ8VWYjdmEeTnCWd7E0Cn5T5f/tUJzsWYsVOPBFBBbwEz4IduZ5ixaeTP+EmTT
         9xygBaPDDeBLkZqo8KExwqPTqrL5B+2kUWXLs5B3UuRPj1zZyM4WMT2UGDIpSnM3lZLU
         m8hVu1OqpgNHQcJTKcCH88/i/+qCgAxR128Btb06k1QqXVAQ7mRFWp8hExWVFOF5a3/I
         TL1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YGL+tnyDie2tyiorw9K8U23+53A0EgaUtXhGsMO1Oeg=;
        b=F709wTqeWbW21N7O8rDYWr6M2av0cF4BYq28SzewSYXHDyDqglsV3rA/hSaWCtx0jW
         DO/tdskQ15Mvv5XxA9ODdfvJrisYfSg63CpukSKy233A0MMjCP+UPCViDOM6sVBjf6PW
         lJBPVVViL0tJqZYSlbK0B2aXKqr9J+7xDWWf8org9NVmbhX/RupWgIeeMegfCBzRCMsj
         UbLu2zIb+lD+6WtYuQeGiGrJy5XWll5BuparGOAAKirsVLo3c2nVQaVwkaAV6+89RmMd
         Sz8ZtHYoSESFX2pcJgbQOwJgTzkwN8nmo6f+sSilo6wFEL2cNlSsC9Rfqp/oy7O/pPdN
         bHnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iVMSh8YU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YGL+tnyDie2tyiorw9K8U23+53A0EgaUtXhGsMO1Oeg=;
        b=QnxTrr1l7gGvwc+CmFci2t9yDBDxRjM9piCUvoYjtWY0nw4a4jBJCwkg/tTu96C9Kd
         qCsHB83tmOVEMrC9+V1iaeguuMdE9clLKdQXsK7I95y16iUURCJWKTlsQ0ypKJQCbUsP
         kIMck3m1Tsi/6udfFxkGOv3HdmEdd/IFJCFHyPiqjwTnRT8vnZ4qhA/BfEQA8ZoLL6OR
         X1NJFKfCy5t1Wl2hxr0QBMHqzV7/RztamcuCcWLQL27RaUxtV9+C2NP+mT1CCj0J/gks
         RyMX+4v7jTt5YtfVl2PG6JGvfvmmwR18yo/dU1KtYVwJ3UqeuQrskoCMCE2inDmVH2aY
         Uhhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YGL+tnyDie2tyiorw9K8U23+53A0EgaUtXhGsMO1Oeg=;
        b=d9VrCCzdiN+8U1a8jzI2wSxPLgm/GCG6j8+lFDBp7otgDQk7f6rhtw5D1B2HdOZxEH
         u7BsB8hBeR4hZ6lcvZU4kVgIP6xSV1OCK+tW1HPEqm+DDNrB+mxPHp0Fg2CJU//e/Wes
         XyDQY00dcVfbmlt1x1xCDi8R6slmyP6be3vsQ1M02xRlTR3X9K+eu2fhe1oC1FAiwDz1
         /0yApdkylzYQTlVUF5h/ftFtAMXQuz4oFwRxDWqcsW9CmLK6UWxmpSu3vTWj61PbHlM5
         3NePi6jz5NYIVQrYKGcklGuPui5wueQBGtpTLIYejoOf0gGCFEFqrhe38XuP96+LaDlG
         GeRQ==
X-Gm-Message-State: APjAAAXx8ska119C41Y+NW+ONtBDtPf4iixYplUzZ+Sk9HNg6Ym3F9pI
	gbgUUNqdPmj76aUY65yOwuw=
X-Google-Smtp-Source: APXvYqwFGhc7ego2lrTMhQ9CIA+TqthrvIgPEO11TZ+KEcfr4CpnyUMgoJ2AC0T9///R7hMncuVzfA==
X-Received: by 2002:a1f:c1c4:: with SMTP id r187mr4163545vkf.73.1574937543659;
        Thu, 28 Nov 2019 02:39:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3dc1:: with SMTP id e1ls1623222uaj.12.gmail; Thu, 28 Nov
 2019 02:39:03 -0800 (PST)
X-Received: by 2002:ab0:30eb:: with SMTP id d11mr4643020uam.67.1574937543218;
        Thu, 28 Nov 2019 02:39:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574937543; cv=none;
        d=google.com; s=arc-20160816;
        b=cM2pP7rjCfxfEmYsSPB3FHluga0N4Ph0nj3206Ewatts2hqeVKiie7xsN5TFwHSC2Z
         euU2BKnWPRlybN0nS0BroGkGg67O1/hRmRPjCRml1TasGFeNC8JqzB/mt98Ft8IMvgm0
         53929tP6/7gk2pbcDr9AlpxsTjAZjUdm7PEBxtzFx1vsTcDhv5PG3bhFEsNcytN1KN11
         iBC46dpOK/49Rt7claU1+IrPp7veqz7I/H12VDr2cJAwTtvaLqaVA2Nh4tqOjGMKsV94
         Mz1gqRQyZWgn4QKr++6ukd6HMkXP5DhJSnyE6RToBhSsSs4c0I7PXA5k3gi4jdcXCgEr
         mm4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p3AKvN/tO+lhaStDPMa1Kw8KDL4h3X77pfKSOUhTuZk=;
        b=D/j/nbU1hzkPgmchT+xgD//2h+D8LPCJNOa6wEiaRJfnOpSuJr7h6uejIurVGJF84/
         MLoH3JcQdJgVJLDxUcYFpSlFV4XT8cZA/d5lpwHtNcH1krL4ydpFsNjnKuy43t2hhkBU
         ge0IQTCvGLL2tYdZi0VPa+m/ZXrewHmVdYDweFy4KWcvEeJZ7JFdgXGvrFLHgRFrQSik
         t95IDTz1p53NOPWY927GTMf38hr4khw4c/go0Z2v932hR9HJZGK+ji5KHqnsK48MPqix
         hIfUvNK5Ir5QhcX0nd3jARpB9BKqLKSBdngvuGaqi11A8hXvwJJd6Dc2oXPPwfm1wSIE
         SolQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iVMSh8YU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id x127si420060vkc.0.2019.11.28.02.39.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Nov 2019 02:39:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id x1so7561567qkl.12
        for <kasan-dev@googlegroups.com>; Thu, 28 Nov 2019 02:39:03 -0800 (PST)
X-Received: by 2002:a37:de12:: with SMTP id h18mr9389184qkj.256.1574937542172;
 Thu, 28 Nov 2019 02:39:02 -0800 (PST)
MIME-Version: 1.0
References: <20191121181519.28637-1-keescook@chromium.org> <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
 <201911262134.ED9E60965@keescook> <CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com>
 <CACT4Y+aFiwxT6SO-ABx695Yg3=Zam5saqCo4+FembPwKSV8cug@mail.gmail.com> <201911270952.D66CD15AEC@keescook>
In-Reply-To: <201911270952.D66CD15AEC@keescook>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Nov 2019 11:38:50 +0100
Message-ID: <CACT4Y+a-0ZqGj0hQhOW=aUcjeQpf_487ASnnzdm_M2N7+z17Lg@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Alexander Potapenko <glider@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Arnd Bergmann <arnd@arndb.de>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, kernel-hardening@lists.openwall.com, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iVMSh8YU;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Wed, Nov 27, 2019 at 6:59 PM Kees Cook <keescook@chromium.org> wrote:
> > > > > > v2:
> > > > > >     - clarify Kconfig help text (aryabinin)
> > > > > >     - add reviewed-by
> > > > > >     - aim series at akpm, which seems to be where ubsan goes through?
> > > > > > v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org
> > > > > >
> > > > > > This splits out the bounds checker so it can be individually used. This
> > > > > > is expected to be enabled in Android and hopefully for syzbot. Includes
> > > > > > LKDTM tests for behavioral corner-cases (beyond just the bounds checker).
> > > > > >
> > > > > > -Kees
> > > > >
> > > > > +syzkaller mailing list
> > > > >
> > > > > This is great!
> > > >
> > > > BTW, can I consider this your Acked-by for these patches? :)
> > > >
> > > > > I wanted to enable UBSAN on syzbot for a long time. And it's
> > > > > _probably_ not lots of work. But it was stuck on somebody actually
> > > > > dedicating some time specifically for it.
> > > >
> > > > Do you have a general mechanism to test that syzkaller will actually
> > > > pick up the kernel log splat of a new check?
> > >
> > > Yes. That's one of the most important and critical parts of syzkaller :)
> > > The tests for different types of bugs are here:
> > > https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report
> > >
> > > But have 3 for UBSAN, but they may be old and it would be useful to
> > > have 1 example crash per bug type:
> > >
> > > syzkaller$ grep UBSAN pkg/report/testdata/linux/report/*
> > > pkg/report/testdata/linux/report/40:TITLE: UBSAN: Undefined behaviour
> > > in drivers/usb/core/devio.c:LINE
> > > pkg/report/testdata/linux/report/40:[    4.556972] UBSAN: Undefined
> > > behaviour in drivers/usb/core/devio.c:1517:25
> > > pkg/report/testdata/linux/report/41:TITLE: UBSAN: Undefined behaviour
> > > in ./arch/x86/include/asm/atomic.h:LINE
> > > pkg/report/testdata/linux/report/41:[    3.805453] UBSAN: Undefined
> > > behaviour in ./arch/x86/include/asm/atomic.h:156:2
> > > pkg/report/testdata/linux/report/42:TITLE: UBSAN: Undefined behaviour
> > > in kernel/time/hrtimer.c:LINE
> > > pkg/report/testdata/linux/report/42:[   50.583499] UBSAN: Undefined
> > > behaviour in kernel/time/hrtimer.c:310:16
> > >
> > > One of them is incomplete and is parsed as "corrupted kernel output"
> > > (won't be reported):
> > > https://github.com/google/syzkaller/blob/master/pkg/report/testdata/linux/report/42
> > >
> > > Also I see that report parsing just takes the first line, which
> > > includes file name, which is suboptimal (too long, can't report 2 bugs
> > > in the same file). We seem to converge on "bug-type in function-name"
> > > format.
> > > The thing about bug titles is that it's harder to change them later.
> > > If syzbot already reported 100 bugs and we change titles, it will
> > > start re-reporting the old one after new names and the old ones will
> > > look stale, yet they still relevant, just detected under different
> > > name.
> > > So we also need to get this part right before enabling.
>
> It Sounds like instead of "UBSAN: Undefined behaviour in $file", UBSAN
> should report something like "UBSAN: $behavior in $file"?
>
> e.g.
> 40: UBSAN: bad shift in drivers/usb/core/devio.c:1517:25"
> 41: UBSAN: signed integer overflow in ./arch/x86/include/asm/atomic.h:156:2

If you mean make them such that kernel testing systems could simply
take the first line as "crash identity", then most likely we need
function name there instead of file:line:column. At least this seems
to be working the best based on our experience.


> I'll add one for the bounds checker.
>
> How are these reports used?

There are test inputs, each also contains expected parsing output
(title at minimum, but can also contain crash type, corrupted mark,
extracted "report") and that's verified against actual parsing result.


> (And is there a way to check a live kernel
> crash? i.e. to tell syzkaller "echo ARRAY_BOUNDS >/.../lkdtm..." and
> generate a report?

Unfortunately all of kernel tooling is completely untested at the
moment. We would very much like to have all sanitizers tested in a
meaningful way, e.g.:
https://github.com/llvm-mirror/compiler-rt/blob/master/test/asan/TestCases/global-overflow.cpp#L15-L18
But also LOCKDEP, KMEMLEAK, ODEBUG, FAULT_INJECTS, etc, all untested
too. Nobody knows what they produce, and if they even still detect
bugs, report false positives, etc.
But that's the kernel testing story...

No, syzbot does not do kernels unit-testing. And there are no such
tests anyways...



> > > > I noticed a few things
> > > > about the ubsan handlers: they don't use any of the common "warn"
> > > > infrastructure (neither does kasan from what I can see), and was missing
> > > > a check for panic_on_warn (kasan has this, but does it incorrectly).
> > >
> > > Yes, panic_on_warn we also need.
> > >
> > > I will look at the patches again for Acked-by.
> >
> >
> > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> > for the series.
>
> Thanks!
>
> >
> > I see you extended the test module, do you have samples of all UBSAN
> > report types that are triggered by these functions? Is so, please add
> > them to:
> > https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report
>
> Okay, cool.
>
> > with whatever titles they are detected now. Improving titles will then
> > be the next step, but much simpler with a good collection of tests.
> >
> > Will you send the panic_on_want patch as well?
>
> Yes; I wanted to make sure it was needed first (which you've confirmed
> now). I'll likely not send it until next week.
>
> --
> Kees Cook
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/201911270952.D66CD15AEC%40keescook.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba-0ZqGj0hQhOW%3DaUcjeQpf_487ASnnzdm_M2N7%2Bz17Lg%40mail.gmail.com.
