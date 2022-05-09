Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCUN4WJQMGQEGJ4J2PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id D9CE35202F0
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 18:51:23 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id l7-20020a05622a174700b002f3c49f49ffsf9387294qtk.15
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 09:51:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652115082; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pm0eGUkATt9Mp43YDBS0IP6+gXhikKXoOdmdFHw/TtnZhcoDeyeiFbwo5McYaxTBCb
         w/6kCViB9SpppWRvIjnwPy0wLrDZgYHAqhwWZ4Vrw1btsKNDAkDUMfVvejiA48ShlL0+
         W2u7HgPuPV+WbsugSLtIodKqtwP+r3GOzrtVGZ86/qFxvbEIrIXUrGGf/a9VjSruGFjD
         sC9WedpDYN5JMvCbml+wNVvraUcW3djJAGBQtTlKA3zJbSzU0yEdlNJAOU3bTFkCfeSF
         XxOB1rhv73wSuFENIc9bxqK1Z72GYhSZFq3BDa+RrXN80EMM+nQYhW50x0XoIoCcD7M5
         ihUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GQSm7q+fzCPPoN2G/7bO/KNF7QKpdf7O5e3SozSO9Rg=;
        b=AwG8fc2XZppTuWHGRAP6JC26SYLjc9s2nkuJQj8fzfhDdXzU8k93siKVMv6f1zFjQu
         YvMaKH/XfqFmiGpWQKs6vaTUaOP7ik0xvf7iyo7pWpPrNLkv39OBmZU+AJ+m6+NScXI5
         7q5B4O4dfhLElvtbKCz2J1Cn2SW4gdzdHGy/qzCkZRyrheTRkkvwIaA3wHQKQsZiYa6x
         xG6cpGRToq2Dmgg6Bzg9Kbk3FX7JuQ7p3aY6Ab8cVJ4oCL9euazh/d0o0+KZz0paCIWm
         ePn4Jno5SYSz6zOUCGs5G0Rw1okCWDQXyz6Ilhn3pXJ+YzsajpAOu/9ZHb8dGiq0OIo7
         d74A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qzQQBeDI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=GQSm7q+fzCPPoN2G/7bO/KNF7QKpdf7O5e3SozSO9Rg=;
        b=SYgMXS/u+tDadSaoFQrMmoaseamMUiNVxcZCdWUe4MWgPqsB2fHUzdENpTnwblWJJS
         mL67C4yhkYnfu74YYlZ/7ijTPZQ52g/yHWsW2klKX+1hydyzLoV7WQCRE4jVHkNzA207
         DiVjkP7xzzhDzxt7Gts+m6FwdSn5ww9C17Mej9wdEB2d/K0gLvvEq1whpNlxvsQaVwr4
         dDTgmwwjkwK0v77I2Y5f/heWqDTrcTdpC/iOqOTBLx6iEHhyL6UeyL2BPbboFwQDKsTQ
         4Zcp+WrOrONZfbl/2c5Mo2ZefUDGZxum3truNDRI72p56xjekuxMD8eipYuHy1YK6GVO
         Wkjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GQSm7q+fzCPPoN2G/7bO/KNF7QKpdf7O5e3SozSO9Rg=;
        b=cefyyMKOMI/ORb7PhSUPrR/v0uObNPCmHBsfmmJQzAbmiU+f+ue9UE+AFEplJS2GZN
         XcITnA0h/koulmURFKRSNY78kW5CmRx5wumHn0KR+fuT6Wuw4MKN5Sm+nBqu9tLiAZxX
         2/k8KV421NrYor6m7R5lkRpDmiL+HSakDlcUtdPZud30nWd1Kk7tisojQlAsnwLhH3qS
         lK6xkxsyQsvddeIEZ0ZA9oMfB7WSCRrT3rc9KcsHn03amlSv20oc1lHp7Z2f/c7+EJ35
         kSI5oSEgabaYdep6NOIFlVby1cIjY3LFyOGHHRCDwJo1LD1q3EF+L0L/QhiUWeSjsSpZ
         izTg==
X-Gm-Message-State: AOAM5330dWqUYAAtdk/XTq0/oidVXZ0ytVp8UcQX6Zr6oRIAMH+7cgYL
	wYgT5OL5wRT/jpcGHRtRZFE=
X-Google-Smtp-Source: ABdhPJwazWtJ2Pf2bvSYlsNBD/DgTO35x4Z+UpD6mL82H5K14CFOiqvydmhhFdeb7NaiRWaYw6P3sw==
X-Received: by 2002:ad4:4ee7:0:b0:45a:f17a:2a56 with SMTP id dv7-20020ad44ee7000000b0045af17a2a56mr12283724qvb.33.1652115082578;
        Mon, 09 May 2022 09:51:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2902:b0:6a0:858b:a9ec with SMTP id
 m2-20020a05620a290200b006a0858ba9ecls2070046qkp.10.gmail; Mon, 09 May 2022
 09:51:22 -0700 (PDT)
X-Received: by 2002:a05:620a:4014:b0:6a0:2701:b574 with SMTP id h20-20020a05620a401400b006a02701b574mr12422223qko.620.1652115082128;
        Mon, 09 May 2022 09:51:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652115082; cv=none;
        d=google.com; s=arc-20160816;
        b=byM6e404BFurUSibnEKuuyrzdnTDeQL5BTULrDClkZeSY7tUmvXhjpTKobZ5ZZvluu
         VLDnl6NnmtwF5hC5PRL9/iPgAqMMPGcJNO2SkQzKveHA1ZiSz0XgO37hUFcYUjnAe6Kr
         uGNfJVe+ueKx7jdk44VRNUlY1aUNy5zDII/h2Znnk83nx04uOIuAQP6qXrKonM6IuBfc
         bKDn75qkfJjD8PeCQ17Mx9PXfry1CG3GSvN7B8hhyemuoBXGtcdfRVf6UJ/ivPzw+0g2
         bJ3xlg8bLl2xJEMalZhJ/9K1tggnq23fNwvyIaGX/gI4eMm7ZllNLW9/GyeuW93klSP9
         /aQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xv3YNr+ejtNXLt/3K/MJW1lmyFr4+HmU5M46knKl15A=;
        b=UdM8G2sXZLf1i9EQX36G0g2+g7EO/BTtW3n3buAhl8X5HmW1MIn0vZxdIQCoTD4SHt
         AnPnHvVlsLKdk/gEO3lj5+dgSTtJvpfjKLxySU/T39o6Mgm5+W3K+R7ffYj2U5TbJ8OX
         D0keiM0i54LKDG8jUjKOcsYeIj2gie+58Nsh95tcEAyOX5gUPkbXSXURfbZxf8JiKRYa
         vqDF8nnjKIAphXhwbxEsw+DGvDykIFaNCJxMCIh3DdopcRJkBNNF0goSwRCBswFC+Mrh
         scVE0l4+X9CSyxl6g/mMO11o9SlTFP6Kxl3gE3joNxWAChet5yVgcG2Fn1TLu1tZ8NLw
         Zxfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qzQQBeDI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id l18-20020a05620a28d200b0069f8dcf5fa2si847522qkp.6.2022.05.09.09.51.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 May 2022 09:51:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id v59so26004596ybi.12
        for <kasan-dev@googlegroups.com>; Mon, 09 May 2022 09:51:22 -0700 (PDT)
X-Received: by 2002:a25:aa62:0:b0:648:590f:5a53 with SMTP id
 s89-20020a25aa62000000b00648590f5a53mr14674322ybi.5.1652115081586; Mon, 09
 May 2022 09:51:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-29-glider@google.com>
 <87a6c6y7mg.ffs@tglx> <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx> <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx> <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
 <87k0ayhc43.ffs@tglx> <CAG_fn=UpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D+4Pttc9dA@mail.gmail.com>
 <87h762h5c2.ffs@tglx>
In-Reply-To: <87h762h5c2.ffs@tglx>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 May 2022 18:50:45 +0200
Message-ID: <CAG_fn=UroTgp0jt77X_E-b1DPJ+32Cye6dRL4DOZ8MRf+XSokg@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=qzQQBeDI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as
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

> The callchain is:
>
>   asm_sysvec_apic_timer_interrupt               <- ASM entry in gate
>      sysvec_apic_timer_interrupt(regs)          <- noinstr C entry point
>         irqentry_enter(regs)                    <- unpoisons @reg
>         __sysvec_apic_timer_interrupt(regs)     <- the actual handler
>            set_irq_regs(regs)                   <- stores regs
>            local_apic_timer_interrupt()
>              ...
>              tick_handler()                     <- One of the 4 variants
>                 regs =3D get_irq_regs();          <- retrieves regs
>                 update_process_times(user_tick =3D user_mode(regs))
>                    account_process_tick(user_tick)
>                       irqtime_account_process_tick(user_tick)
> line 382:                } else if { user_tick }   <- KMSAN complains
>
> I'm even more confused now.

Ok, I think I know what's going on.

Indeed, calling kmsan_unpoison_memory() in irqentry_enter() was
supposed to be enough, but we have code in kmsan_unpoison_memory() (as
well as other runtime functions) that checks for kmsan_in_runtime()
and bails out to prevent potential recursion if KMSAN code starts
calling itself.

kmsan_in_runtime() is implemented as follows:

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
static __always_inline bool kmsan_in_runtime(void)
{
  if ((hardirq_count() >> HARDIRQ_SHIFT) > 1)
    return true;
  return kmsan_get_context()->kmsan_in_runtime;
}
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
(see the code here:
https://lore.kernel.org/lkml/20220426164315.625149-13-glider@google.com/#Z3=
1mm:kmsan:kmsan.h)

If we are running in the task context (in_task()=3D=3Dtrue),
kmsan_get_context() returns a per-task `struct *kmsan_ctx`.
If `in_task()=3D=3Dfalse` and `hardirq_count()>>HARDIRQ_SHIFT=3D=3D1`, it
returns a per-CPU one.
Otherwise kmsan_in_runtime() is considered true to avoid dealing with
nested interrupts.

So in the case when `hardirq_count()>>HARDIRQ_SHIFT` is greater than
1, kmsan_in_runtime() becomes a no-op, which leads to false positives.

The solution I currently have in mind is to provide a specialized
version of kmsan_unpoison_memory() for entry.c, which will not perform
the reentrancy checks.

> > I guess handling those will require wrapping every interrupt gate into
> > a function that performs register unpoisoning?
>
> No, guessing does not help here.
>
> The gates point to the ASM entry point, which then invokes the C entry
> point. All C entry points use a DEFINE_IDTENTRY variant.

Thanks for the explanation. I previously thought there were two
different entry points, one with asm_ and one without, that ended up
calling the same code.

> Some of the DEFINE_IDTENTRY_* C entry points are not doing anything in
> the macro, but the C function either invokes irqentry_enter() or
> irqentry_nmi_enter() open coded _before_ invoking any instrumentable
> function. So the unpoisoning of @regs in these functions should tell
> KMSAN that @regs or something derived from @regs are not some random
> uninitialized values.
>
> There should be no difference between unpoisoning @regs in
> irqentry_enter() or in set_irq_regs(), right?
>
> If so, then the problem is definitely _not_ the idt entry code.
>
> > By the way, if it helps, I think we don't necessarily have to call
> > kmsan_unpoison_memory() from within the
> > instrumentation_begin()/instrumentation_end() region?
> > We could move the call to the beginning of irqentry_enter(), removing
> > unnecessary duplication.
>
> We could, but then you need to mark unpoison_memory() noinstr too and you
> have to add the unpoison into the syscall code. No win and irrelevant to
> the problem at hand.

Makes sense, thank you!

> Thanks,
>
>         tglx
>
>


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
kasan-dev/CAG_fn%3DUroTgp0jt77X_E-b1DPJ%2B32Cye6dRL4DOZ8MRf%2BXSokg%40mail.=
gmail.com.
