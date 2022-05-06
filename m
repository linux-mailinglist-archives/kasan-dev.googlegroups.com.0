Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVXM2SJQMGQETRVX4AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB62A51DB2F
	for <lists+kasan-dev@lfdr.de>; Fri,  6 May 2022 16:53:12 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 204-20020a6302d5000000b003c273168068sf3721738pgc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 06 May 2022 07:53:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651848791; cv=pass;
        d=google.com; s=arc-20160816;
        b=c6YZhYTgjxZlYZSA8SQL1afVFjhGT9JvGsPzfDBveyeGRI79/Y/0ahXwi1oNIv7QT/
         PKIVY4BYdlD1AD6ultw8qfwz1FulR3wVPb8swsgBfGl6UTuu1hawHaoYJqG0dzzPZrZB
         S0yvkW9KmzjEH5LtAuJwQLeEsVZnW5C+6gyntEztsu+eQIVZclcEslg70aK5sW3cni1W
         FGVK6Q9xmmNMJ6x0DS+Z8xZUJBifhcy/eKOIMf//RH28TcusTmZKe69v0OCTUJa2mA0u
         A+F53WyDEZwfa+H6KdX5Td3BVutoHzm0KEH2KM+02dRzfsG0PLa/HUUbQLon6hQ6OpiK
         fTQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fUyjsB/X2R+Blddsgt0AMCoTwClXAGwV3Lt3zY2N/kw=;
        b=YNxYDrRvwIYefrrTSQsIaEcfpu7yY6Zlm5pHzPWsow9fdSa6MCTYBdBijdVJWIy8AP
         8HNUbty84na+jwIpYsA+9z19G7AZ0qch94oJM6o5PWZHnyGI0ibbgFmTTr1jvuTn0VoQ
         iPdqI0AnSgI5ZK+v7CNQFUmuULuRmcc3jy3wNvpEZYGcckqC15Sjd3Bct9cthBXhMX6n
         3P7g90Q4MqxVtI38GMKZxHI0IfL2Aiy9v8x1s4SNr4jKC5cSHDZ+Cpu8QvhrEqeFgBwI
         i/XD83vEvudgyJCFOEXo/fe3dx8YkVVTrYtn2mh98ihnR9wVxQCF3erXRRpzL8sqX8On
         G5Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hx3cfMOx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fUyjsB/X2R+Blddsgt0AMCoTwClXAGwV3Lt3zY2N/kw=;
        b=kbk9NCG/J5qAzi0dxBigL8xnH2sNJy4bbofgkwMhxhqQ4qOgg3kvwnP+l0ct10fxLZ
         NgpR6/fRPs3PPlyZ0d+Po4TuGkt3y8NIN/shU3WOUzrHgM3VjpFJYkobuJ46zt33So7r
         4YIWnfKGcV/EWCqozYS2mN89jykYl2NFd9lM0KixZ9ekySYBrjiHa4MJ1TdET/KYJVwL
         67tvdSAz8TA6U497ZGUv+iRlVkNluYEd289Oyf3iQRxWaHA4ARU7OvnGKq9rMUEWXpsr
         ZkfiDWzIS6PEsGhAEW3ft0Mmw4TKrRIOOlYlmByn5aSYCRb6xkmoEBm7mSJ7By52k/bZ
         sE3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fUyjsB/X2R+Blddsgt0AMCoTwClXAGwV3Lt3zY2N/kw=;
        b=mN0Og8VH9Zos4V5cYy7tAppbp2iTjzOFiRj43cGU3f8a0O0FCjUBRl/83+X+S9QWUV
         EguPvvzGgqMiawcxsq4YwdWumcv3KkyKLRR06arTOEX+WrAmxq54+Pf6kqRqN2R79SJb
         mzBoGaj8OQq8m1+ecze4QD1o0vd3A9fGKZ4c9F/YSEZONODLR38GkHNr6xEptX2RopIG
         jl4tnkCm2kTkJseYLexzwazDChufkomHLcyoyL9vvxK3OTObFXRMAgI/uGkc6NsXnOCe
         T0CLitRzidVZXglJUy6sncyhfSiIj6yfhkQQSPG4/LLlFNWYteT05DLfXkrB3RBJseIf
         wKiw==
X-Gm-Message-State: AOAM532uL6qJ9gZRT5ow9xE5uAzCyisZRFZH+X2b/L0f/ycYCpYQqr8G
	oZ0Y6VSJwArUEdaqQHVmx80=
X-Google-Smtp-Source: ABdhPJzYAoZH80hTpX8ttkQDilT7oTkskfVc/ck0PaDG1jBcDkWNeAt9ibVBpCgEKJ8L73ReY4LX4Q==
X-Received: by 2002:a17:90a:e7d2:b0:1dc:e6c6:604b with SMTP id kb18-20020a17090ae7d200b001dce6c6604bmr1344522pjb.183.1651848790847;
        Fri, 06 May 2022 07:53:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b017:b0:1dc:902e:363f with SMTP id
 x23-20020a17090ab01700b001dc902e363fls6530961pjq.3.gmail; Fri, 06 May 2022
 07:53:10 -0700 (PDT)
X-Received: by 2002:a17:902:d415:b0:15c:ea4b:7b8e with SMTP id b21-20020a170902d41500b0015cea4b7b8emr4078218ple.86.1651848790241;
        Fri, 06 May 2022 07:53:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651848790; cv=none;
        d=google.com; s=arc-20160816;
        b=k1j1i+4ea4BhOc1BVlyMp/PQ/042id4pG6n5INUngkqYzd2iRBJWaWbD2JyKsqKisb
         sK26eizJ5NNRX9ywfwjAXw73oL37G+aUFDvycx1XrZdQBnfAUzayyxgtZkGZbdaU23Sg
         3EeVcWfcxjfjteNdzQ63srI6j/s/RxBHHAU/oe3u68Oi8FmrKOUfWrNzEgc9//WlUZNb
         gM3KgFe4r2oz4e8H4P9nMJlwHA2/eduKS6hUf2FczLtfuF2B3yS/dnhtXU4CyHlVkb7g
         tfw8qE+wvzG5IkE9NaatiaUN1veEKqPk/+ecrHonvkBglx3TxqJ7+4GwBMF0/5p+2z4q
         ppOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8x1ByB3JGKsEKA0yU+drp41tFZX/S/sAjt0JU8w8Oas=;
        b=CoiQg96tFxtuJNYHnxvMcZsn9aAuJdPzHz1w8S/Xu17w1H++3KkhfqpYjcapbCxeZN
         ahx7GRvovQlv6EaHfHDRZxJqASQiUFk/LQRSmh6vr+3Vi5aUSqvjhMn4FgwoRCuQGi06
         mFpKEHYOwLjkOlImG1h/dwHY279XdETohAP4CSp7K6eX54Otpug1wDyb2vFjLt77/zbS
         bQAF0pGhQurgpqXZXqH/WUSKvUw1tl95DODUL+ooZaXbf/qVqtIo91pp7eGe2nSYVbBC
         TfN+e0gyBU2LklRVjZnh7YvYLc1K+5hl9t3eVlaSmammSgg9Rij11elUULTNZRmF0BOg
         JftA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hx3cfMOx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id q10-20020a170902edca00b0015a1cc64912si139940plk.3.2022.05.06.07.53.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 May 2022 07:53:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-2f83983782fso84170667b3.6
        for <kasan-dev@googlegroups.com>; Fri, 06 May 2022 07:53:10 -0700 (PDT)
X-Received: by 2002:a81:19d2:0:b0:2f8:ad73:1f33 with SMTP id
 201-20020a8119d2000000b002f8ad731f33mr2769528ywz.461.1651848789637; Fri, 06
 May 2022 07:53:09 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-29-glider@google.com>
 <87a6c6y7mg.ffs@tglx> <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx> <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx>
In-Reply-To: <878rrfiqyr.ffs@tglx>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 May 2022 16:52:33 +0200
Message-ID: <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=Hx3cfMOx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112d
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

On Thu, May 5, 2022 at 11:56 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> Alexander,
>
> On Thu, May 05 2022 at 20:04, Alexander Potapenko wrote:
> > On Tue, May 3, 2022 at 12:00 AM Thomas Gleixner <tglx@linutronix.de> wr=
ote:
> >> > Regarding the regs, you are right. It should be enough to unpoison t=
he
> >> > regs at idtentry prologue instead.
> >> > I tried that initially, but IIRC it required patching each of the
> >> > DEFINE_IDTENTRY_XXX macros, which already use instrumentation_begin(=
).
> >>
> >> Exactly 4 instances :)
> >>
> >
> > Not really, I had to add a call to `kmsan_unpoison_memory(regs,
> > sizeof(*regs));` to the following places in
> > arch/x86/include/asm/idtentry.h:
> > - DEFINE_IDTENTRY()
> > - DEFINE_IDTENTRY_ERRORCODE()
> > - DEFINE_IDTENTRY_RAW()
> > - DEFINE_IDTENTRY_RAW_ERRORCODE()
> > - DEFINE_IDTENTRY_IRQ()
> > - DEFINE_IDTENTRY_SYSVEC()
> > - DEFINE_IDTENTRY_SYSVEC_SIMPLE()
> > - DEFINE_IDTENTRY_DF()
> >
> > , but even that wasn't enough. For some reason I also had to unpoison
> > pt_regs directly in
> > DEFINE_IDTENTRY_SYSVEC(sysvec_apic_timer_interrupt) and
> > DEFINE_IDTENTRY_IRQ(common_interrupt).
> > In the latter case, this could have been caused by
> > asm_common_interrupt being entered from irq_entries_start(), but I am
> > not sure what is so special about sysvec_apic_timer_interrupt().
> >
> > Ideally, it would be great to find that single point where pt_regs are
> > set up before being passed to all IDT entries.
> > I used to do that by inserting calls to kmsan_unpoison_memory right
> > into arch/x86/entry/entry_64.S
> > (https://github.com/google/kmsan/commit/3b0583f45f74f3a09f4c7e0e0588169=
cef918026),
> > but that required storing/restoring all GP registers. Maybe there's a
> > better way?
>
> Yes. Something like this should cover all exceptions and syscalls before
> anything instrumentable can touch @regs. Anything up to those points is
> either off-limit for instrumentation or does not deal with @regs.
>
> --- a/kernel/entry/common.c
> +++ b/kernel/entry/common.c
> @@ -24,6 +24,7 @@ static __always_inline void __enter_from
>         user_exit_irqoff();
>
>         instrumentation_begin();
> +       unpoison(regs);
>         trace_hardirqs_off_finish();
>         instrumentation_end();
>  }
> @@ -352,6 +353,7 @@ noinstr irqentry_state_t irqentry_enter(
>                 lockdep_hardirqs_off(CALLER_ADDR0);
>                 rcu_irq_enter();
>                 instrumentation_begin();
> +               unpoison(regs);
>                 trace_hardirqs_off_finish();
>                 instrumentation_end();
>
> @@ -367,6 +369,7 @@ noinstr irqentry_state_t irqentry_enter(
>          */
>         lockdep_hardirqs_off(CALLER_ADDR0);
>         instrumentation_begin();
> +       unpoison(regs);
>         rcu_irq_enter_check_tick();
>         trace_hardirqs_off_finish();
>         instrumentation_end();
> @@ -452,6 +455,7 @@ irqentry_state_t noinstr irqentry_nmi_en
>         rcu_nmi_enter();
>
>         instrumentation_begin();
> +       unpoison(regs);
>         trace_hardirqs_off_finish();
>         ftrace_nmi_enter();
>         instrumentation_end();
>
> As I said: 4 places :)

These four instances still do not look sufficient.
Right now I am seeing e.g. reports with the following stack trace:

BUG: KMSAN: uninit-value in irqtime_account_process_tick+0x255/0x580
kernel/sched/cputime.c:382
 irqtime_account_process_tick+0x255/0x580 kernel/sched/cputime.c:382
 account_process_tick+0x98/0x450 kernel/sched/cputime.c:476
 update_process_times+0xe4/0x3e0 kernel/time/timer.c:1786
 tick_sched_handle kernel/time/tick-sched.c:243
 tick_sched_timer+0x83e/0x9e0 kernel/time/tick-sched.c:1473
 __run_hrtimer+0x518/0xe50 kernel/time/hrtimer.c:1685
 __hrtimer_run_queues kernel/time/hrtimer.c:1749
 hrtimer_interrupt+0x838/0x15a0 kernel/time/hrtimer.c:1811
 local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1086
 __sysvec_apic_timer_interrupt+0x1ae/0x680 arch/x86/kernel/apic/apic.c:1103
 sysvec_apic_timer_interrupt+0x95/0xc0 arch/x86/kernel/apic/apic.c:1097
...
(uninit creation stack trace is irrelevant here, because it is some
random value from the stack)

sysvec_apic_timer_interrupt() receives struct pt_regs from
uninstrumented code, so regs can be partially uninitialized.
They are not passed down the call stack directly, but are instead
saved by set_irq_regs() in sysvec_apic_timer_interrupt() and loaded by
get_irq_regs() in tick_sched_timer().

The remaining false positives can be fixed by unpoisoning the
registers in set_irq_regs():

 static inline struct pt_regs *set_irq_regs(struct pt_regs *new_regs)
 {
        struct pt_regs *old_regs;
+       kmsan_unpoison_memory(new_regs, sizeof(*new_regs));

        old_regs =3D __this_cpu_read(__irq_regs);
        __this_cpu_write(__irq_regs, new_regs);

Does that sound viable? Is it correct to assume that set_irq_regs() is
always called for registers received from non-instrumented code?

(It seems that just unpoisoning registers in set_irq_regs() is not
enough, i.e. we still need to do what you suggest in
kernel/entry/common.c)
--
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
kasan-dev/CAG_fn%3DXVchXCcOhFt%2BrP%3DvinRhkyrXJSP46cyvcZeHJWaDquGg%40mail.=
gmail.com.
