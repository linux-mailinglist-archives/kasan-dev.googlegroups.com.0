Return-Path: <kasan-dev+bncBDAMN6NI5EERBBVJYGJQMGQEUHPWSWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C90D1517999
	for <lists+kasan-dev@lfdr.de>; Tue,  3 May 2022 00:00:39 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id h12-20020a05651211cc00b00471af04ec12sf7252490lfr.15
        for <lists+kasan-dev@lfdr.de>; Mon, 02 May 2022 15:00:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651528839; cv=pass;
        d=google.com; s=arc-20160816;
        b=sh6aYA5Yo+sd4ykacZQ79uwb8CpbK+p5XIrDFly1TZ9mru3ctw0r36aWxOLoNuvCBC
         GSJswQqyQF4uNnbmlKdfAAnZrdkh5MFuvcC0ow9eKA/iN7PSr1GojBMI1gFtfQXqwtOu
         8/mG0zYL3i0FyFRUk+utNdFU0zCfZFt874AqC5IAuqS39VyIR0enuUzxoGOVCUtWmHNL
         JT1zh1/74R48XhkaIBb7533o6JhyNx/lKS3qTdo+DRzMuFX/3K8fdGgDkRKsBKOzFhsW
         KK7bmb3wGmXv41TGq97UCccZXU/2YbOUxIyKN6qmzWqPU2umrsFuLvssS73KeS6RZ7QE
         Mzuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=s2jKF8je2bjV1/WD0URFhxmixIp9ZsVIlCWbtpdLtFc=;
        b=POD2q1XIvEgCdCTuY3YbYYljvi+PeAwO4Ug41vCGmmLbFtz0mXFTeK5VCQ2TZfKVHl
         UdjuoQ68rvp6kAMKlA3cmsWCB7ttiTvcUH5qPwapbuP9qW+hYsenYXMD+B9i7g4qUPJq
         wMjhtlD6TL9JumaLPwwk9OgRK3P56mo1Ki9TmLvpntUb9JPtAiYD0D6AK70kUkG+fdAo
         k6iS60UeNHr9LlQlgKjvyWbUKcWCJvQpXyPz8a3vr88PzebgPNc10YWJABT5XouCBwdY
         MvMrsDmjSYoqOo8ub9LUEl3kyqY8yhrDruLXKqnlSCLp+Mda5h2isJi1tWhQQG+FpKna
         zUEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=J4ag3vPs;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s2jKF8je2bjV1/WD0URFhxmixIp9ZsVIlCWbtpdLtFc=;
        b=IZ6LyF1guwxC3SR3TKIyXnd9A5Y6FdZ234SV/ETFm+v/Fq42VC+jAPv3vzJUOE3Bsu
         h9RNxHWytW1a2X8iuqzuRed39r19WtzbsaEzyYnvb/eZ8T4DRaTOnz0TtzZgRzo33/GF
         sjU7qzxP1Uunrn3qmuw7xJ1PT+yl3ULTucTwhnLrnITpPEEi9gQa830Z2R/nAIJPLTd3
         EIEmCWqHfoE1KeaYJqBInOTiysce8AwNOu9JQ2lkVmQdcvw/SYEEHVT6oOdrJEADoL0T
         xuJUU/2/VOQ+nCn74dxA2g8cWI9EnfppOrzudDjaHne1a+xoWD3tjtg9JusHpSUrtoKO
         EiJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s2jKF8je2bjV1/WD0URFhxmixIp9ZsVIlCWbtpdLtFc=;
        b=EFuFE5JEU9GrAQji08dmXHJZmCNp2peU9+78RQ2t+wk7RYFhgSDh2jwWLE/3ONrvG/
         gdRy37e7f+RYCE34Y9bmNUL0aSmCxE+dwYoKyi68msSVhyCvy5WwEsRv9Iv7KbzS5e8C
         1RBS8AjBoPkNGmn9p4Ir7lzCwdzpDT92+PDKri3UYCzXX6Bbl51k5uNd0cNjxPdByXTM
         DmKXo77RsBYUKaHx9hIJaD3jbUHvcKd3PEoRDRckw6dZIq9T6HNg1m1g7RHeLs4KwZQf
         eU8dKtUPzYPtQKSE/TVXaTBbsWZ6AcICMLAnHGIRZk4QV8gpbUSkHSLyXYbtpc0rU7pE
         pefg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ij7yB6TXYinUQYDz8zgws9K8Xq/HluPklnNX4R9TZMAlHzCqO
	Om0sPY4Cg7093R+xe2oOhfE=
X-Google-Smtp-Source: ABdhPJxo1uvPNL8JG6k7Ki4c3AqKL6eBY2vfTUfIu0Yr0glVMH3N6IRtnBLPSfxkQ9n7XL7utl12TQ==
X-Received: by 2002:a05:6512:3047:b0:472:5e5f:e1c7 with SMTP id b7-20020a056512304700b004725e5fe1c7mr7334268lfb.554.1651528839056;
        Mon, 02 May 2022 15:00:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls2140652lfb.1.gmail; Mon, 02 May 2022
 15:00:38 -0700 (PDT)
X-Received: by 2002:a05:6512:131c:b0:44b:5b7:75bf with SMTP id x28-20020a056512131c00b0044b05b775bfmr9658998lfu.652.1651528837916;
        Mon, 02 May 2022 15:00:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651528837; cv=none;
        d=google.com; s=arc-20160816;
        b=w2TJngunLaiaGY9tAzrCvNfYAxJ6NLzg5JbbL+wbKbf7YmXwHt2RDy7KOoxxzEsmTC
         /sxiDtysL9DqYg00Zks+rxAVGB1urYdJXFTWh8iOfKKMB1ElF1+Gnm6k/4JU7xQBADIZ
         CsCm/9JJwrGFGX3TcP4Bd5SL+2lhrrmS+nu3ppf9D+c71czlDAA3nCaQvRJDyIuX0NR+
         8D0w079lZeQF6LHJJ4gU5yjfO7cJ2c22nAI7PWUJeu8dTVmdW2pqSBEn9hn2dSlwUGFg
         zP0Jm4a8mXD1hwvZwNuFbx7f8Bpe7rAHjmEcuNRPtxCmM3e2tPhi48XSiNosQZlJttcC
         vbNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=S+6N0/e64EIdyK+q6LMgUsbq+bhYAt3HjkhVHWMdsus=;
        b=xeDAT8zw6mxMsAUpY62xrkogZ8SgRiIJzJxEthOmGBbwwB3SRq3aQaM1Rp4BorkHPb
         tbZON7ItkGBU1IURCLU28lDs9XlTgAbQiNnFMNtPbEZlCxXpN9ayjNkxtY9VjlGbl+pK
         YTG2QXtxcEaiw5ZuiLUhUhCjHBNr9hh7VZajNYh3pw8K/dl0WlrpG01lsMg0gEV77gVn
         gfGU3XALVpNG3JW5xaVS/51ZkdpQ/GqMqTlap6lYOCyVCje+l7CD1EjeV/QHb3Eh+XFc
         26n/DOLsEQjXJUQXMqxQOyLoem8Zh1Bkqpl7qwTN9RfTE8kPnpKxwxVTAngsJYJ9gVS9
         Xt+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=J4ag3vPs;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id p9-20020a056512138900b0047208583d26si726240lfa.11.2022.05.02.15.00.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 May 2022 15:00:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton
 <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>,
 Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav
 Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik
 <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, Linux
 Memory Management List <linux-mm@kvack.org>, Linux-Arch
 <linux-arch@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
In-Reply-To: <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
References: <20220426164315.625149-1-glider@google.com>
 <20220426164315.625149-29-glider@google.com> <87a6c6y7mg.ffs@tglx>
 <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
Date: Tue, 03 May 2022 00:00:36 +0200
Message-ID: <87y1zjlhmj.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=J4ag3vPs;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

Alexander,

On Mon, May 02 2022 at 19:00, Alexander Potapenko wrote:
> On Wed, Apr 27, 2022 at 3:32 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>> > --- a/kernel/entry/common.c
>> > +++ b/kernel/entry/common.c
>> > @@ -23,7 +23,7 @@ static __always_inline void __enter_from_user_mode(struct pt_regs *regs)
>> >       CT_WARN_ON(ct_state() != CONTEXT_USER);
>> >       user_exit_irqoff();
>> >
>> > -     instrumentation_begin();
>> > +     instrumentation_begin_with_regs(regs);
>>
>> I can see what you are trying to do, but this will end up doing the same
>> thing over and over. Let's just look at a syscall.
>>
>> __visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)
>> {
>>         ...
>>         nr = syscall_enter_from_user_mode(regs, nr)
>>
>>                 __enter_from_user_mode(regs)
>>                         .....
>>                         instrumentation_begin_with_regs(regs);
>>                         ....
>>
>>                 instrumentation_begin_with_regs(regs);
>>                 ....
>>
>>         instrumentation_begin_with_regs(regs);
>>
>>         if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr != -1) {
>>                 /* Invalid system call, but still a system call. */
>>                 regs->ax = __x64_sys_ni_syscall(regs);
>>         }
>>
>>         instrumentation_end();
>>
>>         syscall_exit_to_user_mode(regs);
>>                 instrumentation_begin_with_regs(regs);
>>                 __syscall_exit_to_user_mode_work(regs);
>>         instrumentation_end();
>>         __exit_to_user_mode();
>>
>> That means you memset state four times and unpoison regs four times. I'm
>> not sure whether that's desired.
>
> Regarding the regs, you are right. It should be enough to unpoison the
> regs at idtentry prologue instead.
> I tried that initially, but IIRC it required patching each of the
> DEFINE_IDTENTRY_XXX macros, which already use instrumentation_begin().

Exactly 4 instances :)

> This decision can probably be revisited.

It has to be revisited because the whole thing is incomplete if this is
not addressed.

> As for the state, what we are doing here is still not enough, although
> it appears to work.
>
> Every time an instrumented function calls another function, it sets up
> the metadata for the function arguments in the per-task struct
> kmsan_context_state.
> Similarly, every instrumented function expects its caller to put the
> metadata into that structure.
> Now, if a non-instrumented function (e.g. every `noinstr` function)
> calls an instrumented one (which happens inside the
> instrumentation_begin()/instrumentation_end() region), nobody sets up
> the state for that instrumented function, so it may report false
> positives when accessing its arguments, if there are leftover poisoned
> values in the state.
>
> To overcome this problem, ideally we need to wipe kmsan_context_state
> every time a call from the non-instrumented function occurs.
> But this cannot be done automatically exactly because we cannot
> instrument the named function :)
>
> We therefore apply an approximation, wiping the state at the point of
> the first transition between instrumented and non-instrumented code.
> Because poison values are generally rare, and instrumented regions
> tend to be short, it is unlikely that further calls from the same
> non-instrumented function will result in false positives.
> Yet it is not completely impossible, so wiping the state for the
> second/third etc. time won't hurt.

Understood. But if I understand you correctly:

> Similarly, every instrumented function expects its caller to put the
> metadata into that structure.

then

     instrumentation_begin();
     foo(fargs...);
     bar(bargs...);
     instrumentation_end();

is a source of potential false positives because the state is not
guaranteed to be correct, neither for foo() nor for bar(), even if you
wipe the state in instrumentation_begin(), right?

This approximation approach smells fishy and it's inevitably going to be
a constant source of 'add yet another kmsan annotation/fixup' patches,
which I'm not interested in at all.

As this needs compiler support anyway, then why not doing the obvious:

#define noinstr                                 \
        .... __kmsan_conditional

#define instrumentation_begin()                 \
        ..... __kmsan_cond_begin

#define instrumentation_end()                   \
        __kmsan_cond_end .......

and let the compiler stick whatever is required into that code section
between instrumentation_begin() and instrumentation_end()?

That's not violating any of the noinstr constraints at all. In fact we
allow _any_ instrumentation to be placed between this two points. We
have tracepoints there today.

We could also allow breakpoints, kprobes or whatever, but handling this
at that granularity level for a production kernel is just overkill and
the code in those instrumentable sections is usually not that
interesting as it's mostly function calls.

But if the compiler converts

     instrumentation_begin();
     foo(fargs...);
     bar(bargs...);
     instrumentation_end();

to

     instrumentation_begin();
     kmsan_instr_begin_magic();
     kmsan_magic(fargs...);
     foo(fargs...);
     kmsan_magic(bargs...);
     bar(bargs...);
     kmsan_instr_end_magic();
     instrumentation_end();

for the kmsan case and leaves anything outside of these sections alone,
then you have:

   - a minimal code change
   - the best possible coverage
   - the least false positive crap to chase and annotate

IOW, a solution which is solid and future proof.

I'm all for making use of advanced instrumentation, validation and
debugging features, but this mindset of 'make the code comply to what
the tool of today provides' is fundamentally wrong. Tools have to
provide value to the programmer and not the other way round.

Yes, it's more work on the tooling side, but the tooling side is mostly
a one time effort while chasing the false positives is a long term
nightmare.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y1zjlhmj.ffs%40tglx.
