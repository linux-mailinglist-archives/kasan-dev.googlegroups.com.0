Return-Path: <kasan-dev+bncBDAMN6NI5EERBSWX2WJQMGQEGIVYDOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FC8B51DF36
	for <lists+kasan-dev@lfdr.de>; Fri,  6 May 2022 20:41:15 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id s24-20020a05640217d800b00425e19e7deasf4424748edy.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 May 2022 11:41:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651862475; cv=pass;
        d=google.com; s=arc-20160816;
        b=fKsiyYLO9ugJ742mlAzuyUByLxLJ0RTn824kyMT2/FvInQg8t2ftTzVoEVZXDNFHkd
         EEi0yODCaT+A94qtNQ03fOBFGOkNQ/+lkgXfkNig4QSnzLnasRwLNYZdJAo/02P+qXd5
         JWcUlfxfFJrujrQ+gSwnapur4fTX5XUzt3FpvnAUNuJIxaBPFDC1qmnxLalgibAy94pu
         IvbmTwG1qoeZx5f3o7MQEaFk5no1ZYEtrd0t5doRZKd/mpRx8NvmFDEHjTlIyG1hhwrH
         cHAH1kndL9s3JWy/sRxiVMtW68ow4BRbUAwqZanod+/DAJvIOVSnJ6bKdS+HRMHcNxg/
         lOVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=eNvCQXj/Yis6QfkCRISn0lCyjFd1ibb2i5VphUZCSxQ=;
        b=p4QRDeu9HZXYZYCT/W6gKuohg0gMZB7HCrdAVq3G+WqtJEVO9a/wbEBXuxnCUrVETX
         1DEZOwX9wxw7D5+wUAmeh6Vc7cOa8VMYhOBCCY/DegvqNQtqIMKg9YEhw9pFDpcFrfbj
         neGUF3aV6BoktbzH7TuSCxTlzOI520q2obsfiAHsLG6Yxs0wlwmC22FCHqYm3z4pPndw
         IXADu9K/bfL7SCL53xRRcffBe9/TTAgHxwbEJ+UpLxXu6P+0y8K93eTnb2EdBG3IdqNv
         XDPqsyw08pOSwkyWN7S1Yh9b+y6m6u/0R6pD2ANyenHMOPKk+ZsVS6Xq/SaNHBSHY0EG
         emdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="toC9h/bB";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=8YaG10zQ;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eNvCQXj/Yis6QfkCRISn0lCyjFd1ibb2i5VphUZCSxQ=;
        b=YNLoCmrhig5CpY2PsquG9MzhIyvGrjZptCiRYRCJKDau9+ZfWmubQ3o9nt6GyNVk0p
         9BvZabtkB8QP/5eZEo5cTxBClzTwhHOV0gluG0WEwfk1YsbpoOJE/vSXv5qpqXiJc5AH
         gxorAd3YI66O0bAQ9z/1ZdYypGuaZ252Oe+3i4HLPIaDsmIx4kA23S80+NjH4fwj3Csq
         0k/5b9XfOa/+SENEO4+lU/bqNHA4OEOPs8eVgw9zCYgW0YrvFkfZFiKBhx7WiJZDmbzC
         2n6JGMBXtx/fIILALL2/zi7zJ62yCN4D3qvEaOAKPLBfKV3DqG9bRKtXZNEXOoRWifPX
         Nu7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eNvCQXj/Yis6QfkCRISn0lCyjFd1ibb2i5VphUZCSxQ=;
        b=5twgHVct/Wr3Zpe+nH0RpXj+WxI/FejPXqEDrih4Xt6AwDmnl5ecMGfvpOXB5hppkf
         M/WKnpUwoPBxH3LeqP8YP5/pw4fEMaT+EY4Vj5XTcC0uHzbsZEXK0jaTZdv171njEjwi
         W7EJKXKOB6j1isK5iQW/Xfj4ltk91rGmiaJ0A3rxTO273D2zmi7g2tbTEL1KsBYif2BQ
         +25ayajnIhmVPZbnDwSDsABgvjDleeTGva+PB4qNYN2Tdt1BdiChlnZUiNUKpzFit/af
         eNzMxHHgxqYA13PVf0Yw9g8rrqPFdNtmAdNcqTfonTD3JtyY4zPQ1zalH6z+NqYOdjQV
         q0WQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VcGz6B5IfN6xKtB06A5aVOoWJ58vqs0JkfIr5u+twSm0rdVI0
	ZBQPGwRYo9SOYLHHuwN+3MM=
X-Google-Smtp-Source: ABdhPJx3QMZJgIKLH3WNrI+qwoG8z+AGylKTvv6CJbk8lQj+0/kccQoMU3W6KBs+jZQqWayWb33/GQ==
X-Received: by 2002:a17:906:4fc4:b0:6da:b4c6:fadb with SMTP id i4-20020a1709064fc400b006dab4c6fadbmr4331320ejw.282.1651862475134;
        Fri, 06 May 2022 11:41:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:628e:b0:6e8:76c2:5876 with SMTP id
 nd14-20020a170907628e00b006e876c25876ls542320ejc.7.gmail; Fri, 06 May 2022
 11:41:14 -0700 (PDT)
X-Received: by 2002:a17:907:3e8c:b0:6f4:4fdb:6f24 with SMTP id hs12-20020a1709073e8c00b006f44fdb6f24mr4246362ejc.44.1651862462979;
        Fri, 06 May 2022 11:41:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651862462; cv=none;
        d=google.com; s=arc-20160816;
        b=BkRm+2XzJARtXGNrnIQrmXN9NJ0LauCMz7h7Wl8eVxWdCuPIHTrpDX9g9LDY5/SSA9
         13U5+zeT/keHlnZmdCWEJm98UnF7Ygwz/4J6qFxoYf49OTvB55y7gB/DgcdKZOk98LWt
         bCNAKUx4kAZmWrnuetUUzK3k8QM8MNfh/vwIEaxJ+F+wY4lLN6aKifpNe2LQ1BMltTvp
         nZtMBnMHJYpFwiGq37BeJH/Bv7nof4A/kXH8WpqHS3OdqbhFxea7e4+UL2BSRNXDaRn1
         rvIZwLH3SmKzfiF06s5mMYRuecvDBJHaJ9vDwyLkrx3DKPsKDTe1pa/Rwe1JBvZcc6jq
         KlaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=dbruHfD7L5ui13yo40XACqjP4QTu0Yh5HyGtytqH9h0=;
        b=SnCh6JOQ5dmaAEjkD1dNpdalXcD3Ay7COAATzQJeu7+oXjTx9iF4iIhMbyETVuNjT6
         SayJSquEHYBA9DJlDLVNKes1vRVgpTUH4K3S9iP6wy5QPPXFhX2KifU1jlkUbzBqXGXh
         X3lu+EfZfE/Q6x6lCy3In3BzF/eEi6OdlGZj84MuuvMGZ+njjqfgEuWvQwy80oS1B8FN
         nSaCb88HrvY4wNcGi5789TUAn1K4QyrY6XDw04H43YzjwGe4lvZruJa+18DiHpP/mBZN
         fbAagRI98wpSYVDbeLht3z2zZNKR0VQl/wQh49lVuCJQK3q1OUN0ZfOOIMihAHFmnVmB
         bL+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="toC9h/bB";
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=8YaG10zQ;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id v8-20020aa7d648000000b00425adbac75dsi325845edr.2.2022.05.06.11.41.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 May 2022 11:41:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
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
In-Reply-To: <CAG_fn=UpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D+4Pttc9dA@mail.gmail.com>
References: <20220426164315.625149-1-glider@google.com>
 <20220426164315.625149-29-glider@google.com> <87a6c6y7mg.ffs@tglx>
 <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx>
 <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx>
 <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
 <87k0ayhc43.ffs@tglx>
 <CAG_fn=UpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D+4Pttc9dA@mail.gmail.com>
Date: Fri, 06 May 2022 20:41:01 +0200
Message-ID: <87h762h5c2.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="toC9h/bB";       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=8YaG10zQ;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Fri, May 06 2022 at 19:41, Alexander Potapenko wrote:
> On Fri, May 6, 2022 at 6:14 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>> sysvec_apic_timer_interrupt() invokes irqentry_enter() _before_
>> set_irq_regs() and irqentry_enter() unpoisons @reg.
>>
>> Confused...
>
> As far as I can tell in this case sysvect_apic_timer_interrupt() is
> called by the following code in arch/x86/kernel/idt.c:
>
>   INTG(LOCAL_TIMER_VECTOR,                asm_sysvec_apic_timer_interrupt),
>
> , which does not use IDTENTRY_SYSVEC framework and thus does not call
> irqentry_enter().

  asm_sysvec_apic_timer_interrupt != sysvec_apic_timer_interrupt

arch/x86/kernel/apic/apic.c:
DEFINE_IDTENTRY_SYSVEC(sysvec_apic_timer_interrupt)
{
        ....

#define DEFINE_IDTENTRY_SYSVEC(func)					\
static void __##func(struct pt_regs *regs);				\
									\
__visible noinstr void func(struct pt_regs *regs)			\
{									\
	irqentry_state_t state = irqentry_enter(regs);			\
        ....
	__##func (regs);						\
        ....
}                                                                       \
		                                                        \
static noinline void __##func(struct pt_regs *regs)

So it goes through that code path _before_ the actual implementation
which does set_irq_regs() is reached.

The callchain is:

  asm_sysvec_apic_timer_interrupt               <- ASM entry in gate
     sysvec_apic_timer_interrupt(regs)          <- noinstr C entry point
        irqentry_enter(regs)                    <- unpoisons @reg
        __sysvec_apic_timer_interrupt(regs)     <- the actual handler
           set_irq_regs(regs)                   <- stores regs
           local_apic_timer_interrupt()
             ...
             tick_handler()                     <- One of the 4 variants
                regs = get_irq_regs();          <- retrieves regs
                update_process_times(user_tick = user_mode(regs))
                   account_process_tick(user_tick)
                      irqtime_account_process_tick(user_tick)
line 382:                } else if { user_tick }   <- KMSAN complains

I'm even more confused now.

> I guess handling those will require wrapping every interrupt gate into
> a function that performs register unpoisoning?

No, guessing does not help here.

The gates point to the ASM entry point, which then invokes the C entry
point. All C entry points use a DEFINE_IDTENTRY variant.

Some of the DEFINE_IDTENTRY_* C entry points are not doing anything in
the macro, but the C function either invokes irqentry_enter() or
irqentry_nmi_enter() open coded _before_ invoking any instrumentable
function. So the unpoisoning of @regs in these functions should tell
KMSAN that @regs or something derived from @regs are not some random
uninitialized values.

There should be no difference between unpoisoning @regs in
irqentry_enter() or in set_irq_regs(), right?

If so, then the problem is definitely _not_ the idt entry code.

> By the way, if it helps, I think we don't necessarily have to call
> kmsan_unpoison_memory() from within the
> instrumentation_begin()/instrumentation_end() region?
> We could move the call to the beginning of irqentry_enter(), removing
> unnecessary duplication.

We could, but then you need to mark unpoison_memory() noinstr too and you
have to add the unpoison into the syscall code. No win and irrelevant to
the problem at hand.

Thanks,

        tglx


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h762h5c2.ffs%40tglx.
