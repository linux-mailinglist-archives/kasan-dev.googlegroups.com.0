Return-Path: <kasan-dev+bncBAABBTH5YT4QKGQEAJPBJUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id C478D2405F6
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 14:34:21 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id d3sf2812217uav.6
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 05:34:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597062860; cv=pass;
        d=google.com; s=arc-20160816;
        b=AtNIHcLAVYM8u030jRZOUJiTq1c2EyvuUVFSot4jn/rMWXXPPyjJbkYx4PtL6Z3twW
         dozMKXXWBCbIQkpr7Rip8PWjmNE6FogvdRadL1YWFL3niMh/KPjUwhzk9d6d82Zgs/sj
         qfsj8Oc2b7pGGHy/2YJXqi/gxtI8Sxc4F+y+PQxOqYRix+dEjQTd1IfVDi8/NH6dcfBh
         4Yb7BTW7Xkv1/16jFvkctL9E/Enr6oV3LCE0IGIuxSQY2Jh7kImJe8FpEuqmVbZPhLyr
         M07B5kNWYfLfGy4gN8PRrTn50xNqcZkgkP3CfQYh9/o3E6aj6E5rI3rQ6XO+9wq8q45Z
         qn+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Ch1L0hrmk5c/Xa7ha8t7Bj0wAFr/dfp9zXpzr87aJF4=;
        b=i6McmI4lC55+IHTNEOYQTqJCMBdfwXmg/toIgeAkBwpQ6Elcr54ZZWh5CQB2hgHhtT
         qm9wBYh0dIFkj5sfaE0cZ6njntRbyx+Ej8T//W0ZoOk1qlGgDgv1mXDqMBKomRKRwJlp
         JEZoKmfGyVq8pIlCAk41V1m+izV87rdUa9W88InedgCk94/aWlR9voE0wtvHefB7rlMY
         KHpC2aVByvLE24aoyhpbeIMFjL6l6r9XzcH0FaJ8hNxYhTYJ+gDuV2UteqBZaoJc70FH
         uU6MSW25bBJ2l4j4CLSW6zcPYcP/nsMPd9rLFqSZhJvR5c0lUzdCAzTf807XcXkBZMlM
         w3MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DndfMPaB;
       spf=pass (google.com: domain of srs0=trrf=bu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=tRrf=BU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ch1L0hrmk5c/Xa7ha8t7Bj0wAFr/dfp9zXpzr87aJF4=;
        b=hfTi4UhmtT8kfniLZy9PemNB6q5NR71lqGlHBEyIMQRmv5BKaR3etPwaXQ/VjwROFF
         EnDNyjYG/jfbkF/WYE2NYnudlK7qoLlbL9CEoUvxeK1cFSA4+w0QqRHlIKVDNUj3e6Gi
         3/kVCQjiPbBRojSj9esqO1B+yYCGxcEU8GxJeg27q6qquJW9x827H2UuP5zV1qhL5aSA
         EE0Q5OMq/DcO7OTcK2ME7nA0naUwQ4fUiwFixpsqZ0j2veL72KPWWLTMsTNGS9VWl1h9
         w1Yt2AKa1oV77UllrPfg8WYuoZVbsO94bYHESkhErd0DUHqlTPwLNvgENtfpSumTtrA0
         3sUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ch1L0hrmk5c/Xa7ha8t7Bj0wAFr/dfp9zXpzr87aJF4=;
        b=XeV5AX5wRcBFegfqSdpkscpGGF/jkeyuF1cm38uHRhTAuUPkYPedzH7+/sm2vlaV33
         2QQCorEq1+1u661loDDUSz/w/Rmut3nq1SzFZxckrUekT+nZD1E8UZGEUlb0J1hKGB+P
         TI08wujFhlGut+mHBi0lfaAnXUs3ug4dllrmAg6ypzrNbjYBymqllVRsGOCYNj151zm/
         mjEPJ8czZQIVS/BjN3zxvKfhN+07pz48yERwhadJijgWzZ2o9bYh269Jozm99nyDb1Ot
         goxh5LO+bpgFcIvjbNUjuKoi9zIuM15mFFI9R5bwakoiDFMzUA8hDd/k9M2yzxeHUxH/
         TsOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ekfCyhIiuzjwhJPhtvzVXB3JDzDPH/exyzyfThFqSFIDSFqdL
	NIMxP3uTMvsQJxLpF2Kpk6w=
X-Google-Smtp-Source: ABdhPJxja64H7mYKnyqUWYJc+Vc41h7fLsB9dY6PiurjPwh018Zxp2WJ2loHcxnvTOeuuLz5NmUxbw==
X-Received: by 2002:a1f:1ecd:: with SMTP id e196mr19645718vke.61.1597062860614;
        Mon, 10 Aug 2020 05:34:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:5d84:: with SMTP id r126ls618847vkb.11.gmail; Mon, 10
 Aug 2020 05:34:20 -0700 (PDT)
X-Received: by 2002:a1f:eecb:: with SMTP id m194mr18994759vkh.40.1597062860241;
        Mon, 10 Aug 2020 05:34:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597062860; cv=none;
        d=google.com; s=arc-20160816;
        b=D6/y8S2jYiWgyf67n0qaTDBE6dVYvrqNHYif8IB4TmAHxwg05Qw9KQdw9OQCefIlPJ
         WVNekGrQ1RkHLndZ7gshcQ+VD9E5pBT8y0Cxvie/2khzWLP+8EXlqr2SWDtXZxi8n7Sy
         G5sNebAcNyve2ewfnBqXA1CR0DA1MEaPtn8LLZYCBsqQ17F9Fg4Gdh7CAL7O7EdhzkNY
         h49huMB41jW/MDSaRTMnif5kLIYPswmLGuaQBlgxDcZxsHerGV/Ng0cldA+bMu5V+QqZ
         ikwWA7hDyExIMZMJKiEmbZ4Dp+q3JobMMv9b/IiNKUMKG2Sj2iHVh2y4m3dWPCVIH7S2
         Fnrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=BiPMfIch3FyV72rV56ecSM89bv3vFt7E+LE7j8M7yyg=;
        b=Jw7AYZ81q1zWat30WsnXxTpWQg0YY3lItjaQLIp57oxlGsPUxy4fjXFzfo95ZWgapq
         Nzcxq1X0SwJ7PXeyuh/jG1cJewZdYYegyNT1wA0PWnpCsKt/8O2Vm9Hvxa6h4+uodJRa
         iP5OKPxaTeAjhiwhq9hQYlNeijrYekRBK2dgD5nOCN9943vWQoPGu1nYfhTD0MbN/BGH
         a99rYQNutVUPgEtPRKxRhhFgbDprQ62b6Nn37aYYWQ2GUduvSh2QObthbhRSZ+LpI3No
         xu3K8vq3R2Vkus8pLU0ijafs5fRUhH2y/+FtldCu09XIGPXy3Jogr0Z8C4j42De+u4IY
         ug6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DndfMPaB;
       spf=pass (google.com: domain of srs0=trrf=bu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=tRrf=BU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g19si543828uab.1.2020.08.10.05.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Aug 2020 05:34:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=trrf=bu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 14BBD2078D;
	Mon, 10 Aug 2020 12:34:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id DC4F435228C7; Mon, 10 Aug 2020 05:34:18 -0700 (PDT)
Date: Mon, 10 Aug 2020 05:34:18 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Subject: Re: [PATCH] kcsan: Treat runtime as NMI-like with interrupt tracing
Message-ID: <20200810123418.GH4295@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200807090031.3506555-1-elver@google.com>
 <20200807170618.GW4295@paulmck-ThinkPad-P72>
 <CANpmjNPqEeQvg53wJ5EsyfssSqyOqCsPG+YTV6ytj6wsc+5BPQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPqEeQvg53wJ5EsyfssSqyOqCsPG+YTV6ytj6wsc+5BPQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DndfMPaB;       spf=pass
 (google.com: domain of srs0=trrf=bu=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=tRrf=BU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Aug 10, 2020 at 10:07:44AM +0200, Marco Elver wrote:
> On Fri, 7 Aug 2020 at 19:06, Paul E. McKenney <paulmck@kernel.org> wrote:
> > On Fri, Aug 07, 2020 at 11:00:31AM +0200, Marco Elver wrote:
> > > Since KCSAN instrumentation is everywhere, we need to treat the hooks
> > > NMI-like for interrupt tracing. In order to present an as 'normal' as
> > > possible context to the code called by KCSAN when reporting errors, we
> > > need to update the IRQ-tracing state.
> > >
> > > Tested: Several runs through kcsan-test with different configuration
> > > (PROVE_LOCKING on/off), as well as hours of syzbot testing with the
> > > original config that caught the problem (without CONFIG_PARAVIRT=y,
> > > which appears to cause IRQ state tracking inconsistencies even when
> > > KCSAN remains off, see Link).
> > >
> > > Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
> > > Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> > > Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
> > > Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> 
> Peter, if you're fine with it, I think we'll require your
> Signed-off-by (since Co-developed-by).
> 
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > > Patch Note: This patch applies to latest mainline. While current
> > > mainline suffers from the above problem, the configs required to hit the
> > > issue are likely not enabled too often (of course with PROVE_LOCKING on;
> > > we hit it on syzbot though). It'll probably be wise to queue this as
> > > normal on -rcu, just in case something is still off, given the
> > > non-trivial nature of the issue. (If it should instead go to mainline
> > > right now as a fix, I'd like some more test time on syzbot.)
> >
> > The usual, please let me know when/if you would like me to apply
> > to -rcu.  And have a great weekend!
> 
> I think we need to wait until you have rebased -rcu to 5.9-rc1 some
> time next week. I will send a reminder after, and if it doesn't apply
> cleanly, I'll send a rebased patch.

Sounds good, thank you!

							Thanx, Paul

> Thank you!
> 
> -- Marco
> 
> >                                                 Thanx, Paul
> >
> > > ---
> > >  kernel/kcsan/core.c  | 79 ++++++++++++++++++++++++++++++++++----------
> > >  kernel/kcsan/kcsan.h |  3 +-
> > >  2 files changed, 62 insertions(+), 20 deletions(-)
> > >
> > > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > > index 9147ff6a12e5..6202a645f1e2 100644
> > > --- a/kernel/kcsan/core.c
> > > +++ b/kernel/kcsan/core.c
> > > @@ -291,13 +291,28 @@ static inline unsigned int get_delay(void)
> > >                               0);
> > >  }
> > >
> > > -void kcsan_save_irqtrace(struct task_struct *task)
> > > -{
> > > +/*
> > > + * KCSAN instrumentation is everywhere, which means we must treat the hooks
> > > + * NMI-like for interrupt tracing. In order to present a 'normal' as possible
> > > + * context to the code called by KCSAN when reporting errors we need to update
> > > + * the IRQ-tracing state.
> > > + *
> > > + * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
> > > + * runtime is entered for every memory access, and potentially useful
> > > + * information is lost if dirtied by KCSAN.
> > > + */
> > > +
> > > +struct kcsan_irq_state {
> > > +     unsigned long           flags;
> > >  #ifdef CONFIG_TRACE_IRQFLAGS
> > > -     task->kcsan_save_irqtrace = task->irqtrace;
> > > +     int                     hardirqs_enabled;
> > >  #endif
> > > -}
> > > +};
> > >
> > > +/*
> > > + * This is also called by the reporting task for the other task, to generate the
> > > + * right report with CONFIG_KCSAN_VERBOSE. No harm in restoring more than once.
> > > + */
> > >  void kcsan_restore_irqtrace(struct task_struct *task)
> > >  {
> > >  #ifdef CONFIG_TRACE_IRQFLAGS
> > > @@ -305,6 +320,41 @@ void kcsan_restore_irqtrace(struct task_struct *task)
> > >  #endif
> > >  }
> > >
> > > +/*
> > > + * Saves/restores IRQ state (see comment above). Need noinline to work around
> > > + * unfortunate code-gen upon inlining, resulting in objtool getting confused as
> > > + * well as losing stack trace information.
> > > + */
> > > +static noinline void kcsan_irq_save(struct kcsan_irq_state *irq_state)
> > > +{
> > > +#ifdef CONFIG_TRACE_IRQFLAGS
> > > +     current->kcsan_save_irqtrace = current->irqtrace;
> > > +     irq_state->hardirqs_enabled = lockdep_hardirqs_enabled();
> > > +#endif
> > > +     if (!kcsan_interrupt_watcher) {
> > > +             kcsan_disable_current(); /* Lockdep might WARN, etc. */
> > > +             raw_local_irq_save(irq_state->flags);
> > > +             lockdep_hardirqs_off(_RET_IP_);
> > > +             kcsan_enable_current();
> > > +     }
> > > +}
> > > +
> > > +static noinline void kcsan_irq_restore(struct kcsan_irq_state *irq_state)
> > > +{
> > > +     if (!kcsan_interrupt_watcher) {
> > > +             kcsan_disable_current(); /* Lockdep might WARN, etc. */
> > > +#ifdef CONFIG_TRACE_IRQFLAGS
> > > +             if (irq_state->hardirqs_enabled) {
> > > +                     lockdep_hardirqs_on_prepare(_RET_IP_);
> > > +                     lockdep_hardirqs_on(_RET_IP_);
> > > +             }
> > > +#endif
> > > +             raw_local_irq_restore(irq_state->flags);
> > > +             kcsan_enable_current();
> > > +     }
> > > +     kcsan_restore_irqtrace(current);
> > > +}
> > > +
> > >  /*
> > >   * Pull everything together: check_access() below contains the performance
> > >   * critical operations; the fast-path (including check_access) functions should
> > > @@ -350,11 +400,13 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
> > >       flags = user_access_save();
> > >
> > >       if (consumed) {
> > > -             kcsan_save_irqtrace(current);
> > > +             struct kcsan_irq_state irqstate;
> > > +
> > > +             kcsan_irq_save(&irqstate);
> > >               kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
> > >                            KCSAN_REPORT_CONSUMED_WATCHPOINT,
> > >                            watchpoint - watchpoints);
> > > -             kcsan_restore_irqtrace(current);
> > > +             kcsan_irq_restore(&irqstate);
> > >       } else {
> > >               /*
> > >                * The other thread may not print any diagnostics, as it has
> > > @@ -387,7 +439,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > >       unsigned long access_mask;
> > >       enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
> > >       unsigned long ua_flags = user_access_save();
> > > -     unsigned long irq_flags = 0;
> > > +     struct kcsan_irq_state irqstate;
> > >
> > >       /*
> > >        * Always reset kcsan_skip counter in slow-path to avoid underflow; see
> > > @@ -412,14 +464,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > >               goto out;
> > >       }
> > >
> > > -     /*
> > > -      * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
> > > -      * runtime is entered for every memory access, and potentially useful
> > > -      * information is lost if dirtied by KCSAN.
> > > -      */
> > > -     kcsan_save_irqtrace(current);
> > > -     if (!kcsan_interrupt_watcher)
> > > -             local_irq_save(irq_flags);
> > > +     kcsan_irq_save(&irqstate);
> > >
> > >       watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> > >       if (watchpoint == NULL) {
> > > @@ -559,9 +604,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > >       remove_watchpoint(watchpoint);
> > >       kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
> > >  out_unlock:
> > > -     if (!kcsan_interrupt_watcher)
> > > -             local_irq_restore(irq_flags);
> > > -     kcsan_restore_irqtrace(current);
> > > +     kcsan_irq_restore(&irqstate);
> > >  out:
> > >       user_access_restore(ua_flags);
> > >  }
> > > diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> > > index 29480010dc30..6eb35a9514d8 100644
> > > --- a/kernel/kcsan/kcsan.h
> > > +++ b/kernel/kcsan/kcsan.h
> > > @@ -24,9 +24,8 @@ extern unsigned int kcsan_udelay_interrupt;
> > >  extern bool kcsan_enabled;
> > >
> > >  /*
> > > - * Save/restore IRQ flags state trace dirtied by KCSAN.
> > > + * Restore IRQ flags state trace dirtied by KCSAN.
> > >   */
> > > -void kcsan_save_irqtrace(struct task_struct *task);
> > >  void kcsan_restore_irqtrace(struct task_struct *task);
> > >
> > >  /*
> > > --
> > > 2.28.0.236.gb10cc79966-goog
> > >
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200807170618.GW4295%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810123418.GH4295%40paulmck-ThinkPad-P72.
