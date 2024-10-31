Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAOWRS4QMGQEJ5ITGJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id EB4139B74DB
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 08:00:19 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-7ee22af5bb7sf477860a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 00:00:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730358018; cv=pass;
        d=google.com; s=arc-20240605;
        b=ihrp3v+08X6JbTaNG6pYbMsjGZ8r6YUobXuP/0X+FTEw+6qy7zX2D4/DI+NNEL5Reo
         vWI9rAl7VdRkmPqa3DX7x4ksXuBkUfsUjIfOhgxUS5ou3ICfhkqx8t9u2uzvTqv7/VPv
         9zoovOpZWGJFZttOcbNYrppFmRCk5glnHzxNBP0zNKuSBSMY6FZOpWMeh8i9ITavXQaI
         DEyWtkOws7XpxYcPUS5LWVdfTc6MTac+XMUVo27L2/CGa8hu6eyQvrQ6qqZMDpUagUyt
         +fjpI04kbx29sreJNMii6HrtvNHYXKOUncmh77gm3lfsu57XJtJvtrxrkCcJDwxUedb7
         taDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jgnolDsZ7ZdKi7iOoiDsjpXXqgr2MpAw/OUqOoh1JPM=;
        fh=M8hUkjcy+MrO3rMWnsjyIQheNfAfsnGvBzlE3fvhUgE=;
        b=X148owl8euxE8uPpVBichBa7cdSaeRIIa0OBWija1UWPJua6t7pq0tZqM4oPKCb8Nm
         1621iR9nCMbw/f+QwyJ/Mgqu1D71mklACRGY88VhlhQvus7hFBalymbnE+zn7Iqh+SnF
         y8Tr0lMYR442iCCGd366z01VWm1uYkFfj3GRLsHCIgWV/28OeWJgGRfVEA+ZKXt/WAwI
         rHwLZYRWmttn4q/uGtOyk/euvzChRKyks+/YUVH0flTYdzoCFA7tXAnvOHTnxDYLKyln
         wY3JlaSrMmOlTUIenazCFEU7eqTtbZgaa7nJqsmAPQp1mIPiMagNrTlIcWo2YFd1+FPB
         LAcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y78X6WsQ;
       spf=pass (google.com: domain of elver@google.com designates 2001:4860:4864:20::2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730358018; x=1730962818; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jgnolDsZ7ZdKi7iOoiDsjpXXqgr2MpAw/OUqOoh1JPM=;
        b=ANq23MpZ3iDr26CQcp6GBpwa9xjvuYmuzdu6cHWJhrwQM6HcbWGAHOGtkRUu/ZmA7D
         qNmhogRFKQg9J9n5se5gNAyueB/AMUxNFXqbXdQE9Na2Mkhg1U0ObyVkhhsmeXnX/7D+
         ES+NF6nxsnZDDsESBLOKR0XCSQbqqt8oN/ZzQUD9VaWV4E0uMkGF7oeoFB7PXKoKDZYs
         XZyIyw6437XxzLT8ot2Mw4sEWnQqlSYyRT0W/ggt9LW6baPv1fqnF3fkivECndZkw1g/
         tQEO3x8la3QYiEZXTsBu3U9V3Lzc2M7h4vaeIu1hMrk3UhynlXN86QMhDrIMOaLcBriU
         IYxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730358018; x=1730962818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jgnolDsZ7ZdKi7iOoiDsjpXXqgr2MpAw/OUqOoh1JPM=;
        b=FSwh/KdvOV+C0yeVZ+uAlcqJuRniCue3vlmRlEew2XvdVzxtOcdbmlQHHphEOwVU0A
         MdWy0/OprLXp+JFFWTx2mNUH0jH4jXVf3G09WVazYHvX8LwmWfdA4N86QATzbw4KXtcH
         Q8D4Od2TBlBQ2uuZtjm5CIUVI3Ez147/NnkKtFBvztqpW6fiigM7QIZrQ2uOLhpJpJHT
         Ohnm2mzt2UIVbkdSAlu0iQw5B5pblFw45+5H3vpze2fG0xstj4Isama3sciGRV44GUqe
         MGLM+icPe7Jo887gYnR8/hSUQuZCANM868m/lbBTL7hPWPbiRS8O5+De8OdCwMCXo82D
         UuJg==
X-Forwarded-Encrypted: i=2; AJvYcCVdgK4MNpAAFeQ3UL59KgrxtywICh0Y0EiDYrK5vCoE+sVF6N+SqqB1qFnYdhalNZpDNgmLgw==@lfdr.de
X-Gm-Message-State: AOJu0Yxk5D9YveZHQI9UeMQaLNXe2WZimLu48R2WEmOVElmAOZ5PvJnU
	XYjy8lvNTPEhAr2wdQ7J2Dqm137wk+QWiVEtKt/tWsZE4Gt/QK3y
X-Google-Smtp-Source: AGHT+IEWp+VWV3/2YeXiQuSoyBOqk6kqIqPLGYzht5Ei1L8ciSFBathAbKX8x+FQfR4C19OBmUDfDg==
X-Received: by 2002:a17:902:e552:b0:20c:853a:52a7 with SMTP id d9443c01a7336-210c6c31d52mr241758405ad.36.1730358017903;
        Thu, 31 Oct 2024 00:00:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:34ce:b0:205:8948:3577 with SMTP id
 d9443c01a7336-21103868656ls4074745ad.1.-pod-prod-04-us; Thu, 31 Oct 2024
 00:00:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWckVGEf40D04IjU6fqO6E25j+3RlcfxxBstvOGdHB6gcaUpcs1M3001/fDSbfHzr6/B1vhR7CYn9A=@googlegroups.com
X-Received: by 2002:a17:902:ea08:b0:20e:71ee:568e with SMTP id d9443c01a7336-210c68d336dmr257176085ad.13.1730358016288;
        Thu, 31 Oct 2024 00:00:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730358016; cv=none;
        d=google.com; s=arc-20240605;
        b=CDzOew1ZYWCoKQ56IbX6V7OGDCMItxkrsPmaFyE48yKVNjwEBlCHOf+pKNQP3nI2oU
         OBOHfsigce8kq61TTU5ia77YNeeJ8TWphTPDuQbDbApcRwT19CMn/eBk9jdPgyedfuzO
         ImTi30FPrhVhgJiA7KQKKNMIRxQMzYnLNWiXy/sB73+J2UfG7E2f3RVBP+JNFKCgkUZ2
         jiWU3w6oEGBWyWHYkZKZIAIJXaRMfVYd2A7VUSEnmzK+AHIVYWXBZPzwF0DDdNLucuV5
         0X22osi98dhy7HopD/ijm2gtLxJN1lq12pJx5b3HvClLQ33/I3E9wccJBDb2OCeVnY+T
         jIOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sppGUZRH/VIPn+CbB520cu48wmx8heQ3RHF4CC/cpsk=;
        fh=lKRLFQakOrJ+boDSpAqJLSfREZGcoG1f0aXk9zp5QHc=;
        b=F6Smg4s90WMR/Nj4BrOA86NIusQdVsCJJmegFLlvHURS4tW4tCBybcGzLFdvHHa4DN
         JOl0kcTHCn/Cw+kG2V+42mT2+AXXb7v7srGDenx6TLdn76iKir0aICJdZiDJD8J+OfEN
         5EQmLBoCiuUhbXf6aK/X3vlyiwfLazjlSYFPHCEFQZxgG9kMKUhzxDTnL4dYrdjZzAi1
         6CxfUBCOujPIp0+MLZrVmzm3f0gOJa/M4wx4wOcA5vl3X4zFbxAv3VqxqIIGps33oQSs
         7e11I9fHdepSAVQShbmEQGDseX48rJxeDxSSsT9GiybZYVg1bBizLliCZkDvFnRfOaXL
         Z9Uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y78X6WsQ;
       spf=pass (google.com: domain of elver@google.com designates 2001:4860:4864:20::2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oa1-x2e.google.com (mail-oa1-x2e.google.com. [2001:4860:4864:20::2e])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-211057cc6fbsi377115ad.11.2024.10.31.00.00.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Oct 2024 00:00:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2001:4860:4864:20::2e as permitted sender) client-ip=2001:4860:4864:20::2e;
Received: by mail-oa1-x2e.google.com with SMTP id 586e51a60fabf-290c69be014so324576fac.3
        for <kasan-dev@googlegroups.com>; Thu, 31 Oct 2024 00:00:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVi+jgNaMs9bBvfSZo0/s0GrakyTD/HlemuYf5DdASKX6P6X4K5xwWvRxb34LG/T0jRNZjhEhisKW4=@googlegroups.com
X-Received: by 2002:a05:6870:b522:b0:261:86d:89e2 with SMTP id
 586e51a60fabf-29051d49278mr15266657fac.36.1730358015264; Thu, 31 Oct 2024
 00:00:15 -0700 (PDT)
MIME-Version: 1.0
References: <20241029083658.1096492-1-elver@google.com> <20241029114937.GT14555@noisy.programming.kicks-ass.net>
 <CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q@mail.gmail.com>
 <20241029134641.GR9767@noisy.programming.kicks-ass.net> <ZyFKUU1LpFfLrVXb@elver.google.com>
 <20241030204815.GQ14555@noisy.programming.kicks-ass.net>
In-Reply-To: <20241030204815.GQ14555@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 31 Oct 2024 08:00:00 +0100
Message-ID: <CANpmjNNsDG7J=ZsuA40opV1b3xKMF0P8P3yCsufowJCRegGa7w@mail.gmail.com>
Subject: Re: [PATCH] kcsan, seqlock: Support seqcount_latch_t
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, 
	Boqun Feng <boqun.feng@gmail.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Mark Rutland <mark.rutland@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=y78X6WsQ;       spf=pass
 (google.com: domain of elver@google.com designates 2001:4860:4864:20::2e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 30 Oct 2024 at 21:48, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Oct 29, 2024 at 09:49:21PM +0100, Marco Elver wrote:
>
> > Something like this?
> >
> > ------ >8 ------
> >
> > Author: Marco Elver <elver@google.com>
> > Date:   Tue Oct 29 21:16:21 2024 +0100
> >
> >     time/sched_clock: Swap update_clock_read_data() latch writes
> >
> >     Swap the writes to the odd and even copies to make the writer critical
> >     section look like all other seqcount_latch writers.
> >
> >     With that, we can also add the raw_write_seqcount_latch_end() to clearly
> >     denote the end of the writer section.
> >
> >     Signed-off-by: Marco Elver <elver@google.com>
> >
> > diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
> > index 68d6c1190ac7..311c90a0e86e 100644
> > --- a/kernel/time/sched_clock.c
> > +++ b/kernel/time/sched_clock.c
> > @@ -119,9 +119,6 @@ unsigned long long notrace sched_clock(void)
> >   */
> >  static void update_clock_read_data(struct clock_read_data *rd)
> >  {
> > -     /* update the backup (odd) copy with the new data */
> > -     cd.read_data[1] = *rd;
> > -
> >       /* steer readers towards the odd copy */
> >       raw_write_seqcount_latch(&cd.seq);
> >
> > @@ -130,6 +127,11 @@ static void update_clock_read_data(struct clock_read_data *rd)
> >
> >       /* switch readers back to the even copy */
> >       raw_write_seqcount_latch(&cd.seq);
> > +
> > +     /* update the backup (odd) copy with the new data */
> > +     cd.read_data[1] = *rd;
> > +
> > +     raw_write_seqcount_latch_end(&cd.seq);
> >  }
> >
> >  /*
>
> That looks about right :-)
>
> > ------ >8 ------
> >
> > I also noticed your d16317de9b41 ("seqlock/latch: Provide
> > raw_read_seqcount_latch_retry()") to get rid of explicit instrumentation
> > in noinstr.
> >
> > Not sure how to resolve that. We have that objtool support to erase
> > calls in noinstr code (is_profiling_func), but that's x86 only.
> >
> > I could also make kcsan_atomic_next(0) noinstr compatible by checking if
> > the ret IP is in noinstr, and immediately return if it is.
> >
> > Preferences?
>
> Something like this perhaps?

Looks good.

Let me try to assemble the pieces into a patch. (Your SOB will be
needed - either now or later.)

Thanks,
-- Marco

> ---
>  arch/x86/kernel/tsc.c        |  5 +++--
>  include/linux/rbtree_latch.h | 14 ++++++++------
>  include/linux/seqlock.h      | 31 ++++++++++++++++++++++++++++++-
>  kernel/printk/printk.c       |  9 +++++----
>  kernel/time/sched_clock.c    | 20 ++++++++++++--------
>  kernel/time/timekeeping.c    | 10 ++++++----
>  6 files changed, 64 insertions(+), 25 deletions(-)
>
> diff --git a/arch/x86/kernel/tsc.c b/arch/x86/kernel/tsc.c
> index dfe6847fd99e..67aeaba4ba9c 100644
> --- a/arch/x86/kernel/tsc.c
> +++ b/arch/x86/kernel/tsc.c
> @@ -174,10 +174,11 @@ static void __set_cyc2ns_scale(unsigned long khz, int cpu, unsigned long long ts
>
>         c2n = per_cpu_ptr(&cyc2ns, cpu);
>
> -       raw_write_seqcount_latch(&c2n->seq);
> +       write_seqcount_latch_begin(&c2n->seq);
>         c2n->data[0] = data;
> -       raw_write_seqcount_latch(&c2n->seq);
> +       write_seqcount_latch(&c2n->seq);
>         c2n->data[1] = data;
> +       write_seqcount_latch_end(&c2n->seq);
>  }
>
>  static void set_cyc2ns_scale(unsigned long khz, int cpu, unsigned long long tsc_now)
> diff --git a/include/linux/rbtree_latch.h b/include/linux/rbtree_latch.h
> index 6a0999c26c7c..bc992c61b7ce 100644
> --- a/include/linux/rbtree_latch.h
> +++ b/include/linux/rbtree_latch.h
> @@ -145,10 +145,11 @@ latch_tree_insert(struct latch_tree_node *node,
>                   struct latch_tree_root *root,
>                   const struct latch_tree_ops *ops)
>  {
> -       raw_write_seqcount_latch(&root->seq);
> +       write_seqcount_latch_begin(&root->seq);
>         __lt_insert(node, root, 0, ops->less);
> -       raw_write_seqcount_latch(&root->seq);
> +       write_seqcount_latch(&root->seq);
>         __lt_insert(node, root, 1, ops->less);
> +       write_seqcount_latch_end(&root->seq);
>  }
>
>  /**
> @@ -172,10 +173,11 @@ latch_tree_erase(struct latch_tree_node *node,
>                  struct latch_tree_root *root,
>                  const struct latch_tree_ops *ops)
>  {
> -       raw_write_seqcount_latch(&root->seq);
> +       write_seqcount_latch_begin(&root->seq);
>         __lt_erase(node, root, 0);
> -       raw_write_seqcount_latch(&root->seq);
> +       write_seqcount_latch(&root->seq);
>         __lt_erase(node, root, 1);
> +       write_seqcount_latch_end(&root->seq);
>  }
>
>  /**
> @@ -204,9 +206,9 @@ latch_tree_find(void *key, struct latch_tree_root *root,
>         unsigned int seq;
>
>         do {
> -               seq = raw_read_seqcount_latch(&root->seq);
> +               seq = read_seqcount_latch(&root->seq);
>                 node = __lt_find(key, root, seq & 1, ops->comp);
> -       } while (raw_read_seqcount_latch_retry(&root->seq, seq));
> +       } while (read_seqcount_latch_retry(&root->seq, seq));
>
>         return node;
>  }
> diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> index fffeb754880f..9c2751087185 100644
> --- a/include/linux/seqlock.h
> +++ b/include/linux/seqlock.h
> @@ -621,6 +621,12 @@ static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *
>         return READ_ONCE(s->seqcount.sequence);
>  }
>
> +static __always_inline unsigned read_seqcount_latch(const seqcount_latch_t *s)
> +{
> +       kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
> +       return raw_read_seqcount_latch(s);
> +}
> +
>  /**
>   * raw_read_seqcount_latch_retry() - end a seqcount_latch_t read section
>   * @s:         Pointer to seqcount_latch_t
> @@ -635,6 +641,13 @@ raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
>         return unlikely(READ_ONCE(s->seqcount.sequence) != start);
>  }
>
> +static __always_inline int
> +read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
> +{
> +       kcsan_atomic_next(0);
> +       return raw_read_seqcount_latch_retry(s, start);
> +}
> +
>  /**
>   * raw_write_seqcount_latch() - redirect latch readers to even/odd copy
>   * @s: Pointer to seqcount_latch_t
> @@ -716,13 +729,29 @@ raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
>   *     When data is a dynamic data structure; one should use regular RCU
>   *     patterns to manage the lifetimes of the objects within.
>   */
> -static inline void raw_write_seqcount_latch(seqcount_latch_t *s)
> +static __always_inline void raw_write_seqcount_latch(seqcount_latch_t *s)
>  {
>         smp_wmb();      /* prior stores before incrementing "sequence" */
>         s->seqcount.sequence++;
>         smp_wmb();      /* increment "sequence" before following stores */
>  }
>
> +static __always_inline void write_seqcount_latch_begin(seqcount_latch_t *s)
> +{
> +       kcsan_nestable_atomic_begin();
> +       raw_write_seqcount_latch(s);
> +}
> +
> +static __always_inline void write_seqcount_latch(seqcount_latch_t *s)
> +{
> +       raw_write_seqcount_latch(s);
> +}
> +
> +static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
> +{
> +       kcsan_nestable_atomic_end();
> +}
> +
>  #define __SEQLOCK_UNLOCKED(lockname)                                   \
>         {                                                               \
>                 .seqcount = SEQCNT_SPINLOCK_ZERO(lockname, &(lockname).lock), \
> diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
> index beb808f4c367..19911c8fa7b6 100644
> --- a/kernel/printk/printk.c
> +++ b/kernel/printk/printk.c
> @@ -560,10 +560,11 @@ bool printk_percpu_data_ready(void)
>  /* Must be called under syslog_lock. */
>  static void latched_seq_write(struct latched_seq *ls, u64 val)
>  {
> -       raw_write_seqcount_latch(&ls->latch);
> +       write_seqcount_latch_begin(&ls->latch);
>         ls->val[0] = val;
> -       raw_write_seqcount_latch(&ls->latch);
> +       write_seqcount_latch(&ls->latch);
>         ls->val[1] = val;
> +       write_seqcount_latch_end(&ls->latch);
>  }
>
>  /* Can be called from any context. */
> @@ -574,10 +575,10 @@ static u64 latched_seq_read_nolock(struct latched_seq *ls)
>         u64 val;
>
>         do {
> -               seq = raw_read_seqcount_latch(&ls->latch);
> +               seq = read_seqcount_latch(&ls->latch);
>                 idx = seq & 0x1;
>                 val = ls->val[idx];
> -       } while (raw_read_seqcount_latch_retry(&ls->latch, seq));
> +       } while (read_seqcount_latch_retry(&ls->latch, seq));
>
>         return val;
>  }
> diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
> index 68d6c1190ac7..4958b40ba6c9 100644
> --- a/kernel/time/sched_clock.c
> +++ b/kernel/time/sched_clock.c
> @@ -71,13 +71,13 @@ static __always_inline u64 cyc_to_ns(u64 cyc, u32 mult, u32 shift)
>
>  notrace struct clock_read_data *sched_clock_read_begin(unsigned int *seq)
>  {
> -       *seq = raw_read_seqcount_latch(&cd.seq);
> +       *seq = read_seqcount_latch(&cd.seq);
>         return cd.read_data + (*seq & 1);
>  }
>
>  notrace int sched_clock_read_retry(unsigned int seq)
>  {
> -       return raw_read_seqcount_latch_retry(&cd.seq, seq);
> +       return read_seqcount_latch_retry(&cd.seq, seq);
>  }
>
>  unsigned long long noinstr sched_clock_noinstr(void)
> @@ -102,7 +102,9 @@ unsigned long long notrace sched_clock(void)
>  {
>         unsigned long long ns;
>         preempt_disable_notrace();
> +       kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
>         ns = sched_clock_noinstr();
> +       kcsan_atomic_next(0);
>         preempt_enable_notrace();
>         return ns;
>  }
> @@ -119,17 +121,19 @@ unsigned long long notrace sched_clock(void)
>   */
>  static void update_clock_read_data(struct clock_read_data *rd)
>  {
> -       /* update the backup (odd) copy with the new data */
> -       cd.read_data[1] = *rd;
> -
>         /* steer readers towards the odd copy */
> -       raw_write_seqcount_latch(&cd.seq);
> +       write_seqcount_latch_begin(&cd.seq);
>
>         /* now its safe for us to update the normal (even) copy */
>         cd.read_data[0] = *rd;
>
>         /* switch readers back to the even copy */
> -       raw_write_seqcount_latch(&cd.seq);
> +       write_seqcount_latch(&cd.seq);
> +
> +       /* update the backup (odd) copy with the new data */
> +       cd.read_data[1] = *rd;
> +
> +       write_seqcount_latch_end(&cd.seq);
>  }
>
>  /*
> @@ -267,7 +271,7 @@ void __init generic_sched_clock_init(void)
>   */
>  static u64 notrace suspended_sched_clock_read(void)
>  {
> -       unsigned int seq = raw_read_seqcount_latch(&cd.seq);
> +       unsigned int seq = read_seqcount_latch(&cd.seq);
>
>         return cd.read_data[seq & 1].epoch_cyc;
>  }
> diff --git a/kernel/time/timekeeping.c b/kernel/time/timekeeping.c
> index 7e6f409bf311..2ca26bfeb8f3 100644
> --- a/kernel/time/timekeeping.c
> +++ b/kernel/time/timekeeping.c
> @@ -424,16 +424,18 @@ static void update_fast_timekeeper(const struct tk_read_base *tkr,
>         struct tk_read_base *base = tkf->base;
>
>         /* Force readers off to base[1] */
> -       raw_write_seqcount_latch(&tkf->seq);
> +       write_seqcount_latch_begin(&tkf->seq);
>
>         /* Update base[0] */
>         memcpy(base, tkr, sizeof(*base));
>
>         /* Force readers back to base[0] */
> -       raw_write_seqcount_latch(&tkf->seq);
> +       write_seqcount_latch(&tkf->seq);
>
>         /* Update base[1] */
>         memcpy(base + 1, base, sizeof(*base));
> +
> +       write_seqcount_latch_end(&tkf->seq);
>  }
>
>  static __always_inline u64 __ktime_get_fast_ns(struct tk_fast *tkf)
> @@ -443,11 +445,11 @@ static __always_inline u64 __ktime_get_fast_ns(struct tk_fast *tkf)
>         u64 now;
>
>         do {
> -               seq = raw_read_seqcount_latch(&tkf->seq);
> +               seq = read_seqcount_latch(&tkf->seq);
>                 tkr = tkf->base + (seq & 0x01);
>                 now = ktime_to_ns(tkr->base);
>                 now += __timekeeping_get_ns(tkr);
> -       } while (raw_read_seqcount_latch_retry(&tkf->seq, seq));
> +       } while (read_seqcount_latch_retry(&tkf->seq, seq));
>
>         return now;
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNsDG7J%3DZsuA40opV1b3xKMF0P8P3yCsufowJCRegGa7w%40mail.gmail.com.
