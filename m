Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTV3QO4QMGQEUVFD44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 363A79B4A96
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 14:06:26 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-71e51a31988sf7694315b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 06:06:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730207183; cv=pass;
        d=google.com; s=arc-20240605;
        b=IbLvlJTOujexxUXIudsGFkX+khC6M5ax5QIdM6YPuPuvWLaaRfTYshomqU7H0XY/dc
         C58+Zhk1KybKKVmiZN/5hFIDdOGYF//zqVOHYpAwVUs6V8pL4pJ0xY73ZWnRjETxhxvk
         lChyjLe/usfMglVnfGY+ruhQhmvKZAGhTCg0jPnW6g7XdgXsow59gneKLwgon85n1tAF
         6F0SBKzhikGk7pAc/nuMjKLnZuKOK75wCfAiJvhek81OD1ntz4Q9PKro1fUaGbhEh/en
         roJxOofW9OZqRldKQ9RvBD8g6VSl4LBMdkUh5M7kWRaGUEu9lhD5VrFcpjxgGM9KsRcd
         P7AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Tcg10law5ahWjeYghMqKqX+y7kjwKvKTB3icGn2+XIg=;
        fh=PahOjtdULBwKA3kNABwsshJMBK03nwngLIFNn7hsCIw=;
        b=iNC86LFgsv1MfdLQfo7kV1W8eKhAoGm21CFS0P1tOxNM8EAbf98etD15P5sGNFPSnX
         9FwYw7MG0wqxW+mB3caaDGV/dx8G8xVUoVjfkUSf8IO9VyRlE0YfoGkLL4fSinvqdBI1
         EvxjqZ+5/z85mqacTJ7HIXxO+WX3ubJzT9m7Q1xqE6Gc7o6ub/hWa2Z1+e9Zt1wTPSCv
         fJf/hEtVacJCgunmN4ItibW6oQY8ID7A+JpLj8YmJr+bYo+SjUnp6LGZ04jskClEuORd
         8QKGdPjs01akChov6x/G+MOfiRQcR8+QS9VZIfIbyymMAixTnu0P2nhaLVbkzW3ApC4i
         VmzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=no04QDhX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730207183; x=1730811983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Tcg10law5ahWjeYghMqKqX+y7kjwKvKTB3icGn2+XIg=;
        b=uiT9d57F6qOz+GwV2O1Ijst8Te8Tu8dNbe7WCMfNCmV5ImyTZMiTPbPEWUHLOODYbI
         7p/saAskgmv5fnnF0LN55ondEQ2SJ9DD0QqK73D9T0Pq6JtRORzwqtnbXbJ4M1qT2A3O
         7ePBRz1hrLlLwET2Be0ECKsg2RAcAdqGATOhBQyqAWnYD9mZUgZ1d+EQgwxBzidyabBj
         61aOOwM37VoEXUseFzAEbHt/BPzCg3KGQ5OX7NggkW2iEUPM0eYDvpD0HpVh2vSSoQUh
         73QrZMAn6qdg0pTFp82lzghxg/jP88L/0bApPBjH0X/320zS5K3bt35wAb6K7y9OMKnt
         jO9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730207183; x=1730811983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Tcg10law5ahWjeYghMqKqX+y7kjwKvKTB3icGn2+XIg=;
        b=IyW8k0YXwHm+9gIHthK+42Y5eAs/rajoduoTMdzB/V8OmDU4PudFbFT6gOCez1gYAI
         vW+RKa5qNhIcOc1tCepo32spHmljrNsOM5KuWmCsykLCSEZ54lWOsYH4Eb/DqFFdHzEo
         RetTZSnGlxyXhP4dKFIUuw7s1bOY7fUe8odvEtJecjhmI+EsjuxU6bwwRzI9gkDp3g39
         fp2ZfoBRMXYt+FxWMfM4J19TUZE3Jg9ik1dzvGB9asZIlu+pHKJJG4fH/CtugfvH+tW0
         QBOQj1VJtTYM5vEYjwY7CDxXjG0DWrYPecWXuk8oLLQYH0eiUTFSdiZY0EYaW2XQT8nz
         V9kg==
X-Forwarded-Encrypted: i=2; AJvYcCU3LwUqJgJbn4nqK54tuWX4M5JBBfE9Av5GHGoAgs89bCkC1QHikXDWaA0zAj7bFBSALWP6mA==@lfdr.de
X-Gm-Message-State: AOJu0YwEXlov9xnwmWPAWmo1LusNuv1rGdPROwiANzafxbPvm580eg/w
	JqYrdkLwvoor5b1VSzTZSz3X4CgG/5vIGJewJfn2KzHecXM1UEdw
X-Google-Smtp-Source: AGHT+IFic+YpaRY/eQI9LE1zsf4OVZJEijI49up+S6JDQOaBxG62uuCz/wc9GvTWbEq3pEzxAEUKow==
X-Received: by 2002:a05:6a00:18a8:b0:71d:f64d:ec60 with SMTP id d2e1a72fcca58-72062f83dedmr18657266b3a.7.1730207182749;
        Tue, 29 Oct 2024 06:06:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1896:b0:71e:4823:555e with SMTP id
 d2e1a72fcca58-720403a7bb6ls3888015b3a.2.-pod-prod-05-us; Tue, 29 Oct 2024
 06:06:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZKUz90q3pmy16MDs/Dk+/AlDUg7s7GfEXXox5nNARmiCDHNe0yZ5n2qeHjwZMyA18PTGW7GBrucM=@googlegroups.com
X-Received: by 2002:a05:6a20:c6ce:b0:1d9:77a0:20c7 with SMTP id adf61e73a8af0-1d9a81ba801mr15674810637.0.1730207181109;
        Tue, 29 Oct 2024 06:06:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730207181; cv=none;
        d=google.com; s=arc-20240605;
        b=ZzmyjpxQ7PAh+EZvXeSq1t/TcB1HE1Xa4UCB7s2i6h0XnKOKUIHWxbz713Pb4JB7kl
         MA57X+W9ytOpx/pbMAbrcRUw6XcDy2fCmO34lVTrFG7Xl/84AyojZYC78edRoI/bj0En
         Kyl2rHgS7gcan6WATy12NyOxVbqE3pOW+UjwKRyo0L0HcSc1Gpc2/FP0MC42nZG4ULyP
         f63Ny1yUSRjlFmMrB3BfarBN/jSl5Rd5ICqHEb2IIth4yiuE+1j9nAsAhu6PRdWCmmJh
         EZZqn7A29CsTUGhuqx5Spa0k2JwWEuSWgkAHo+PjWgnlhxymnOODlUECZqs+5kCzsv0F
         l3lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NHj8IGmGIs1egtb7syFkJuryY4pVczFLIPpjJP1F+TM=;
        fh=C0RWQ/4zApjCPBn7obHZzcPi9MGAm9VDpj421mdDzbs=;
        b=V+RB/Mwy7LFcuvWUAzrjzNLAWzTHRD6k5U+qISm5wH+dMp9orYcHGy6hQANB3DGGiT
         kB8xghTb08LoXJwo6Ddl/lhfP6f0OR1p94FZa2Y649Io4CvM1R8oaSVYI5z3+kutaPPb
         2mfood7O9QdlsXG+I+b3W5vydOnjBdB8bgZQUXOMPFJPCmZ7jHupKs46NpHSgkO3ZLVO
         62DJT87C5ZkPIIY3QmF9mm84eOlQHKkTah2OY9fxhoBIMg6zl3N6DNGJhqLmNcCGvUul
         lhlNb75boQPkVxvG6fZI9bMC0SyH59Uq2+zzU8D27mCHVY6ehE27e0noua/SdCoabwB2
         3JUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=no04QDhX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-72057818d24si379564b3a.0.2024.10.29.06.06.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Oct 2024 06:06:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-71e5130832aso3795609b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Oct 2024 06:06:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUI0bF9gTZh08ksw1U9LDdWO1H78LZuqUTyc9BgzagvSxJRExT5EFDxmOvzl99VSR2vhVp+IyoQICI=@googlegroups.com
X-Received: by 2002:a05:6a00:3cc8:b0:71e:e3:608 with SMTP id
 d2e1a72fcca58-7206306ebb4mr15810841b3a.26.1730207180368; Tue, 29 Oct 2024
 06:06:20 -0700 (PDT)
MIME-Version: 1.0
References: <20241029083658.1096492-1-elver@google.com> <20241029114937.GT14555@noisy.programming.kicks-ass.net>
In-Reply-To: <20241029114937.GT14555@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Oct 2024 14:05:38 +0100
Message-ID: <CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=no04QDhX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::432 as
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

On Tue, 29 Oct 2024 at 12:49, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Oct 29, 2024 at 09:36:29AM +0100, Marco Elver wrote:
> > Reviewing current raw_write_seqcount_latch() callers, the most common
> > patterns involve only few memory accesses, either a single plain C
> > assignment, or memcpy;
>
> Then I assume you've encountered latch_tree_{insert,erase}() in your
> travels, right?

Oops. That once certainly exceeds the "8 memory accesses".

> Also, I note that update_clock_read_data() seems to do things
> 'backwards' and will completely elide your proposed annotation.

Hmm, for the first access, yes. This particular oddity could be
"fixed" by surrounding the accesses by
kcsan_nestable_atomic_begin/end(). I don't know if it warrants adding
a raw_write_seqcount_latch_begin().

Preferences?

> > therefore, the value of 8 memory accesses after
> > raw_write_seqcount_latch() is chosen to (a) avoid most false positives,
> > and (b) avoid excessive number of false negatives (due to inadvertently
> > declaring most accesses in the proximity of update_fast_timekeeper() as
> > "atomic").
>
> The above latch'ed RB-trees can certainly exceed this magical number 8.
>
> > Reported-by: Alexander Potapenko <glider@google.com>
> > Tested-by: Alexander Potapenko <glider@google.com>
> > Fixes: 88ecd153be95 ("seqlock, kcsan: Add annotations for KCSAN")
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/seqlock.h | 9 +++++++++
> >  1 file changed, 9 insertions(+)
> >
> > diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> > index fffeb754880f..e24cf144276e 100644
> > --- a/include/linux/seqlock.h
> > +++ b/include/linux/seqlock.h
> > @@ -614,6 +614,7 @@ typedef struct {
> >   */
> >  static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *s)
> >  {
> > +     kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
> >       /*
> >        * Pairs with the first smp_wmb() in raw_write_seqcount_latch().
> >        * Due to the dependent load, a full smp_rmb() is not needed.
> > @@ -631,6 +632,7 @@ static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *
> >  static __always_inline int
> >  raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
> >  {
> > +     kcsan_atomic_next(0);
> >       smp_rmb();
> >       return unlikely(READ_ONCE(s->seqcount.sequence) != start);
> >  }
> > @@ -721,6 +723,13 @@ static inline void raw_write_seqcount_latch(seqcount_latch_t *s)
> >       smp_wmb();      /* prior stores before incrementing "sequence" */
> >       s->seqcount.sequence++;
> >       smp_wmb();      /* increment "sequence" before following stores */
> > +
> > +     /*
> > +      * Latch writers do not have a well-defined critical section, but to
> > +      * avoid most false positives, at the cost of false negatives, assume
> > +      * the next few memory accesses belong to the latch writer.
> > +      */
> > +     kcsan_atomic_next(8);
> >  }
>
> Given there are so very few latch users, would it make sense to
> introduce a raw_write_seqcount_latch_end() callback that does
> kcsan_atomic_next(0) ? -- or something along those lines? Then you won't
> have to assume such a small number.

That's something I considered, but thought I'd try the unintrusive
version first. But since you proposed it here, I'd much prefer that,
too. ;-)
Let me try that.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q%40mail.gmail.com.
