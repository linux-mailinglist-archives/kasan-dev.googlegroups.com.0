Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO7UZ7XQKGQESUVIGXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B96411EC1B
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 21:53:17 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id i4sf89990ual.10
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 12:53:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576270396; cv=pass;
        d=google.com; s=arc-20160816;
        b=XZnGe7S8r6dgU3iuhKH6u2xBsVNU4nH89c9OL/ZGHOADXNJ/LV59GkPFDD5pVWgYm/
         4YXGTbTsMMFqosa5zHIV/EFEW95sFCdEsP6V+nih7h80aeekwm6CWWB2HaaarKXGXli8
         ZSqg8r/IJ/yH0LFtT73i7GgG87klN3GfxGiKcrl4obvWdbSvjdDrz3JGzxfCXKpF5RVf
         b4TjEb/qAEVrIj/1mtvYkBupQu5peASTVSD2dRawo2sALbSgnCGSZlrGBBSTyGL0gkb+
         jMHCWZ1lCOWqgLTak6EGTl7LsmNugV9Elgoz2AYz7f8dRnuo4lKWrbf5KJig18QBfHLJ
         pDaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yq8b8XCAnwcbG8/QIKBM54js1t1WWjDrnB9d8OFxXNA=;
        b=DDkcXho2WWoTURIxM58+qG98AYFG35v/UiD30hubASyq6ZwVBoY6/ComFUFMa2SwTE
         zdB5MplXoTG11tfkxpdDqy4AAL6x0hZiMKoprXDZsQpIQ5NHgn/6MnFc58uHq5rW8e4D
         mGAF8bn5wzkUV/c3f474QTdFvB70Pc8Wntt9krQfxszhW9XQXY7JpISRogpUsYZGefcY
         vXrxUl9cto1P7rpt7HHXNn5WGgXJnM8a/0el8SHZsuU0NOGs+klqf7ux9kJiYgy3Hlo6
         +NrXPdZ3qGo35T8FiZ99/EiVr/p4kR1H2NTZxlQIHr4AKfNEDheYy52iielwZxvNZXp1
         DIYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n8TzZEHD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yq8b8XCAnwcbG8/QIKBM54js1t1WWjDrnB9d8OFxXNA=;
        b=IHE46QeGOKM7Sgo+w99P5QbaWUGfOueL/0eDZejXb98NlHTSyPrzKF2d6KBS0+tDex
         DfucNMbqXJhbybXGkXQjcfkyuVgHAuAaat0FXMgBZi7+F0hffdPdSH99rH3Q6nQtg0UJ
         A6495m+1y+CMoHRLmjPTzkZWGLtmgfOjh433soXFHL7A3h0zJq2ZrcqDl5h9sHFH6gXA
         yd/KhmG5xfR1h5hF8vuJ0WUm2Rv/umBSXpEZ9gOutvDaZoby4vWz+we8EnEfy51Asb/i
         YLONtxj8EvnEsMbam2iCV79MrL17/N3h9HuCgLQyNjiJu/50BduytmhmsQHj8O17bFt2
         EMaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yq8b8XCAnwcbG8/QIKBM54js1t1WWjDrnB9d8OFxXNA=;
        b=udLstV/wvP+uh7+pha7AxE0N2idYifkHhyd/wrfJigfdeR6Al8ZbedIWom3THI6PGr
         BN9Yv923UD9Xww/p4m9O+3HVXWaem+/HZEv50vC2wLRo3GPHP1ZR2QhfGUvnE4XbIjSR
         UrnTe6AzW1tv2vPuhhpMTBMqbdg4PsGaV8TbU6/QJkhbCeM8A8yrfBsM7JpVOch87YeG
         Z+Pk+4f5IwDEHGxlKO29p06A7s/Mdi7ZVISQ3iOos2fp1cJ9zGiyAPvr08U33Q6Hw1Ts
         tWc6W4w9MY0wcMtNr+sCsaqBT8T2jnnjrpxwaLHEnulqwTT6o9wNPaNv2W/MHz0bicZJ
         t2AA==
X-Gm-Message-State: APjAAAX7VHPLffrjMz2yFpRS8taIq3Xby6n8Pjxb8GFeH6juJcomB8vE
	fM3F+9aV3OsjVP5FamZ9qDE=
X-Google-Smtp-Source: APXvYqymL7B2BmWW4CfzXQHKPwopdi7gRQWXEAL7Dv+NYu28tukTPDBAie4qSsNYbOf5OMAJurFGCQ==
X-Received: by 2002:a67:bd0e:: with SMTP id y14mr12660972vsq.59.1576270395896;
        Fri, 13 Dec 2019 12:53:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2885:: with SMTP id s5ls793035uap.10.gmail; Fri, 13 Dec
 2019 12:53:15 -0800 (PST)
X-Received: by 2002:ab0:714c:: with SMTP id k12mr14998579uao.124.1576270395412;
        Fri, 13 Dec 2019 12:53:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576270395; cv=none;
        d=google.com; s=arc-20160816;
        b=nc7a7L5WXEWcLOJjr95S5ZSF2EqgYEQXMGY8y7tepIhcswa2FFgi44S2cmVqUnqc8f
         mpu9AeO3PKRSiIAztJSz/FuazTAiulKQ6yAKR9syj7cNNXjus0wVaIkf5FN//IPlq+Ot
         Pbf4WoNblxJ8RlI9Ge2EIQNoMSaEYOaMgIHrnkkOvLNmPdO+LbCm0MLyv6JZpjhFOhhN
         rG/iH2Sl1np/+tlrVkLSWpnOMsb1xalyGFvfMwxc2MTjJn18xOUWP+PUvdGH3Ugo7LTy
         jl65AJ7SbaKv53+Vf7vHSHi6h0/q8QnQymQ720J+6HkBQBFreRjLM49ZWtDLLjq9l4R8
         6AQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RJVV240FcmOJOsegfmFG4PxTY2FHtv3JmMVXSMNvK6k=;
        b=BRmOQNGu6Qpixqq/8MdEFrLfKv5nyQ6qX79vFDjB5qWfUJ3gNr6BRY5rwkAoepuszl
         bSZHZiVQYbmTxVUkuXv7vtr8ndYNaCv3PYT02BH9rUztyZiAGnm9DN9sDzKw/Oamhypw
         FX89CY9AdRCH9mY1OKtRmNxGosm/Xhs2wb2eHuF79bHOWcUm7g0G66TsF8AdG7E8zt7C
         +0rzOYuryBkjynv8rXNDaXp9OuJrKFaBtz2nBvyytwd2+A+O1j246keHtHuzz4E/gwb7
         ONC1Z7vgqfJMViCXJ6ZTYFsONEy/tZ9UYpkFVbCfSpqlkrtpWw6S3f6fH36gQYFUaf8l
         xlDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n8TzZEHD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id w4si502564vse.2.2019.12.13.12.53.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Dec 2019 12:53:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id 59so569566otp.12
        for <kasan-dev@googlegroups.com>; Fri, 13 Dec 2019 12:53:15 -0800 (PST)
X-Received: by 2002:a9d:7f12:: with SMTP id j18mr17267505otq.17.1576270394337;
 Fri, 13 Dec 2019 12:53:14 -0800 (PST)
MIME-Version: 1.0
References: <20191126140406.164870-1-elver@google.com> <20191126140406.164870-3-elver@google.com>
 <00ee3b40-0e37-c9ac-3209-d07b233a0c1d@infradead.org> <20191203160128.GC2889@paulmck-ThinkPad-P72>
 <CANpmjNOvDHoapk1cR5rCAcYgfVwf8NS0wFJncJ-bQrWzCKLPpw@mail.gmail.com> <20191213013127.GE2889@paulmck-ThinkPad-P72>
In-Reply-To: <20191213013127.GE2889@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 13 Dec 2019 21:53:02 +0100
Message-ID: <CANpmjNPWYh1HioefhZjQtXv+8sXSxQmg22uJN=-ut9mdsr=atw@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kcsan: Prefer __always_inline for fast-path
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Randy Dunlap <rdunlap@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-arch <linux-arch@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=n8TzZEHD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, 13 Dec 2019 at 02:31, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Dec 12, 2019 at 10:11:59PM +0100, Marco Elver wrote:
> > On Tue, 3 Dec 2019 at 17:01, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Mon, Dec 02, 2019 at 09:30:22PM -0800, Randy Dunlap wrote:
> > > > On 11/26/19 6:04 AM, Marco Elver wrote:
> > > > > Prefer __always_inline for fast-path functions that are called outside
> > > > > of user_access_save, to avoid generating UACCESS warnings when
> > > > > optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
> > > > > surprises with compiler versions that change the inlining heuristic even
> > > > > when optimizing for performance.
> > > > >
> > > > > Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> > > > > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > >
> > > > Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested
> > >
> > > Thank you, Randy!
> >
> > Hoped this would have applied by now, but since KCSAN isn't in
> > mainline yet, should I send a version of this patch rebased on
> > -rcu/kcsan?
> > It will just conflict with the style cleanup that is in
> > -tip/locking/kcsan when another eventual merge happens. Alternatively,
> > we can delay it for now and just have to remember to apply eventually
> > (and have to live with things being messy for a bit longer :-)).
>
> Excellent question.  ;-)
>
> The first several commits are in -tip already, so they will go upstream
> in their current state by default.  And a bunch of -tip commits have
> already been merged on top of them, so it might not be easy to move them.
>
> So please feel free to port the patch to -rcu/ksan and let's see how that
> plays out.  If it gets too ugly, then maybe wait until the current set
> of patches go upstream.
>
> Another option is to port them to the kcsan merge point in -rcu.  That
> would bring in v5.5-rc1.  Would that help?

For this patch it won't help, since it only conflicts with changes in
this commit which is not in v5.5-rc1:
https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?h=locking/kcsan&id=5cbaefe9743bf14c9d3106db0cc19f8cb0a3ca22

However, for this patch there are only 3 locations in
kernel/kcsan/{core.c,encoding.h} that conflict, and all of them should
be trivial to resolve. For the version rebased against -rcu/kcsan, in
the conflicting locations I simply carried over the better style, so
that upon eventual merge the resolution should be trivial (I hope). I
have sent the rebased version here:
http://lkml.kernel.org/r/20191213204946.251125-1-elver@google.com

Unrelated to this patch, we also deferred the updated bitops patch
which now applies on top of v5.5-rc1:
http://lkml.kernel.org/r/20191115115524.GA77379@google.com
but doesn't apply to -rcu/kcsan. I think the bitops patch isn't
terribly urgent, so it could wait to avoid further confusion.

Many thanks,
-- Marco


>                                                         Thanx, Paul
>
> > The version as-is here applies on -tip/locking/kcsan and -next (which
> > merged -tip/locking/kcsan).
> >
> > Thanks,
> > -- Marco
> >
> >
> > >                                                         Thanx, Paul
> > >
> > > > Thanks.
> > > >
> > > > > ---
> > > > > Rebased on: locking/kcsan branch of tip tree.
> > > > > ---
> > > > >  kernel/kcsan/atomic.h   |  2 +-
> > > > >  kernel/kcsan/core.c     | 16 +++++++---------
> > > > >  kernel/kcsan/encoding.h | 14 +++++++-------
> > > > >  3 files changed, 15 insertions(+), 17 deletions(-)
> > > > >
> > > > > diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> > > > > index 576e03ddd6a3..a9c193053491 100644
> > > > > --- a/kernel/kcsan/atomic.h
> > > > > +++ b/kernel/kcsan/atomic.h
> > > > > @@ -18,7 +18,7 @@
> > > > >   * than cast to volatile. Eventually, we hope to be able to remove this
> > > > >   * function.
> > > > >   */
> > > > > -static inline bool kcsan_is_atomic(const volatile void *ptr)
> > > > > +static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
> > > > >  {
> > > > >     /* only jiffies for now */
> > > > >     return ptr == &jiffies;
> > > > > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > > > > index 3314fc29e236..c616fec639cd 100644
> > > > > --- a/kernel/kcsan/core.c
> > > > > +++ b/kernel/kcsan/core.c
> > > > > @@ -78,10 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
> > > > >   */
> > > > >  static DEFINE_PER_CPU(long, kcsan_skip);
> > > > >
> > > > > -static inline atomic_long_t *find_watchpoint(unsigned long addr,
> > > > > -                                        size_t size,
> > > > > -                                        bool expect_write,
> > > > > -                                        long *encoded_watchpoint)
> > > > > +static __always_inline atomic_long_t *
> > > > > +find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
> > > > >  {
> > > > >     const int slot = watchpoint_slot(addr);
> > > > >     const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> > > > > @@ -146,7 +144,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
> > > > >   * 2. the thread that set up the watchpoint already removed it;
> > > > >   * 3. the watchpoint was removed and then re-used.
> > > > >   */
> > > > > -static inline bool
> > > > > +static __always_inline bool
> > > > >  try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
> > > > >  {
> > > > >     return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
> > > > > @@ -160,7 +158,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
> > > > >     return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
> > > > >  }
> > > > >
> > > > > -static inline struct kcsan_ctx *get_ctx(void)
> > > > > +static __always_inline struct kcsan_ctx *get_ctx(void)
> > > > >  {
> > > > >     /*
> > > > >      * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
> > > > > @@ -169,7 +167,7 @@ static inline struct kcsan_ctx *get_ctx(void)
> > > > >     return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
> > > > >  }
> > > > >
> > > > > -static inline bool is_atomic(const volatile void *ptr)
> > > > > +static __always_inline bool is_atomic(const volatile void *ptr)
> > > > >  {
> > > > >     struct kcsan_ctx *ctx = get_ctx();
> > > > >
> > > > > @@ -193,7 +191,7 @@ static inline bool is_atomic(const volatile void *ptr)
> > > > >     return kcsan_is_atomic(ptr);
> > > > >  }
> > > > >
> > > > > -static inline bool should_watch(const volatile void *ptr, int type)
> > > > > +static __always_inline bool should_watch(const volatile void *ptr, int type)
> > > > >  {
> > > > >     /*
> > > > >      * Never set up watchpoints when memory operations are atomic.
> > > > > @@ -226,7 +224,7 @@ static inline void reset_kcsan_skip(void)
> > > > >     this_cpu_write(kcsan_skip, skip_count);
> > > > >  }
> > > > >
> > > > > -static inline bool kcsan_is_enabled(void)
> > > > > +static __always_inline bool kcsan_is_enabled(void)
> > > > >  {
> > > > >     return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
> > > > >  }
> > > > > diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> > > > > index b63890e86449..f03562aaf2eb 100644
> > > > > --- a/kernel/kcsan/encoding.h
> > > > > +++ b/kernel/kcsan/encoding.h
> > > > > @@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
> > > > >                   (addr & WATCHPOINT_ADDR_MASK));
> > > > >  }
> > > > >
> > > > > -static inline bool decode_watchpoint(long watchpoint,
> > > > > -                                unsigned long *addr_masked,
> > > > > -                                size_t *size,
> > > > > -                                bool *is_write)
> > > > > +static __always_inline bool decode_watchpoint(long watchpoint,
> > > > > +                                         unsigned long *addr_masked,
> > > > > +                                         size_t *size,
> > > > > +                                         bool *is_write)
> > > > >  {
> > > > >     if (watchpoint == INVALID_WATCHPOINT ||
> > > > >         watchpoint == CONSUMED_WATCHPOINT)
> > > > > @@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
> > > > >  /*
> > > > >   * Return watchpoint slot for an address.
> > > > >   */
> > > > > -static inline int watchpoint_slot(unsigned long addr)
> > > > > +static __always_inline int watchpoint_slot(unsigned long addr)
> > > > >  {
> > > > >     return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
> > > > >  }
> > > > >
> > > > > -static inline bool matching_access(unsigned long addr1, size_t size1,
> > > > > -                              unsigned long addr2, size_t size2)
> > > > > +static __always_inline bool matching_access(unsigned long addr1, size_t size1,
> > > > > +                                       unsigned long addr2, size_t size2)
> > > > >  {
> > > > >     unsigned long end_range1 = addr1 + size1 - 1;
> > > > >     unsigned long end_range2 = addr2 + size2 - 1;
> > > > >
> > > >
> > > >
> > > > --
> > > > ~Randy
> > > >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191213013127.GE2889%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPWYh1HioefhZjQtXv%2B8sXSxQmg22uJN%3D-ut9mdsr%3Datw%40mail.gmail.com.
