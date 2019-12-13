Return-Path: <kasan-dev+bncBAABB4GTZPXQKGQEVGGFZZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B109511DBB1
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 02:31:29 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id z21sf603720iob.22
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 17:31:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576200688; cv=pass;
        d=google.com; s=arc-20160816;
        b=CcU4lgheIM9uz3WIur3QlAu8/rNKZnIKmlYI/zkX4LOP5YuzvSssQQ7ntumB7maXzC
         sCHv8fHrnScfBJGMijKS89U5qqIQhrGSQBNzuhozU/BjLIc9H07Uw2YKVSKtaULRpERm
         brp2OrRnLXOgWdv1syOJWG55BffEpvCtnejdHWy1eqn9nwiH2HB0Pn46hqSTHUQLa5vA
         V+L+VRB8qA8D2EnNggISBqJ4toUSrI/0I8FK5WpbSyePSvWmA5tegxNRaJuHl5AAfcEf
         acBD/zXpAFgbUbqJNiCp+71AqbjFjt/tmAMoNFpkzC1pWmsKIrWx+c94DQWkI9phs7uv
         zVZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=b+5vAS3+dbaey22FYB8FaEj6XFr9XxNoPYUdnkci1Oc=;
        b=zasG8BuxmHo2b5RsvHXavfmTNl+wFWsWpFZMU0TCFh6j3XeacXFGkqTaREjG+GKpVL
         pGyPNg6V4y5ZFBnLVO8d+t+GeuI4+qtQdCb/q/pccuPfRPZHRSayqhRrXxpSOHjIATGF
         mXl4ziR50Bu3qjdz+qQojmIkCTbruDFCwIbYq9Ioufx+LB4Zm1ZNHFLHq/CN+PglmWLH
         t69cIK+Hpts7ps1oJBq9sfwoF5hqusL5HzTxlUOW3etNNj1thl82toHu98XjfUIjEAB6
         y+wP1PfB0g0WF4W3NsuxYHsmRag9p5GOaMNDV9adOa55TcGxlxdnBUpO8z77V//I7PG8
         yUCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="H/ST3WYj";
       spf=pass (google.com: domain of srs0=3cy6=2d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3cY6=2D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b+5vAS3+dbaey22FYB8FaEj6XFr9XxNoPYUdnkci1Oc=;
        b=Yv2afRni+RuHI2QPi5csl/IJ1QwO8rTnuYKmK0NVnwx6WACNeboWuCOihkaPWDVPBH
         +ULue27gifgQMX0ggoatYhJcFOqTHeahB6MmPeKVlwdsaoWidRt+7O1T4fdIbfNhpTR+
         QvFuShGjKtVZ04d1Ze9MU1vnycWNU7znunQuJ/aAXj+tHj+2enixOGkcmDWBrBNnMOwH
         JabzdaAhqpzT8J2pVcow2j1QU0icbMKHuDqe65iAhK8+JC3KvkZtR/LCxfekFS/yeZFl
         F89UdTr2wS/8NJg+zI7rMnliObN2pjchwPpe85xvaVcJX3veyOmH793HdCzp59Kt7Qpn
         7D3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b+5vAS3+dbaey22FYB8FaEj6XFr9XxNoPYUdnkci1Oc=;
        b=s7h0IafS7oXuXSm22uCnl5v6lK+esb3N4LuhvoGx0dEJSoJ29ZEhU97LQQzVUQHDeW
         YtKtyDqEhpTTBOEybtLOZUEybvUbIucw+SUZ/lflmkHE4zRQYhx5C7kEQucMo0ZbliDB
         kBusJjpV/yTPpEOl6XUNBtt4cWj8KyVaN5LUPiR2rxf2+QmBPXah7fSHTTjd+fanAc0g
         MtiN+YZ7o8FF7sm0sVhX8MB3ZmJkVaoi8d2wxXA4GY6+z14FitXPgm0BK9KffRgqCiMp
         KvKTM2Lc39Sc9w8nPFwPmH8Rsdc23I8JmHFXYQmKXNC3u+OamEZPFXhEca5YeLl6YyQp
         sX3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUXtvM/YKO9z4gHrS7wfvVI3kTG9KVwrReexmREuYmWJ8RIKWgD
	6SbzrV+49Q2qAs7iQJ8PUL8=
X-Google-Smtp-Source: APXvYqyaASSUA27UtbWjKciJ2Yj3RRWpGXJmEOf84yN0GRulGtuXiXGialJ5diljppm+hDRL8vhfuA==
X-Received: by 2002:a92:d5cf:: with SMTP id d15mr10862241ilq.306.1576200688658;
        Thu, 12 Dec 2019 17:31:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:b047:: with SMTP id q7ls29335jah.15.gmail; Thu, 12 Dec
 2019 17:31:28 -0800 (PST)
X-Received: by 2002:a02:856a:: with SMTP id g97mr10728554jai.97.1576200688308;
        Thu, 12 Dec 2019 17:31:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576200688; cv=none;
        d=google.com; s=arc-20160816;
        b=CfT7cRziBCH5UjtNKkF2xaI19cmu4f70H2Bd6Y7qZmo+TeYC7oA23zTEdA0CcWkzaK
         FEYT/znsKucD/eSpNLQkR0YhMSTIdy0x/A8P9X2SzgMzIkVslYaagPSY2vsQTlNoDF4D
         lZrkjSHcss8Fv6jO+M4WiDbCZRoRZwNCjdytJa7d3zzxvFblV9FwaYBPq8v7MJswT6eR
         8d2SylAKpCmZsZtJqVCuVxVXK4W5NYADz5EXux2TlqPyBQxZep1ULE5og76p4XJnF8Ho
         33tBI0wnQTmCYyQytLOKGNKxAuzmsVynCCjLLSg8RjPgo/j1hhn1ytsCv1hy8/OA6+St
         zxbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Zl+1mRss4eQpjG4x/0Z0Yaud59kKVB0xtNvX3URdWGY=;
        b=YTTiCvbPACBnzSFpODpHvwLtOWkXIuWOkH8+sFH6Azp/YJ9FSNdOP6gbuMYkqB2CNX
         mD2SXAWD8ohk26+EA6txpcjjAaoj9Vyd9Qi1KokT5FkRHQWdPYBonr+NTxnXEWI+t9sy
         SP+xcuoq2/qdwyXCJAk627BqsjA+eXch+uZiumP/LsLSv4xuZ7sg3qBh+v8osl15QJfe
         +uDCvTZzi1t4+p00/EpWvS+74YK0u+nyqoc8IDbLQYvWKrLTYag6j/lee8xsWUHo+pQf
         nrQ7eCBdoh1Geh3J5lMxN6R8cQBfZNELyCmCDr09ySKbsrx6EOprdWz7489bM04c9cj4
         ol9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="H/ST3WYj";
       spf=pass (google.com: domain of srs0=3cy6=2d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3cY6=2D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g12si252974iok.4.2019.12.12.17.31.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Dec 2019 17:31:28 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=3cy6=2d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.130])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8112A206B7;
	Fri, 13 Dec 2019 01:31:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 19AE135227E8; Thu, 12 Dec 2019 17:31:27 -0800 (PST)
Date: Thu, 12 Dec 2019 17:31:27 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Randy Dunlap <rdunlap@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>,
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 3/3] kcsan: Prefer __always_inline for fast-path
Message-ID: <20191213013127.GE2889@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191126140406.164870-1-elver@google.com>
 <20191126140406.164870-3-elver@google.com>
 <00ee3b40-0e37-c9ac-3209-d07b233a0c1d@infradead.org>
 <20191203160128.GC2889@paulmck-ThinkPad-P72>
 <CANpmjNOvDHoapk1cR5rCAcYgfVwf8NS0wFJncJ-bQrWzCKLPpw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOvDHoapk1cR5rCAcYgfVwf8NS0wFJncJ-bQrWzCKLPpw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="H/ST3WYj";       spf=pass
 (google.com: domain of srs0=3cy6=2d=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3cY6=2D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Dec 12, 2019 at 10:11:59PM +0100, Marco Elver wrote:
> On Tue, 3 Dec 2019 at 17:01, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Mon, Dec 02, 2019 at 09:30:22PM -0800, Randy Dunlap wrote:
> > > On 11/26/19 6:04 AM, Marco Elver wrote:
> > > > Prefer __always_inline for fast-path functions that are called outside
> > > > of user_access_save, to avoid generating UACCESS warnings when
> > > > optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
> > > > surprises with compiler versions that change the inlining heuristic even
> > > > when optimizing for performance.
> > > >
> > > > Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> > > > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > >
> > > Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested
> >
> > Thank you, Randy!
> 
> Hoped this would have applied by now, but since KCSAN isn't in
> mainline yet, should I send a version of this patch rebased on
> -rcu/kcsan?
> It will just conflict with the style cleanup that is in
> -tip/locking/kcsan when another eventual merge happens. Alternatively,
> we can delay it for now and just have to remember to apply eventually
> (and have to live with things being messy for a bit longer :-)).

Excellent question.  ;-)

The first several commits are in -tip already, so they will go upstream
in their current state by default.  And a bunch of -tip commits have
already been merged on top of them, so it might not be easy to move them.

So please feel free to port the patch to -rcu/ksan and let's see how that
plays out.  If it gets too ugly, then maybe wait until the current set
of patches go upstream.

Another option is to port them to the kcsan merge point in -rcu.  That
would bring in v5.5-rc1.  Would that help?

							Thanx, Paul

> The version as-is here applies on -tip/locking/kcsan and -next (which
> merged -tip/locking/kcsan).
> 
> Thanks,
> -- Marco
> 
> 
> >                                                         Thanx, Paul
> >
> > > Thanks.
> > >
> > > > ---
> > > > Rebased on: locking/kcsan branch of tip tree.
> > > > ---
> > > >  kernel/kcsan/atomic.h   |  2 +-
> > > >  kernel/kcsan/core.c     | 16 +++++++---------
> > > >  kernel/kcsan/encoding.h | 14 +++++++-------
> > > >  3 files changed, 15 insertions(+), 17 deletions(-)
> > > >
> > > > diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> > > > index 576e03ddd6a3..a9c193053491 100644
> > > > --- a/kernel/kcsan/atomic.h
> > > > +++ b/kernel/kcsan/atomic.h
> > > > @@ -18,7 +18,7 @@
> > > >   * than cast to volatile. Eventually, we hope to be able to remove this
> > > >   * function.
> > > >   */
> > > > -static inline bool kcsan_is_atomic(const volatile void *ptr)
> > > > +static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
> > > >  {
> > > >     /* only jiffies for now */
> > > >     return ptr == &jiffies;
> > > > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > > > index 3314fc29e236..c616fec639cd 100644
> > > > --- a/kernel/kcsan/core.c
> > > > +++ b/kernel/kcsan/core.c
> > > > @@ -78,10 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
> > > >   */
> > > >  static DEFINE_PER_CPU(long, kcsan_skip);
> > > >
> > > > -static inline atomic_long_t *find_watchpoint(unsigned long addr,
> > > > -                                        size_t size,
> > > > -                                        bool expect_write,
> > > > -                                        long *encoded_watchpoint)
> > > > +static __always_inline atomic_long_t *
> > > > +find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
> > > >  {
> > > >     const int slot = watchpoint_slot(addr);
> > > >     const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> > > > @@ -146,7 +144,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
> > > >   * 2. the thread that set up the watchpoint already removed it;
> > > >   * 3. the watchpoint was removed and then re-used.
> > > >   */
> > > > -static inline bool
> > > > +static __always_inline bool
> > > >  try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
> > > >  {
> > > >     return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
> > > > @@ -160,7 +158,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
> > > >     return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
> > > >  }
> > > >
> > > > -static inline struct kcsan_ctx *get_ctx(void)
> > > > +static __always_inline struct kcsan_ctx *get_ctx(void)
> > > >  {
> > > >     /*
> > > >      * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
> > > > @@ -169,7 +167,7 @@ static inline struct kcsan_ctx *get_ctx(void)
> > > >     return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
> > > >  }
> > > >
> > > > -static inline bool is_atomic(const volatile void *ptr)
> > > > +static __always_inline bool is_atomic(const volatile void *ptr)
> > > >  {
> > > >     struct kcsan_ctx *ctx = get_ctx();
> > > >
> > > > @@ -193,7 +191,7 @@ static inline bool is_atomic(const volatile void *ptr)
> > > >     return kcsan_is_atomic(ptr);
> > > >  }
> > > >
> > > > -static inline bool should_watch(const volatile void *ptr, int type)
> > > > +static __always_inline bool should_watch(const volatile void *ptr, int type)
> > > >  {
> > > >     /*
> > > >      * Never set up watchpoints when memory operations are atomic.
> > > > @@ -226,7 +224,7 @@ static inline void reset_kcsan_skip(void)
> > > >     this_cpu_write(kcsan_skip, skip_count);
> > > >  }
> > > >
> > > > -static inline bool kcsan_is_enabled(void)
> > > > +static __always_inline bool kcsan_is_enabled(void)
> > > >  {
> > > >     return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
> > > >  }
> > > > diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> > > > index b63890e86449..f03562aaf2eb 100644
> > > > --- a/kernel/kcsan/encoding.h
> > > > +++ b/kernel/kcsan/encoding.h
> > > > @@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
> > > >                   (addr & WATCHPOINT_ADDR_MASK));
> > > >  }
> > > >
> > > > -static inline bool decode_watchpoint(long watchpoint,
> > > > -                                unsigned long *addr_masked,
> > > > -                                size_t *size,
> > > > -                                bool *is_write)
> > > > +static __always_inline bool decode_watchpoint(long watchpoint,
> > > > +                                         unsigned long *addr_masked,
> > > > +                                         size_t *size,
> > > > +                                         bool *is_write)
> > > >  {
> > > >     if (watchpoint == INVALID_WATCHPOINT ||
> > > >         watchpoint == CONSUMED_WATCHPOINT)
> > > > @@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
> > > >  /*
> > > >   * Return watchpoint slot for an address.
> > > >   */
> > > > -static inline int watchpoint_slot(unsigned long addr)
> > > > +static __always_inline int watchpoint_slot(unsigned long addr)
> > > >  {
> > > >     return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
> > > >  }
> > > >
> > > > -static inline bool matching_access(unsigned long addr1, size_t size1,
> > > > -                              unsigned long addr2, size_t size2)
> > > > +static __always_inline bool matching_access(unsigned long addr1, size_t size1,
> > > > +                                       unsigned long addr2, size_t size2)
> > > >  {
> > > >     unsigned long end_range1 = addr1 + size1 - 1;
> > > >     unsigned long end_range2 = addr2 + size2 - 1;
> > > >
> > >
> > >
> > > --
> > > ~Randy
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191213013127.GE2889%40paulmck-ThinkPad-P72.
