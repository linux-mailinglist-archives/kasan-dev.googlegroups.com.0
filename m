Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLG2ZLXQKGQEQTPV5TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 72EAF11D852
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 22:12:13 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id w6sf228489ill.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 13:12:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576185132; cv=pass;
        d=google.com; s=arc-20160816;
        b=Itu/prJlOMySxrSZ9EpN71gDp3qwE0Z5S6oUItPrUyoTKqDKxdumZse/yIQievlF01
         jxmLP721LYRFVsybRaWLS4uaZXfPM9NzweQY2j7IOL1HopUd1o7ds/LRPHH7wjvrYyQG
         Sa8cHht4qiYInWKldzH74EfZ2CExKhNDJKdfGcsz++XWmiRU1vmToEe92SQeQJIOKo38
         wXMiOlmCmgKS/owLxl9J6VoGxF7X0w+y83gh1APfLW40Lg2MwvPh6A7lxaqE+OKICjfc
         AoJ3WosXyMiOQXPQkgtQCateIh4gBRJ7FeWCWH17Ltao1wbDvqIYbXZKyYI1xAKJGQ7R
         pi7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z3HoClMRZYv1wAFC70ZgQwobYMc9sBsycHzVTnfc/gw=;
        b=xKzep7+CkU+ZdUnpRjyAHOgT5J7TTW/ymWQSHs6tDnmE5gGF52aH5su5e9clhTeLAp
         D2wDBtPyiRC/zDhUQK27ikuEw0IY+TjHyjGu1EzB4StQKBC2UP3mB0U9OM+xcOMLciof
         MzX4iSqCpSvUDwkW+LHKv0rs/4rGWD4K03O+FYZZHY7NG9foiqoRnhd6wEA6Ns/1qd/Q
         0edY0DvmJsNyC0k54gCyDh3dt63QpKUQuogrhjfgZ9Kp9V+XegOvkV6b3ZWTEafdgHzC
         qIQE5CFWN3V3zjJ1A7yMlEiuzJTI0Hl2iJTKnesv5HLThyk/CcvBmOC2aay87yyjkMTw
         RUZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kwaUKevD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z3HoClMRZYv1wAFC70ZgQwobYMc9sBsycHzVTnfc/gw=;
        b=bBN8BAScBKvC5HDpsiJ6gPGSV9ulH5LsGoZm3PQGA6f3gFcPQa+6wnIoAEg1wqP5SD
         poaFCYq1N/lw0XTej1qPx9uwlY+nNM/SSvtvldmmcTkt88+VSoSRwYD8AYlMCIp0bTC1
         Vw2jKKIWmQYEvvlEA7yE2RLwqwitNA1Jg+iS+sQ2m1RjL/uuL1T79WcbcIWZmuw/dNwQ
         yOdLN8qQGG0Swvx7yymrFYKcfss3/TNvJEfNK8w4DcIcpHncV0SmsitDOG9vSWbfDeeS
         SsSdDCG9hNO15iseArdKethDQd6rAc2nPqnpb8HkLihZ1UEGv32wuhZgQjXpbAHVnswF
         g2GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z3HoClMRZYv1wAFC70ZgQwobYMc9sBsycHzVTnfc/gw=;
        b=Ba9/nfXT2UwJ9E23yUrCWm4Tub4YDXW/XB1b0j2MCN94hgrcrTaKyrou5Mtb/3Fqo4
         UfgUqfLDHkrZ/N7g6mrYojoF7dlj3xCb2GHgp5rql3RyV64LrrnIYLDK1zc4B3oAfdNK
         QIBNrdWN7+SeSqG6NbViX+JU+LV85L6t/3SrYOLYRBIK2fbQwRmuY0lbn6YDmqToGeid
         y2h/q6r30MC10f0kdemfjfDNUQBS+4vi4ru0qFcZoTLOMATbBbwEYN95IV1YkWLrDfGo
         ValaohZA1Ib3usP7rlpoDRD3nx3L8XKUQp/PJDJ0p9cQ4UO7NfyD4+Nc2+p8fprJH4z4
         Vt0A==
X-Gm-Message-State: APjAAAU3vOBK6yEQNgJ0PwMRYEixY5+1CXUwzTROT59palY676htINtV
	0yUrZuVoMcZluOemvFCtMqs=
X-Google-Smtp-Source: APXvYqyGag9ahKXImsGAFxJKivnNu45zSNkaoO+wwRh5ox6D+/e+S3N2aAsXYjuue3eIO9LLdMZ1OA==
X-Received: by 2002:a92:bb4a:: with SMTP id w71mr10570016ili.112.1576185132227;
        Thu, 12 Dec 2019 13:12:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5d90:: with SMTP id e16ls1133161ilg.4.gmail; Thu, 12 Dec
 2019 13:12:11 -0800 (PST)
X-Received: by 2002:a92:5c8f:: with SMTP id d15mr10925890ilg.102.1576185131837;
        Thu, 12 Dec 2019 13:12:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576185131; cv=none;
        d=google.com; s=arc-20160816;
        b=w7EB5D1/DKG+YaO7KbGJ52ej/QXdakO5YPGeTwzVBAxq/IErpp9i0f7oARnZNE0l2Z
         gQz4Xnjvi/3BapIJVVkQd3Hl3pn2qZhAJzb53o5B5GH0mAkPvoC1Kg86g1MG+OXaJs1F
         Nw62dxclQ4gEpglghAKlhJgOWzwq8gZE0LCHJezvG9bLjaTO7eCI77DBtfEv7w1gKhGo
         W4nbHNtUHF/4tj1S8afJ2lUyfy7Tc8AmGVxQOeKq2X/jbtiQb0Ec0pDdPSSZrjLLb2Sf
         Q1b45jHbBgBP19O85VGuzGakTnaeUdUO2tTZlWRXRGsT05kpd3V/jMexwLGjP4qfP4G8
         /cjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cBgSBX+BgteTiVIKyAFTeKLIx8W4ON2ZbWr1HbcmNZw=;
        b=mSIABW/R/vkE0wqvVxIK+NQ1yM+P12I9DG1BagTpPD8V80ehEv7gQf0q3OMAhfGdZm
         xjOW8JHC4p1IlYkOOMX3LSx2GfrszbNwr9Mi5zTBSGFO1hl6f2ckuTfvC2iZeQQX5oYc
         BuC8x3Rtr7Nyc/uaNR+g6K1hvSWQacUOj4WTlB6ZCxWo6nSlS9+Hu0yIi5yarg/bl/oe
         VBs/LMMepLNwthC4IYRysoAe8aiqTyOM2ek52BNhkooMKgCFeQwFHaqcMepcQYTPWuU9
         voQHOaMRKSprmnXAQ+kAKUWT4N+7Zbqg2hOcykX59dz4jlA0nXR2pYILHEJbXT04wuCR
         3tXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kwaUKevD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id v6si189079ios.0.2019.12.12.13.12.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2019 13:12:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id o9so3508151ote.2
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2019 13:12:11 -0800 (PST)
X-Received: by 2002:a05:6830:1d6a:: with SMTP id l10mr10813196oti.233.1576185131062;
 Thu, 12 Dec 2019 13:12:11 -0800 (PST)
MIME-Version: 1.0
References: <20191126140406.164870-1-elver@google.com> <20191126140406.164870-3-elver@google.com>
 <00ee3b40-0e37-c9ac-3209-d07b233a0c1d@infradead.org> <20191203160128.GC2889@paulmck-ThinkPad-P72>
In-Reply-To: <20191203160128.GC2889@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Dec 2019 22:11:59 +0100
Message-ID: <CANpmjNOvDHoapk1cR5rCAcYgfVwf8NS0wFJncJ-bQrWzCKLPpw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=kwaUKevD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Tue, 3 Dec 2019 at 17:01, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, Dec 02, 2019 at 09:30:22PM -0800, Randy Dunlap wrote:
> > On 11/26/19 6:04 AM, Marco Elver wrote:
> > > Prefer __always_inline for fast-path functions that are called outside
> > > of user_access_save, to avoid generating UACCESS warnings when
> > > optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
> > > surprises with compiler versions that change the inlining heuristic even
> > > when optimizing for performance.
> > >
> > > Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> > > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested
>
> Thank you, Randy!

Hoped this would have applied by now, but since KCSAN isn't in
mainline yet, should I send a version of this patch rebased on
-rcu/kcsan?
It will just conflict with the style cleanup that is in
-tip/locking/kcsan when another eventual merge happens. Alternatively,
we can delay it for now and just have to remember to apply eventually
(and have to live with things being messy for a bit longer :-)).

The version as-is here applies on -tip/locking/kcsan and -next (which
merged -tip/locking/kcsan).

Thanks,
-- Marco


>                                                         Thanx, Paul
>
> > Thanks.
> >
> > > ---
> > > Rebased on: locking/kcsan branch of tip tree.
> > > ---
> > >  kernel/kcsan/atomic.h   |  2 +-
> > >  kernel/kcsan/core.c     | 16 +++++++---------
> > >  kernel/kcsan/encoding.h | 14 +++++++-------
> > >  3 files changed, 15 insertions(+), 17 deletions(-)
> > >
> > > diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> > > index 576e03ddd6a3..a9c193053491 100644
> > > --- a/kernel/kcsan/atomic.h
> > > +++ b/kernel/kcsan/atomic.h
> > > @@ -18,7 +18,7 @@
> > >   * than cast to volatile. Eventually, we hope to be able to remove this
> > >   * function.
> > >   */
> > > -static inline bool kcsan_is_atomic(const volatile void *ptr)
> > > +static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
> > >  {
> > >     /* only jiffies for now */
> > >     return ptr == &jiffies;
> > > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > > index 3314fc29e236..c616fec639cd 100644
> > > --- a/kernel/kcsan/core.c
> > > +++ b/kernel/kcsan/core.c
> > > @@ -78,10 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
> > >   */
> > >  static DEFINE_PER_CPU(long, kcsan_skip);
> > >
> > > -static inline atomic_long_t *find_watchpoint(unsigned long addr,
> > > -                                        size_t size,
> > > -                                        bool expect_write,
> > > -                                        long *encoded_watchpoint)
> > > +static __always_inline atomic_long_t *
> > > +find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
> > >  {
> > >     const int slot = watchpoint_slot(addr);
> > >     const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> > > @@ -146,7 +144,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
> > >   * 2. the thread that set up the watchpoint already removed it;
> > >   * 3. the watchpoint was removed and then re-used.
> > >   */
> > > -static inline bool
> > > +static __always_inline bool
> > >  try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
> > >  {
> > >     return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
> > > @@ -160,7 +158,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
> > >     return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
> > >  }
> > >
> > > -static inline struct kcsan_ctx *get_ctx(void)
> > > +static __always_inline struct kcsan_ctx *get_ctx(void)
> > >  {
> > >     /*
> > >      * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
> > > @@ -169,7 +167,7 @@ static inline struct kcsan_ctx *get_ctx(void)
> > >     return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
> > >  }
> > >
> > > -static inline bool is_atomic(const volatile void *ptr)
> > > +static __always_inline bool is_atomic(const volatile void *ptr)
> > >  {
> > >     struct kcsan_ctx *ctx = get_ctx();
> > >
> > > @@ -193,7 +191,7 @@ static inline bool is_atomic(const volatile void *ptr)
> > >     return kcsan_is_atomic(ptr);
> > >  }
> > >
> > > -static inline bool should_watch(const volatile void *ptr, int type)
> > > +static __always_inline bool should_watch(const volatile void *ptr, int type)
> > >  {
> > >     /*
> > >      * Never set up watchpoints when memory operations are atomic.
> > > @@ -226,7 +224,7 @@ static inline void reset_kcsan_skip(void)
> > >     this_cpu_write(kcsan_skip, skip_count);
> > >  }
> > >
> > > -static inline bool kcsan_is_enabled(void)
> > > +static __always_inline bool kcsan_is_enabled(void)
> > >  {
> > >     return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
> > >  }
> > > diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> > > index b63890e86449..f03562aaf2eb 100644
> > > --- a/kernel/kcsan/encoding.h
> > > +++ b/kernel/kcsan/encoding.h
> > > @@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
> > >                   (addr & WATCHPOINT_ADDR_MASK));
> > >  }
> > >
> > > -static inline bool decode_watchpoint(long watchpoint,
> > > -                                unsigned long *addr_masked,
> > > -                                size_t *size,
> > > -                                bool *is_write)
> > > +static __always_inline bool decode_watchpoint(long watchpoint,
> > > +                                         unsigned long *addr_masked,
> > > +                                         size_t *size,
> > > +                                         bool *is_write)
> > >  {
> > >     if (watchpoint == INVALID_WATCHPOINT ||
> > >         watchpoint == CONSUMED_WATCHPOINT)
> > > @@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
> > >  /*
> > >   * Return watchpoint slot for an address.
> > >   */
> > > -static inline int watchpoint_slot(unsigned long addr)
> > > +static __always_inline int watchpoint_slot(unsigned long addr)
> > >  {
> > >     return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
> > >  }
> > >
> > > -static inline bool matching_access(unsigned long addr1, size_t size1,
> > > -                              unsigned long addr2, size_t size2)
> > > +static __always_inline bool matching_access(unsigned long addr1, size_t size1,
> > > +                                       unsigned long addr2, size_t size2)
> > >  {
> > >     unsigned long end_range1 = addr1 + size1 - 1;
> > >     unsigned long end_range2 = addr2 + size2 - 1;
> > >
> >
> >
> > --
> > ~Randy
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOvDHoapk1cR5rCAcYgfVwf8NS0wFJncJ-bQrWzCKLPpw%40mail.gmail.com.
