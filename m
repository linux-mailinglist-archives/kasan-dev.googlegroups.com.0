Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZVCRPZAKGQE5FNJB3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5087C15946B
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 17:08:07 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id i1sf3633980vkn.9
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 08:08:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581437286; cv=pass;
        d=google.com; s=arc-20160816;
        b=NFZ+sU0S800eve6YBeDVG0hvibkEGO6JC7S9GcN82qf1hPicm5ijTIhO0CKYO+OOZp
         HkTEnRoKpv0rcOQcCHihil9tcgrarUx9w019hy28j+KfVshwf+9dKok9yrx5iMOT/Ove
         g7iTYKrB/QaG0+BoR/TLjuvPIZBHeYDzXv4yEMlTm37Ercz8Mvxa45KHVygU4fem1cp9
         EQOkhAX8T0RA/9eJsUbHShtwqdlPZ8f1JQ2qI8q01amKHi1g9euw7dO/PCfVWwAf3lBV
         RcTDGMXdwD1yojliiLuEcn2ACIS0jtJ0CezPDrw238MKrtK1ZJp9jVzFYDn+7yV2Pk2+
         3dZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+kV+6nlMxtJR4AvQBup3Vm8KNCPpAUgOX4QYBSOljrw=;
        b=v3GDJRGSJ5bAHKFzibzcDQ67r3jVtgjjV4z8q0pdqozH28EeoJrjqRgb++20ScO8bI
         ifYNViLR4bPgvZ7YsXjVsiS/dMdYgXZ1t5M9P77fQz3GfCZE8bpS/il3Uxpcb9IcLwGr
         ioZYJ38kEw/KtnNyfd8FhyOWXFV/3DUimu9oFz0ReKGe+PNyWqMcARJNFt2m1NpUnBqb
         lwmwmGExWsdUMOBtqVXY3puwjecAMwe6Z2X7vYqQNXDqNPTcvIzwwvq6JJzQTdoJtcQf
         68g2BAzU3tDEhMhG+5oiNCoHWDgCGe2wkjcYXWj6sDRsZ4hwlGUIOYDffT2/59tqOVDt
         4mZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="i2/994BZ";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+kV+6nlMxtJR4AvQBup3Vm8KNCPpAUgOX4QYBSOljrw=;
        b=SIFJnt5O6OYRCLsLrqZraTx/0PIYJ1knjg2V7EL7Ih+clM5DYjK7WraglKBooznKfR
         fylUXX3/DqjeYuibal5cCYgPVXPDnFg82QyUhOhF2BIAp25bTAJSKswqneqSmyKAxMYH
         ro7lqMGdeOu7ztKKNLlJVjX/pPUWicHsdhNbUMpy0Sb1qbma1N4HIMWWXJYR2O5w2/WK
         uPRRzm+4Xz0Ypl0zZM71+sVpQBvj2H4ZiLcf0NWwuHsY7DGgbFBDKIqx7ptbU698g8bL
         4Vdj74sGF4AV4xdHHmeUDmbACjniGdd9+bZS8jAHDFEBSP0HViFmLAvpjIHJpStN6Di0
         82iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+kV+6nlMxtJR4AvQBup3Vm8KNCPpAUgOX4QYBSOljrw=;
        b=jcj8S42nEskZrjF+qptfguJWjgUb43kVwJIfoOyKtgzQQyE7MpqRxUJOAfdTQp2R/q
         Lc/GSNNv4p3WtfNwzLNP80TiNKvLEUPobh9AkgVhsIoWaNPmg9xyZnGnAR4fGxzTU/Mx
         mKj8hfwnWQkje+Ds4JH6LcGVA26ZBUW6+C35LoYVnO5OIo0R8us7TF607Fp7CqdoawTK
         veFJ3C3oeqgOVA+WbHY9GUlqGNCKxftpQnYYiSDr/ecVHiRhCkgo1Yg8kbcpZKg5qGge
         PvGXoZgTy8cx/l/NwTJ5ebWZZOYNVCjgQz4ZDLBdXNFvri3L83RFJLS50Sv7OLWJbLUb
         677g==
X-Gm-Message-State: APjAAAXKJayUt4ZKIf9sdoMqqQrhnKsbyuu1nvv+KZ6YcL4u5rgcZsNb
	8XWFyZeoJJtbrgDp3YInOzA=
X-Google-Smtp-Source: APXvYqzgLXwFWih/6VG79dCIjEZkUitj9qr2geekQXSM5l15UJ3lRfYXn9F+EOBEbhAcN5DXoLcqnw==
X-Received: by 2002:ab0:3381:: with SMTP id y1mr1923977uap.93.1581437286278;
        Tue, 11 Feb 2020 08:08:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:cd2a:: with SMTP id a10ls551137vkm.4.gmail; Tue, 11 Feb
 2020 08:08:05 -0800 (PST)
X-Received: by 2002:ac5:c97c:: with SMTP id t28mr5311015vkm.20.1581437285885;
        Tue, 11 Feb 2020 08:08:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581437285; cv=none;
        d=google.com; s=arc-20160816;
        b=gwMrOjaKMfgJBlB2ey+xsGhgSr9qFw8VNHwDTuVn8fWB+rm911RUF7ZTcOfSvNcCGK
         hct5Z0yo0Opc2NwKD/Ylb1ghY8k2ixQ4eLBidyk4gC88MuCYdCA0ouO8wX/8QP1wLU9g
         nzFSGX6uUF2HFDZIsbBK/y8W9LdDAssYE+9QGxc70KUFu3bS1drjp1KpUHo5+nvNNysz
         9I+exlcKo5XKqnefIEMkJ4UGeDWJFzgcy/QGm84LpBC/X4cgaHyCOLGP31djUvIohCsK
         6Loj0eufV7+ko+nVZhatd4/wt1IhVicbsNkAqFbyHluBV0W4gejZnFhhs3mybuhcnz0o
         FQqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9hnUT6qESAq7DlFLNCIERdoa2al8Z8MvMWl2WRSW1VA=;
        b=GIMADEYrHJ5SW8fiV7PV4IOO6yOvgkS85fa06/ru/Y/psbCczOlXrhdRV9tuRODt/J
         9/kRzQ3q3/g4xuz0tbwW1wo+lGU8aX+v8LbSABMB1vAvw7fpUyedxE+NH6zZ7FUZFzt1
         hSWXjzkxF0DWwBFXEwOnELvWNrfl28HZJjrxsMQfsXxWqBWKmDtAIm+k3gbuKe7NLaRN
         lzCaiU2AAgx0u3Bdb8fV7woqVg9/cLgLu0qXZhoCq7btxjg4I9L2NwQjQZD4pfIT6LB+
         QkfEZgJ4dPvVQuOfs3Ghe2TYjbALMKUW6G2+ZdGdR4xPlN3Akm5zCamwERRvaipUFZtH
         8RKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="i2/994BZ";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id h7si245810vsm.1.2020.02.11.08.08.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 08:08:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id i6so10589895otr.7
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 08:08:05 -0800 (PST)
X-Received: by 2002:a9d:7f12:: with SMTP id j18mr6082544otq.17.1581437285234;
 Tue, 11 Feb 2020 08:08:05 -0800 (PST)
MIME-Version: 1.0
References: <20200210184317.233039-1-elver@google.com> <20200210184317.233039-5-elver@google.com>
 <3963b39c-bdc9-d188-a086-f5ea443477d1@nvidia.com>
In-Reply-To: <3963b39c-bdc9-d188-a086-f5ea443477d1@nvidia.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Feb 2020 17:07:53 +0100
Message-ID: <CANpmjNNJbt3HRg-CNw8w5jnfNzU0hNqd8Y-r1J9_H0o83MvO5w@mail.gmail.com>
Subject: Re: [PATCH 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
To: John Hubbard <jhubbard@nvidia.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="i2/994BZ";       spf=pass
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

v2: https://lore.kernel.org/lkml/20200211160423.138870-5-elver@google.com/

On Mon, 10 Feb 2020 at 22:07, John Hubbard <jhubbard@nvidia.com> wrote:
>
> On 2/10/20 10:43 AM, Marco Elver wrote:
> > This introduces ASSERT_EXCLUSIVE_BITS(var, mask).
> > ASSERT_EXCLUSIVE_BITS(var, mask) will cause KCSAN to assume that the
> > following access is safe w.r.t. data races (however, please see the
> > docbook comment for disclaimer here).
> >
> > For more context on why this was considered necessary, please see:
> >   http://lkml.kernel.org/r/1580995070-25139-1-git-send-email-cai@lca.pw
> >
> > In particular, data races between reads (that use @mask bits of an
> > access that should not be modified concurrently) and writes (that change
> > ~@mask bits not used by the read) should ordinarily be marked. After
> > marking these, we would no longer be able to detect harmful races
> > between reads to @mask bits and writes to @mask bits.
>
> I know this is "just" the commit log, but as long as I'm reviewing the
> whole thing...to make the above a little clearer, see if you like this
> revised wording:
>
> In particular, before this patch, data races between reads (that use
> @mask bits of an access that should not be modified concurrently) and
> writes (that change ~@mask bits not used by the readers) would have
> been annotated with "data_race()". However, doing so would then hide
> real problems: we would no longer be able to detect harmful races
> between reads to @mask bits and writes to @mask bits.

Thanks, applied.

> >
> > Therefore, by using ASSERT_EXCLUSIVE_BITS(var, mask), we accomplish:
> >
> >   1. No new macros introduced elsewhere; since there are numerous ways in
> >      which we can extract the same bits, a one-size-fits-all macro is
> >      less preferred.
>
> This somehow confuses me a lot. Maybe say it like this:
>
> 1. Avoid a proliferation of specific macros at the call sites: by including a
>    mask in the argument list, we can use the same macro in a wide variety of
>    call sites, regardless of which bits in a field each call site uses.
>
> ?

Thanks, I took that mostly as-is.

> >
> >   2. The existing code does not need to be modified (although READ_ONCE()
> >      may still be advisable if we cannot prove that the data race is
> >      always safe).
> >
> >   3. We catch bugs where the exclusive bits are modified concurrently.
> >
> >   4. We document properties of the current code.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: David Hildenbrand <david@redhat.com>
> > Cc: Jan Kara <jack@suse.cz>
> > Cc: John Hubbard <jhubbard@nvidia.com>
> > Cc: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Qian Cai <cai@lca.pw>
> > ---
> >  include/linux/kcsan-checks.h | 57 ++++++++++++++++++++++++++++++++----
> >  kernel/kcsan/debugfs.c       | 15 +++++++++-
> >  2 files changed, 65 insertions(+), 7 deletions(-)
> >
> > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > index 4ef5233ff3f04..eae6030cd4348 100644
> > --- a/include/linux/kcsan-checks.h
> > +++ b/include/linux/kcsan-checks.h
> > @@ -152,9 +152,9 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> >  #endif
> >
> >  /**
> > - * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> > + * ASSERT_EXCLUSIVE_WRITER - assert no concurrent writes to @var
> >   *
> > - * Assert that there are no other threads writing @var; other readers are
> > + * Assert that there are no concurrent writes to @var; other readers are
> >   * allowed. This assertion can be used to specify properties of concurrent code,
> >   * where violation cannot be detected as a normal data race.
> >   *
> > @@ -171,11 +171,11 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> >       __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
> >
> >  /**
> > - * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> > + * ASSERT_EXCLUSIVE_ACCESS - assert no concurrent accesses to @var
> >   *
> > - * Assert that no other thread is accessing @var (no readers nor writers). This
> > - * assertion can be used to specify properties of concurrent code, where
> > - * violation cannot be detected as a normal data race.
> > + * Assert that there are no concurrent accesses to @var (no readers nor
> > + * writers). This assertion can be used to specify properties of concurrent
> > + * code, where violation cannot be detected as a normal data race.
> >   *
> >   * For example, in a reference-counting algorithm where exclusive access is
> >   * expected after the refcount reaches 0. We can check that this property
> > @@ -191,4 +191,49 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> >  #define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> >       __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> >
> > +/**
> > + * ASSERT_EXCLUSIVE_BITS - assert no concurrent writes to subset of bits in @var
> > + *
> > + * [Bit-granular variant of ASSERT_EXCLUSIVE_WRITER(var)]
>
>
> No need for the square brackets, unless that's some emerging convention in the
> documentation world.

Done.

>
> > + *
> > + * Assert that there are no concurrent writes to a subset of bits in @var;
> > + * concurrent readers are permitted. Concurrent writes (or reads) to ~@mask bits
> > + * are ignored. This assertion can be used to specify properties of concurrent
> > + * code, where marked accesses imply violations cannot be detected as a normal
> > + * data race.
>
>
> How about this wording:
>
> /*
>  * Assert that there are no concurrent writes to a subset of bits in @var;
>  * concurrent readers are permitted. Concurrent writes (or reads) to ~@mask bits
>  * are ignored. This assertion provides more detailed, bit-level information to
>  * the KCSAN system than most of the other (word granularity) annotations. As
>  * such, it allows KCSAN to safely overlook some bits while still continuing to
>  * check the remaining bits for unsafe access patterns.
>  *
>  * Use this if you have some bits that are read-only, and other bits that are
>  * not, within a variable.
>  */
>
> ?

I've updated it based on the information you want to convey here. I've
removed mention to KCSAN in the first paragraph, since KCSAN is an
implementation of this, but a user of the API shouldn't care too much
about that.

Hopefully it makes more sense in v2.

>
> > + *
> > + * For example, this may be used when certain bits of @var may only be modified
> > + * when holding the appropriate lock, but other bits may still be modified
> > + * concurrently. Writers, where other bits may change concurrently, could use
> > + * the assertion as follows:
> > + *
> > + *   spin_lock(&foo_lock);
> > + *   ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
> > + *   old_flags = READ_ONCE(flags);
> > + *   new_flags = (old_flags & ~FOO_MASK) | (new_foo << FOO_SHIFT);
> > + *   if (cmpxchg(&flags, old_flags, new_flags) != old_flags) { ... }
> > + *   spin_unlock(&foo_lock);
> > + *
> > + * Readers, could use it as follows:
> > + *
> > + *   ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
> > + *   foo = (READ_ONCE(flags) & FOO_MASK) >> FOO_SHIFT;
>
>
> In the general case (which is what this documentation covers), the
> READ_ONCE() is not required. So this should either leave it out, or
> explain that it's not necessarily required.

I've updated the example to lead to the fact you can omit the
READ_ONCE. However, I want to be very careful here, since I still
can't prove to myself no compiler will mess this up. In the general
case, we likely won't need the READ_ONCE, because you'd need a pretty
unfortunate compiler + architecture combo to mess this up for you. But
you never know.

Thanks,
-- Marco

>
> > + *
> > + * NOTE: The access that immediately follows is assumed to access the masked
> > + * bits only, and safe w.r.t. data races. While marking this access is optional
> > + * from KCSAN's point-of-view, it may still be advisable to do so, since we
> > + * cannot reason about all possible compiler optimizations when it comes to bit
> > + * manipulations (on the reader and writer side).
> > + *
> > + * @var variable to assert on
> > + * @mask only check for modifications to bits set in @mask
> > + */
> > +#define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \
>
>
> This API looks good to me.
>
>
> > +     do {                                                                   \
> > +             kcsan_set_access_mask(mask);                                   \
> > +             __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT);\
> > +             kcsan_set_access_mask(0);                                      \
> > +             kcsan_atomic_next(1);                                          \
> > +     } while (0)
> > +
> >  #endif /* _LINUX_KCSAN_CHECKS_H */
> > diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> > index 9bbba0e57c9b3..2ff1961239778 100644
> > --- a/kernel/kcsan/debugfs.c
> > +++ b/kernel/kcsan/debugfs.c
> > @@ -100,8 +100,10 @@ static noinline void microbenchmark(unsigned long iters)
> >   * debugfs file from multiple tasks to generate real conflicts and show reports.
> >   */
> >  static long test_dummy;
> > +static long test_flags;
> >  static noinline void test_thread(unsigned long iters)
> >  {
> > +     const long CHANGE_BITS = 0xff00ff00ff00ff00L;
> >       const struct kcsan_ctx ctx_save = current->kcsan_ctx;
> >       cycles_t cycles;
> >
> > @@ -109,16 +111,27 @@ static noinline void test_thread(unsigned long iters)
> >       memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
> >
> >       pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
> > +     pr_info("test_dummy@%px, test_flags@%px\n", &test_dummy, &test_flags);
> >
> >       cycles = get_cycles();
> >       while (iters--) {
> > +             /* These all should generate reports. */
> >               __kcsan_check_read(&test_dummy, sizeof(test_dummy));
> > -             __kcsan_check_write(&test_dummy, sizeof(test_dummy));
> >               ASSERT_EXCLUSIVE_WRITER(test_dummy);
> >               ASSERT_EXCLUSIVE_ACCESS(test_dummy);
> >
> > +             ASSERT_EXCLUSIVE_BITS(test_flags, ~CHANGE_BITS); /* no report */
> > +             __kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
> > +
> > +             ASSERT_EXCLUSIVE_BITS(test_flags, CHANGE_BITS); /* report */
> > +             __kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
> > +
> >               /* not actually instrumented */
> >               WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
> > +             __kcsan_check_write(&test_dummy, sizeof(test_dummy));
> > +
> > +             test_flags ^= CHANGE_BITS; /* generate value-change */
> > +             __kcsan_check_write(&test_flags, sizeof(test_flags));
> >       }
> >       cycles = get_cycles() - cycles;
> >
> >
>
>
>
> thanks,
> --
> John Hubbard
> NVIDIA

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNJbt3HRg-CNw8w5jnfNzU0hNqd8Y-r1J9_H0o83MvO5w%40mail.gmail.com.
