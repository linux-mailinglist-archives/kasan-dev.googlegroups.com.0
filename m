Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLFUR7ZAKGQEJJ3EI7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id BD16A15A731
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 11:57:49 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id l19sf777060oil.7
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 02:57:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581505068; cv=pass;
        d=google.com; s=arc-20160816;
        b=yRPpiEoGtRYGMrZLC0Nn+CUwFJZ62mj8ZSs0uoL7XeHXqLARF1PHw3+ba8WRFeX1oG
         fOwDtp+WZODjEjbKpT+sy45eIQyrD8iJtFk1KjbSr+Or9Ncwohc+xoxs770x39Zbc39I
         Q0eSWH6AAjZMByuVGEyWwhhNfVkWE3dNmB3tx7iWwn4XxcJsQ6AATPoKXFm/AgWvlV3u
         VvajnGlZlQgfA76AWUnmGgLT81WMtpFRrBJeEPCf+YQPgjC1VczMfhkMRvS5t3rFmUb+
         Dl8+YHFXOrgP4raxE/xrTV35Aq+9OQIomaIEFYt4RBqggLro09ySwFkyYGvjWr/k+OFT
         BqeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ywM39I35BiZ+EaTkRPGM6bYs11bVtdS0lwL//8206AE=;
        b=EonQymiAWebbVgxQNpe6SW1Obc0DjpLHSLaXqJA74Gi7lssLcfBEZmf7E7av9oxGQx
         Cc6ho3v3kEMlxHZtfYM33fEg+KS5rBdVjAfJCNxAoVTb/Cs8lxWZtnc1A35jwEg3Hufb
         e9oPkLS40q5AjlyBZGH2bPdTbul3zohxQ3TES6wviv4tExl5oRNQgRqXxDYZEJgiTs+Z
         xQp57ugL2IsnjJzvRPn3mvEAJB6EoMnxosrIGnQoI7A29dDBQ+s6bsVaULoayLWfKwW+
         bVOVsRRkDHl0p1YQRjQ5A3uytNA3rbUUPGJ6VpPtICnvaXVh+gk5Pl07b/qMkwcsEpeH
         DXtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iirO+oAZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ywM39I35BiZ+EaTkRPGM6bYs11bVtdS0lwL//8206AE=;
        b=YKoF3Tlyj3OzbU4UIpQ9/01ReYC/5baf1fTFFeuNj6UOW0xlMcTP7VspU07QJATzyb
         LVPqy/r9sTLhfWHQg5ggz7IU0cE2NAx7bsYJsvEp3/fRxPjgF85KZ+3B4iA+zByGlvuz
         x3vPeW4JYapjDb6NeRWft+eVZaSycEVgqr1C9TAdX68k8GkaUHXxS3EE7dLhktWW0IUP
         uXWhOIA0YeGsH0GoaySfUXKWWHFXg8DcTsJJtYzhHlHoaOOxr7ZSVVyK3wfBX7IgbPzV
         NZ627NDp82C1xaUlr03uLbDrj5D/gqUiVp0WpFj7Jt/cnTsqNcHDVuWr7xUziK8FV8dG
         nsew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ywM39I35BiZ+EaTkRPGM6bYs11bVtdS0lwL//8206AE=;
        b=r7Pa7mUrNGlwrrtJzE+B1hpCfCV4jIK1z6JQPETWONBIpFStUgt5pZXj9rhNBMvDMD
         Mg4gXELK82MUpCX49poIVyBLtgxN7kmRueYt31xYJgmqkVHyMjNVHTcyJG+yDN4jamJh
         L8ePMG5UHCob4HazjoQ3BxkBjX8o5zlK3FvsDeFnrl+1D9a6xQIg9eIoduN3wYpeklUk
         W2EHTyijKMVsb/cUyHOf5DZ3NFJICpZwNu1HyfUbIyr+9ptI1mOb1ZV9rMEfNRJjFX2E
         Aqb24NLoGJwVOtgjcQRUsidpcLSKoA1vIbYDheZaRGJ7GGCc5tXSD5axiU24Nn9dYtHn
         44YQ==
X-Gm-Message-State: APjAAAXHMyx5j5eEyML4xUoVE4w66xbDceM+iLz67LrApCu5Onuaz1ce
	EOxQ4JFsRJfrQYkNDxSCq4M=
X-Google-Smtp-Source: APXvYqzAwS9u44A0XD5dykonyt5nXGxeRl9aRq4ksd5B7t9IyU61XNbWqxY8uPbPrem4PEuBALlwxw==
X-Received: by 2002:a9d:7410:: with SMTP id n16mr9057849otk.23.1581505068143;
        Wed, 12 Feb 2020 02:57:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5a87:: with SMTP id w7ls4349493oth.1.gmail; Wed, 12 Feb
 2020 02:57:47 -0800 (PST)
X-Received: by 2002:a9d:1c96:: with SMTP id l22mr1520147ota.322.1581505067751;
        Wed, 12 Feb 2020 02:57:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581505067; cv=none;
        d=google.com; s=arc-20160816;
        b=sg4tDe8g2f9Ovwm7asFSl6KOkBqIjiUK5U+xugc8OxHjFrTpubgAogTuvnNQUV2lfZ
         RSWxYOXAwRbXfb7KPFbPoNiuDhLYgpG2hQlZHeI6u//raJF/R8ZrcTpqiYXwfPlB7rzP
         zvlojzo1NwORAM+bvXRASfBEAZQb+eiQmv/vnGwP/hugPN34D+iw33feTxbRLtimEOK0
         4qNo+vqhRUDhAcrKWVRru4pYlrSdpm3eALOKvUfy7/p2plDImge25nxwy5YhVAu87hSX
         4N9TZqt9bRBn7rXHci5v2WRAREi48mOitzs+rXKMQbFx+e7lXSTBes20ePPY+EuxRcXt
         k1kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PFew8rKg4ZVQwTxQ3iTASZzMVyEkdsLW0wvz/USyjXc=;
        b=UIPV2wXD4q70a+fgrm9zi5inxv2jLokIdT+wXX9lQuOgkFnMplw+VhHgbfaY/Iwrmr
         Mb+pQVdSEaEDTSiGHD4nykFk1yeS+XtohlHxWPeOLMKmmqbVPJR1dNmOVErOqLQ6laq0
         7PiDHivDU8klDAc8Wp3XPaOI4MGx6jyu87CL9GaulYu5kyqQdJAYocMVsfI4iMiT0mV4
         s55ojECCF3l3xNmuQ9X/QeI5q1i6/YQKVSaIELq/Ma38uuERUnjpB2tziZXNKJ4/IRkI
         p+3tis423OwwplYZRwUaHN9FDyLwIgznLDx8ceeix/taC6SD2cSqzqviE1rKiTNlairM
         LLzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iirO+oAZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id d6si333147oig.4.2020.02.12.02.57.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 02:57:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id z2so1604237oih.6
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 02:57:47 -0800 (PST)
X-Received: by 2002:a05:6808:8d5:: with SMTP id k21mr5883820oij.121.1581505067174;
 Wed, 12 Feb 2020 02:57:47 -0800 (PST)
MIME-Version: 1.0
References: <20200211160423.138870-1-elver@google.com> <20200211160423.138870-5-elver@google.com>
 <29718fab-0da5-e734-796c-339144ac5080@nvidia.com>
In-Reply-To: <29718fab-0da5-e734-796c-339144ac5080@nvidia.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Feb 2020 11:57:36 +0100
Message-ID: <CANpmjNOWzWB2GgJiZx7c96qoy-e+BDFUx9zYr+1hZS1SUS7LBQ@mail.gmail.com>
Subject: Re: [PATCH v2 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
To: John Hubbard <jhubbard@nvidia.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iirO+oAZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Tue, 11 Feb 2020 at 22:41, John Hubbard <jhubbard@nvidia.com> wrote:
>
> On 2/11/20 8:04 AM, Marco Elver wrote:
> > This introduces ASSERT_EXCLUSIVE_BITS(var, mask).
> > ASSERT_EXCLUSIVE_BITS(var, mask) will cause KCSAN to assume that the
> > following access is safe w.r.t. data races (however, please see the
> > docbook comment for disclaimer here).
> >
> > For more context on why this was considered necessary, please see:
> >   http://lkml.kernel.org/r/1580995070-25139-1-git-send-email-cai@lca.pw
> >
> > In particular, before this patch, data races between reads (that use
> > @mask bits of an access that should not be modified concurrently) and
> > writes (that change ~@mask bits not used by the readers) would have been
> > annotated with "data_race()" (or "READ_ONCE()"). However, doing so would
> > then hide real problems: we would no longer be able to detect harmful
> > races between reads to @mask bits and writes to @mask bits.
> >
> > Therefore, by using ASSERT_EXCLUSIVE_BITS(var, mask), we accomplish:
> >
> >   1. Avoid proliferation of specific macros at the call sites: by
> >      including a single mask in the argument list, we can use the same
> >      macro in a wide variety of call sites, regardless of how and which
> >      bits in a field each call site actually accesses.
> >
> >   2. The existing code does not need to be modified (although READ_ONCE()
> >      may still be advisable if we cannot prove that the data race is
> >      always safe).
> >
> >   3. We catch bugs where the exclusive bits are modified concurrently.
> >
> >   4. We document properties of the current code.
>
>
> API looks good to me. (I'm not yet familiar enough with KCSAN to provide
> any useful review of about the various kcsan*() calls that implement the
> new macro.)
>
> btw, it might be helpful for newcomers if you mentioned which tree this
> is based on. I poked around briefly and failed several times to find one. :)

KCSAN is currently in -rcu (kcsan branch has the latest version),
-tip, and -next.

> You can add:
>
> Acked-by: John Hubbard <jhubbard@nvidia.com>

Thank you!
-- Marco

>
> thanks,
> --
> John Hubbard
> NVIDIA
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: David Hildenbrand <david@redhat.com>
> > Cc: Jan Kara <jack@suse.cz>
> > Cc: John Hubbard <jhubbard@nvidia.com>
> > Cc: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Qian Cai <cai@lca.pw>
> > ---
> > v2:
> > * Update API documentation to be clearer about how this compares to the
> >   existing assertions, and update use-cases. [Based on suggestions from
> >   John Hubbard]
> > * Update commit message. [Suggestions from John Hubbard]
> > ---
> >  include/linux/kcsan-checks.h | 69 ++++++++++++++++++++++++++++++++----
> >  kernel/kcsan/debugfs.c       | 15 +++++++-
> >  2 files changed, 77 insertions(+), 7 deletions(-)
> >
> > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > index 4ef5233ff3f04..1b8aac5d6a0b5 100644
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
> > @@ -191,4 +191,61 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> >  #define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> >       __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> >
> > +/**
> > + * ASSERT_EXCLUSIVE_BITS - assert no concurrent writes to subset of bits in @var
> > + *
> > + * Bit-granular variant of ASSERT_EXCLUSIVE_WRITER(var).
> > + *
> > + * Assert that there are no concurrent writes to a subset of bits in @var;
> > + * concurrent readers are permitted. This assertion captures more detailed
> > + * bit-level properties, compared to the other (word granularity) assertions.
> > + * Only the bits set in @mask are checked for concurrent modifications, while
> > + * ignoring the remaining bits, i.e. concurrent writes (or reads) to ~@mask bits
> > + * are ignored.
> > + *
> > + * Use this for variables, where some bits must not be modified concurrently,
> > + * yet other bits are expected to be modified concurrently.
> > + *
> > + * For example, variables where, after initialization, some bits are read-only,
> > + * but other bits may still be modified concurrently. A reader may wish to
> > + * assert that this is true as follows:
> > + *
> > + *   ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
> > + *   foo = (READ_ONCE(flags) & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
> > + *
> > + *   Note: The access that immediately follows ASSERT_EXCLUSIVE_BITS() is
> > + *   assumed to access the masked bits only, and KCSAN optimistically assumes it
> > + *   is therefore safe, even in the presence of data races, and marking it with
> > + *   READ_ONCE() is optional from KCSAN's point-of-view. We caution, however,
> > + *   that it may still be advisable to do so, since we cannot reason about all
> > + *   compiler optimizations when it comes to bit manipulations (on the reader
> > + *   and writer side). If you are sure nothing can go wrong, we can write the
> > + *   above simply as:
> > + *
> > + *   ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
> > + *   foo = (flags & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
> > + *
> > + * Another example, where this may be used, is when certain bits of @var may
> > + * only be modified when holding the appropriate lock, but other bits may still
> > + * be modified concurrently. Writers, where other bits may change concurrently,
> > + * could use the assertion as follows:
> > + *
> > + *   spin_lock(&foo_lock);
> > + *   ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
> > + *   old_flags = READ_ONCE(flags);
> > + *   new_flags = (old_flags & ~FOO_MASK) | (new_foo << FOO_SHIFT);
> > + *   if (cmpxchg(&flags, old_flags, new_flags) != old_flags) { ... }
> > + *   spin_unlock(&foo_lock);
> > + *
> > + * @var variable to assert on
> > + * @mask only check for modifications to bits set in @mask
> > + */
> > +#define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \
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
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29718fab-0da5-e734-796c-339144ac5080%40nvidia.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOWzWB2GgJiZx7c96qoy-e%2BBDFUx9zYr%2B1hZS1SUS7LBQ%40mail.gmail.com.
