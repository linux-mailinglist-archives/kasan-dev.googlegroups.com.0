Return-Path: <kasan-dev+bncBAABBR67SHZAKGQE6D3XDPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id B390815B2D6
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 22:36:08 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id w4sf2112621pjt.5
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 13:36:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581543367; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZ/GEfkLnzqBPhAOh2nJYQlW1s7a2etUsdGjG4Hg40JskZOc/g7URLdoeJaI2hF9OM
         RlNDAjyjfDzHPTlzhxnOiy7XLwtoftDdl8Zd7DZWjxgKob3r+bhBlAXSsX0SRdbCP6h3
         N4pgD3kaLtZkiJZ/F+7+2le+s9enfBcPQ/91yehxuQ9QbMJKO3BkVheddQCTahW/wVpp
         IYw8gRV9g8Sw3iH0fxI3wp8U6QfmltX2yFUmk8SYhNINJDT2W7MbM4Mj97fLTDKwDhAD
         YXwj8uZMmt8IdkKOjb94/dY514PvBUW9VWwam/Vc1fqNtK1DV73x7vwpxNB+dY0wMyEm
         pnBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=am+770HKuGsCPai1kvAG89IuDrg+TZjOO4hYoz35z8Q=;
        b=bi733W1vjb+7Z3g9Lb9yn+ZuMEu5kdMF8pW1W13nbB5UseRVXXGjyR0OM9mxlQSmIK
         wRArLnOU56qetKYnhHcT1lswn2XtvyUPlH3cXct0bqOa25nB4/S9zLzXNN/AOt/+biv0
         R98lV3P52VGvZFVIGOpmzG5vhSH7eGGO4kxYWQmX+QHCs9ZwDoFwlmLuzfXTV3KlVjqA
         69hr2XKqzCnGGQnu0iwML2y6qHjNoKTcXeHaAA/8VnE0YEwIBuTsqAmVfRLUwNldAYTC
         p+ZR56wnqzzvPA3twhMrgIg/tCx0zfEiKERE9bvjkQKdKaTtr2z10h5pkJbjEHv/NlyT
         BoDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=biKeEXQe;
       spf=pass (google.com: domain of srs0=uvu3=4a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=uvu3=4A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=am+770HKuGsCPai1kvAG89IuDrg+TZjOO4hYoz35z8Q=;
        b=cfZBJD7EW74P9ka3Wr7e29In5ENXOGWHLC605H5MvO+1fJKFsUEFg1MzAxUdBAh+A0
         QSxD4OGGmM0ZF9uKM7oP8PYQ9Fu8uPYOGo6t58dSNi1kM5fBX1RKBBPNmFnxPNNnszO5
         wQjujtVtv4mK4vclU6LAGLr3TuHBjWYPr4OcqY4MEtu+lmf6bUAtOGDlhl+s/XvHbQFx
         QHnmDWoJ2Pnq3XbIGoyrzTOjzPnBY5WMZsoKkhD46VOa4tjT1DTk3uOAjSRq+FQhTCiD
         6+hT9nEA+7n+ggxA8KewnKeivPe6VOqk0IGVBxuvVQQ3KnWkgyHQuP9uiW7jwO3Pdrpc
         +zgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=am+770HKuGsCPai1kvAG89IuDrg+TZjOO4hYoz35z8Q=;
        b=eiE6yLUFKx6ZIi6v+KlpkaJTg1vvZg6hW3F1bH7imOq/mPeItg6WDBBr37vdacGCoc
         Gwpb5x6/deDP8FHwp4NEn9QN8ruqezfppzQucfNHDgSO2Ndh/dlE2r5sgfYNw1nRIeMb
         XDLNO7pvYNDCShIs9FW7H12HJXurMBM+4uqP198pYWHPQNjaAlk1QHW5HJMnpABKuGGe
         M0QG+6p0eNyd2dX+6VUfHL9KkTsMgmYbvETsyXvBPwK1iI2IT34BVGS30pucq9kqfu2t
         jQm2XG45k6/5wl0ln3tzkZeG5O0lEYKrarh0tzogMhf5JN/GT/K4O3OYUBc6GDxDpuAK
         CULA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9FCg1/KEaSPoyGPVw7ow6799NF9pqxhbbKH9l64oF+Yzfbc4T
	udJqijMWYfIsmDGIfeBbrCA=
X-Google-Smtp-Source: APXvYqwWE2GTN5Ul2SpUIrxO2eDAqLw5C9PH6CnhOmTyHouiqWynf63k0i5HzSGAImfsa2OBdsf7fg==
X-Received: by 2002:a63:c304:: with SMTP id c4mr14870900pgd.85.1581543367052;
        Wed, 12 Feb 2020 13:36:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ed49:: with SMTP id m9ls5618365pgk.0.gmail; Wed, 12 Feb
 2020 13:36:06 -0800 (PST)
X-Received: by 2002:a65:6454:: with SMTP id s20mr4548916pgv.386.1581543366626;
        Wed, 12 Feb 2020 13:36:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581543366; cv=none;
        d=google.com; s=arc-20160816;
        b=MPSjGh9lOad3cA86mctmqIqrtfszIBLXBWXgCHeg4PXAEXWaAUhTYLqRjkhPPcD8LL
         mTe3SfSQu9GRsGr6ed9KHmepEfJAdRGcizkkZE8YqTk67alaJNYA6aQ5u7JDdq9ac38a
         Y/lQVzQodnUHBRZQ51fuLCT4vLJ1uv3YDGQIf8Dv+vi4+c3jg5s8UUn+pB9dnbKu3R9L
         l2i+942xuteIxFSFtFPreKLpTRx7snkBmn1JS5Qr5rrqW0LN/uGeS+1BPBW9D3U++9ip
         g2i8Qb9kqi7p2RTEwCg07cliUzlgGtuneZNJvTztFRYYCThF7sW+bKWVGi3v3W1zDTv6
         LvGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=m33BDIXptp5RKNn5OffdPN8u4pCFw4h1Ns0xvUpev0Q=;
        b=sK48I30l0qYXkC5R/Nx9jSzFwDLCYN2lemZ9msSKiDjxBqc9GBZ0QI+8KFfgQSRZF2
         ttVEk78AsGMHSE1Y2ihkfvMPYUtQtvxdEbKg/1+1qpnXGZMRdEhoqEwFYTKrt4B7S0Jc
         fenEiwZEZkmwduGr7OSHA0Dwn9eqUPS2O22aYiqfoh3fROxfxjfVe0MowojoL9FpDBGj
         4ekhqIVA9EXFAJJ+o14LFoUP9nN7zNti9D6HEdMBniUTPUCHgwUSjWAO1xC87/Dk1gjM
         Jub8vtGUOeqHkdqEuCzq6Jtb2LIukv52zoHcAMN3FBQ4PSC8IhAC7geTJAlMY1ucqqrS
         0mOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=biKeEXQe;
       spf=pass (google.com: domain of srs0=uvu3=4a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=uvu3=4A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a4si217853pje.1.2020.02.12.13.36.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Feb 2020 13:36:06 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=uvu3=4a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [62.84.152.189])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 0416424671;
	Wed, 12 Feb 2020 21:36:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 530AE3522725; Wed, 12 Feb 2020 13:36:04 -0800 (PST)
Date: Wed, 12 Feb 2020 13:36:04 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: John Hubbard <jhubbard@nvidia.com>
Cc: Marco Elver <elver@google.com>, andreyknvl@google.com,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>,
	Qian Cai <cai@lca.pw>
Subject: Re: [PATCH v2 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
Message-ID: <20200212213604.GR2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200211160423.138870-1-elver@google.com>
 <20200211160423.138870-5-elver@google.com>
 <29718fab-0da5-e734-796c-339144ac5080@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <29718fab-0da5-e734-796c-339144ac5080@nvidia.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=biKeEXQe;       spf=pass
 (google.com: domain of srs0=uvu3=4a=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=uvu3=4A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Feb 11, 2020 at 01:41:14PM -0800, John Hubbard wrote:
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
> 
> You can add:
> 
> Acked-by: John Hubbard <jhubbard@nvidia.com>

Queued for testing and further review, thank you both!

							Thanx, Paul

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
> >  	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
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
> >  	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
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
> > + *	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
> > + *	foo = (READ_ONCE(flags) & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
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
> > + * 	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
> > + *	foo = (flags & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
> > + *
> > + * Another example, where this may be used, is when certain bits of @var may
> > + * only be modified when holding the appropriate lock, but other bits may still
> > + * be modified concurrently. Writers, where other bits may change concurrently,
> > + * could use the assertion as follows:
> > + *
> > + *	spin_lock(&foo_lock);
> > + *	ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
> > + *	old_flags = READ_ONCE(flags);
> > + *	new_flags = (old_flags & ~FOO_MASK) | (new_foo << FOO_SHIFT);
> > + *	if (cmpxchg(&flags, old_flags, new_flags) != old_flags) { ... }
> > + *	spin_unlock(&foo_lock);
> > + *
> > + * @var variable to assert on
> > + * @mask only check for modifications to bits set in @mask
> > + */
> > +#define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \
> > +	do {                                                                   \
> > +		kcsan_set_access_mask(mask);                                   \
> > +		__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT);\
> > +		kcsan_set_access_mask(0);                                      \
> > +		kcsan_atomic_next(1);                                          \
> > +	} while (0)
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
> > +	const long CHANGE_BITS = 0xff00ff00ff00ff00L;
> >  	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
> >  	cycles_t cycles;
> >  
> > @@ -109,16 +111,27 @@ static noinline void test_thread(unsigned long iters)
> >  	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
> >  
> >  	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
> > +	pr_info("test_dummy@%px, test_flags@%px\n", &test_dummy, &test_flags);
> >  
> >  	cycles = get_cycles();
> >  	while (iters--) {
> > +		/* These all should generate reports. */
> >  		__kcsan_check_read(&test_dummy, sizeof(test_dummy));
> > -		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
> >  		ASSERT_EXCLUSIVE_WRITER(test_dummy);
> >  		ASSERT_EXCLUSIVE_ACCESS(test_dummy);
> >  
> > +		ASSERT_EXCLUSIVE_BITS(test_flags, ~CHANGE_BITS); /* no report */
> > +		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
> > +
> > +		ASSERT_EXCLUSIVE_BITS(test_flags, CHANGE_BITS); /* report */
> > +		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
> > +
> >  		/* not actually instrumented */
> >  		WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
> > +		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
> > +
> > +		test_flags ^= CHANGE_BITS; /* generate value-change */
> > +		__kcsan_check_write(&test_flags, sizeof(test_flags));
> >  	}
> >  	cycles = get_cycles() - cycles;
> >  
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200212213604.GR2935%40paulmck-ThinkPad-P72.
