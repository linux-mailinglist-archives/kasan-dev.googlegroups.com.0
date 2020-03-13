Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMPDV3ZQKGQE2IXHL5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id D2FF2184C25
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Mar 2020 17:15:46 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id e16sf7933880qvr.16
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Mar 2020 09:15:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584116146; cv=pass;
        d=google.com; s=arc-20160816;
        b=mM0LAB2UoiB2SWwulYPoKrW3DdYXCBXZOU2iTol+xl07J+uKIQsMxMyqt1VhniHF1f
         CWx2oH6yPOLIx2tslGyPYI8657ZSDsUIR6Rqt0XODMk778WM05gjnM/NJgn4e2tzmvbJ
         eEft/KElqTyYVqPqvizNwu6wmxApkMlT0SGs0dB+z1SW2B3YMfR8qUK0DLY+0nl1e9wQ
         9dhggptcicutZsOfnk6+EeubpShT865obN9IiT4YGyr1KGB4Rnlcrc0XA1Lae/YU6nMy
         P6zNhMybDgIApXCc3OxdFSVVEDu0/RIGqWlqiwBIp0ZL/Kzx1TJG5R2LV4JHhyvntTW7
         h6uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O9sxvUGgNy4kR0KvJnvDcmevXP+zDVywecO7mgESs9U=;
        b=SdCRMbfp/lDApH/Y+CfU6eMumbm2VTy2gxpZ/BVb0fxsIJXUfetcn/SJ/3EFRm1yM3
         FvNVIN2l9sEp9iDJw4Y/HeVNEOv9INs9C2bN75KvuEcxfgHK0SwNUDrukiSqAoyfjns5
         0RmupEHDDvs2I8svKI50kj8soo2h7Ez9cU3Y+somUVTRVgug5VP+VjEWPU4ZUzuYGYSJ
         fHFjanqzuasTzlHMB+7R73KX8UEs7GNuMAnzCkYjE1Q3RmX+ycYyGLqSUqLL7NqwfFf6
         EZEJNd8ljMEphtgStbBTIm/U5Z+H2E88fTvIinPEFT1LsrNzL4iRQiTiWbZq33LTutPB
         Tn/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ggK3KIuW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O9sxvUGgNy4kR0KvJnvDcmevXP+zDVywecO7mgESs9U=;
        b=gIBAIHGHGJ0K6uonlDxWwC4rhMfyo77MaO66MUgohA+ibwSCYWVlosO8gsbp5fqVS1
         l9jXI2f8XQYMW1Fscf0gCW/NtKBcZM/R/212v0OpVjvMolj/AqElEs7MMYjXWbmHo77o
         J+cDCUMfUMseM7J1g4LPXHIazE3XVrRG/9M1W9gKjFuqKVMy0Kt0lYR2ZuAHEnDDsWqP
         XGNokss+5fpMsT+7lRi37gknhoLkf4ITpyLOEQ/LZt76dRL3SvC9m1fgFQ2BeoSV68qn
         97yglrBKYvpbnsWKn1AxxAwpn1jpNYVRI8mwHFLoHrrRQrnKfck4V2LD3/xzzAPgjqnZ
         RlzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O9sxvUGgNy4kR0KvJnvDcmevXP+zDVywecO7mgESs9U=;
        b=ffhSAndcpvyb03oxQ6+clFdDIUz0H2lBLAZQWG6ueJlSU89UQe2+uUQ+J27iIw3NFw
         CrTiJXb7ZeRCsbZCpeqv5NCy2LKSOnjc9u3L3YojIMcLAq3VEN7Fgb6jJUn2W+nyNtQB
         K+36xdborIQhnlqiveTdkbQddqXeMl63hG0hKdQlW2al6+MSJ9prscGERzoS3SnduJOp
         phB9qlpPmu9YGuN1RGOGPzMmMBu5ZhlUoLf/n5ILmExWWjfK04/mXq5sipoBxnKh/mux
         HX/pzxu1ZnKQLnD8UYAI7HcV7ZKAyIV5qZN4XYfrPYLtGdSEtWaMK2Jx0pptRwCWa5FY
         6vcw==
X-Gm-Message-State: ANhLgQ0bPMnKtwCTHbHqpzXYyEqZ0pY4KhEw2C9RbPxQFSZngK6I8rkn
	+I1yO1kHI0blfDWoehN6jK0=
X-Google-Smtp-Source: ADFU+vsbFn4Hg8pXsqrgL59qX0e69PGG5kOR8Y4k9LjUqkIo3AFFG3a/qdOEygxnI05iuK+BPUsekQ==
X-Received: by 2002:ad4:54d4:: with SMTP id j20mr7302117qvx.75.1584116145777;
        Fri, 13 Mar 2020 09:15:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:f1d:: with SMTP id e29ls911348qtk.2.gmail; Fri, 13 Mar
 2020 09:15:45 -0700 (PDT)
X-Received: by 2002:aed:3a89:: with SMTP id o9mr13515075qte.375.1584116145226;
        Fri, 13 Mar 2020 09:15:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584116145; cv=none;
        d=google.com; s=arc-20160816;
        b=Y4h1/SEmfFvHggzbXFhkNIE0FLR+RVQdF/fsdBGnZ9FH43iBs1OvcAD0krPoKeTy87
         mRg77mSC6z6wmGjxEQmHziOxgd9mRTv5nLN9xzFafBmbdyyuMb/B6Aw1YG32cb2QM+8r
         WaSO41W02HXTE4BWKQQxPYNClXirBLGe49kPtft7tZc0D26k8xmc3Fh831T9xmOWi0Ah
         7HRuYQ5s278SzSoMjdPx7IC8vg8L8LEGJQBP60YFpP/xFLvZv9srIiB0QQeQKhavxrI3
         lqdWlvxjQ1lPpqVAuRpPN64BcuLzTm1Fc6wy96CW+z11ikqvLbmgeUq7awD2/Ud1kes0
         RpBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ItqazNtvdRJuwEbZG7KQ5fbAxT8GhXH9Ce1D20Tz2pA=;
        b=BoWUenEwOG5ttDNfISW62Hb6eJSdijiUuDFCWcmozxporoejI10il5bC2TollchviZ
         FlKTEzqSTR2JjXr1Mzg3vgyXuuEcZmbmvH4qYheRr01tNK/p6woaGtlnGaJbLqD4qgJ6
         qhk58RMDyems2ZxG1ECtOtX0Ikv1W000eyhYrAQ+0Mkkrv42KyD1kknWsShk7wczkw2M
         iZFQFTwpQeTpQdj+EuE8PdiqV+JUNyO5akusTeBgJ4acfiPbKYF5qsstJ0qHpOA6Mgy7
         y1Sqo295yG4gxSI8FbY/K1M+QC+29rRWxuSInMOjKMNv3wu2c12IAL5zy2X8Cz56XPtK
         s4cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ggK3KIuW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id w10si448317qtn.1.2020.03.13.09.15.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Mar 2020 09:15:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id d63so9952654oig.6
        for <kasan-dev@googlegroups.com>; Fri, 13 Mar 2020 09:15:45 -0700 (PDT)
X-Received: by 2002:a05:6808:1c4:: with SMTP id x4mr7731480oic.83.1584116144238;
 Fri, 13 Mar 2020 09:15:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200309190359.GA5822@paulmck-ThinkPad-P72> <20200309190420.6100-17-paulmck@kernel.org>
 <20200313085220.GC105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
In-Reply-To: <20200313085220.GC105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 13 Mar 2020 17:15:32 +0100
Message-ID: <CANpmjNO-hjVfp729YOGdoiuwWjLacW+OCJ=5RnxEYGvQjfQGhA@mail.gmail.com>
Subject: Re: [PATCH kcsan 17/32] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com, 
	Ingo Molnar <mingo@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ggK3KIuW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Fri, 13 Mar 2020 at 09:52, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> Hi Marco,
>
> On Mon, Mar 09, 2020 at 12:04:05PM -0700, paulmck@kernel.org wrote:
> > From: Marco Elver <elver@google.com>
> >
> > Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> > may be used to assert properties of synchronization logic, where
> > violation cannot be detected as a normal data race.
> >
> > Examples of the reports that may be generated:
> >
> >     ==================================================================
> >     BUG: KCSAN: assert: race in test_thread / test_thread
> >
> >     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
> >      test_thread+0x8d/0x111
> >      debugfs_write.cold+0x32/0x44
> >      ...
> >
> >     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> >      test_thread+0xa3/0x111
> >      debugfs_write.cold+0x32/0x44
> >      ...
> >     ==================================================================
> >
> >     ==================================================================
> >     BUG: KCSAN: assert: race in test_thread / test_thread
> >
> >     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
> >      test_thread+0xb9/0x111
> >      debugfs_write.cold+0x32/0x44
> >      ...
> >
> >     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> >      test_thread+0x77/0x111
> >      debugfs_write.cold+0x32/0x44
> >      ...
> >     ==================================================================
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > ---
> >  include/linux/kcsan-checks.h | 40 ++++++++++++++++++++++++++++++++++++++++
> >  1 file changed, 40 insertions(+)
> >
> > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > index 5dcadc2..cf69617 100644
> > --- a/include/linux/kcsan-checks.h
> > +++ b/include/linux/kcsan-checks.h
> > @@ -96,4 +96,44 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> >       kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
> >  #endif
> >
> > +/**
> > + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> > + *
> > + * Assert that there are no other threads writing @var; other readers are
> > + * allowed. This assertion can be used to specify properties of concurrent code,
> > + * where violation cannot be detected as a normal data race.
> > + *
>
> I like the idea that we can assert no other writers, however I think
> assertions like ASSERT_EXCLUSIVE_WRITER() are a little limited. For
> example, if we have the following code:
>
>         preempt_disable();
>         do_sth();
>         raw_cpu_write(var, 1);
>         do_sth_else();
>         preempt_enable();
>
> we can add the assert to detect another potential writer like:
>
>         preempt_disable();
>         do_sth();
>         ASSERT_EXCLUSIVE_WRITER(var);
>         raw_cpu_write(var, 1);
>         do_sth_else();
>         preempt_enable();
>
> , but, if I understand how KCSAN works correctly, it only works if the
> another writer happens when the ASSERT_EXCLUSIVE_WRITER(var) is called,
> IOW, it can only detect another writer between do_sth() and
> raw_cpu_write(). But our intent is to prevent other writers for the
> whole preemption-off section. With this assertion introduced, people may
> end up with code like:

To confirm: KCSAN will detect a race if it sets up a watchpoint on
ASSERT_EXCLUSIVE_WRITER(var), and a concurrent write happens. Note
that the watchpoints aren't always set up, but only periodically
(discussed more below). For every watchpoint, we also inject an
artificial delay. Pseudo-code:

if watchpoint for access already set up {
  consume watchpoint;
else if should set up watchpoint {
  setup watchpoint;
  udelay(...);
  check watchpoint consumed;
  release watchpoint;
}

>         preempt_disable();
>         ASSERT_EXCLUSIVE_WRITER(var);
>         do_sth();
>         ASSERT_EXCLUSIVE_WRITER(var);
>         raw_cpu_write(var, 1);
>         ASSERT_EXCLUSIVE_WRITER(var);
>         do_sth_else();
>         ASSERT_EXCLUSIVE_WRITER(var);
>         preempt_enable();
>
> and that is horrible...

It is, and I would strongly discourage any such use, because it's not
necessary. See below.

> So how about making a pair of annotations
> ASSERT_EXCLUSIVE_WRITER_BEGIN() and ASSERT_EXCLUSIVE_WRITER_END(), so
> that we can write code like:
>
>         preempt_disable();
>         ASSERT_EXCLUSIVE_WRITER_BEGIN(var);
>         do_sth();
>         raw_cpu_write(var, 1);
>         do_sth_else();
>         ASSERT_EXCLUSIVE_WRITER_END(var);
>         preempt_enable();
>
> ASSERT_EXCLUSIVE_WRITER_BEGIN() could be a rough version of watchpoint
> setting up and ASSERT_EXCLUSIVE_WRITER_END() could be watchpoint
> removing. So I think it's feasible.

Keep in mind that the time from ASSERT_EXCLUSIVE_WRITER_BEGIN to END
might be on the order of a few nanosec, whereas KCSAN's default
watchpoint delay is 10s of microsec (default ~80 for tasks). That
means we would still have to set up a delay somewhere, and the few
nanosec between BEGIN and END are insignificant and don't buy us
anything.

Re feasibility: Right now setting up and removing watchpoints is not
exposed, and doing something like this would be an extremely intrusive
change. Because of that, without being able to quantify the actual
usefulness of this, and having evaluated better options (see below),
I'd recommend not pursuing this.

> Thoughts?

Firstly, what is your objective? From what I gather you want to
increase the probability of detecting a race with 'var'.

I agree, and have been thinking about it, but there are other options
that haven't been exhausted, before we go and make the interface more
complicated.

== Interface design ==
The interface as it is right now, is intuitive and using it is hard to
get wrong. Demanding begin/end markers introduces complexity that will
undoubtedly result in incorrect usage, because as soon as you somehow
forget to end the region, you'll get tons of false positives. This may
be due to control-flow that was missed etc. We had a similar problem
with seqlocks, and getting them to work correctly with KCSAN was
extremely difficult, because clear begin and end markers weren't
always given. I imagine introducing an interface like this will
ultimately result in similar problems, as much as we'd like to believe
this won't ever happen.

== Improving race detection for KCSAN_ACCESS_ASSERT access types ==
There are several options:

1. Always set up a watchpoint for assert-type accesses, and ignore
KCSAN_SKIP_WATCH/kcsan_skip counter (see 'should_watch()'). One
problem with this is that it would seriously impact overall
performance as soon as we get a few ASSERT_EXCLUSIVE_*() in a hot path
somewhere. A compromise might be simply being more aggressive with
setting up watchpoints on assert-type accesses.

2. Let's say in the above example (without BEGIN/END) the total
duration (via udelay) of watchpoints for 'var' being set up is 4*D.
Why not just increase the watchpoint delay for assert-type accesses to
4*D? Then, just having one ASSERT_EXCLUSIVE_WRITER(var) somewhere in
the region would have the same probability of catching a race.
(Assuming that the region's remaining execution time is on the order
of nanosecs.)

I have some limited evidence that (1) is going to help, but not (2).
This is based on experiments trying to reproduce racy use-after-free
bugs that KASAN found, but with KCSAN. The problem is that it does
slow-down overall system performance if in a hot path like an
allocator. Which led me to a 3rd option.

3. Do option (1) but do the opposite of (2), i.e. always set up a
watchpoint on assert-type accesses, but *reduce* the watchpoint delay.

I haven't yet sent a patch for any one of 1-3 because I'm hesitant
until we can actually show one of them would always be useful and
improve things. For now, the best thing is to dynamically adjust
udelay_{task,interrupt} and skip_watch either via Kconfig options or
/sys/modules/kcsan/parameters/ and not add more complexity without
good justification. A good stress test will also go a long way.

There are some more (probably bad) ideas I have, but the above are the
best options for now.

So, anything that somehow increases the total time that a watchpoint
is set up will increase the probability of detecting a race. However,
we're also trying to balance overall system performance, as poor
performance could equally affect race detection negatively (fewer
instructions executed, etc.). Right now any one of 1-3 might sound
like a decent idea, but I don't know what it will look like once we
have dozens of ASSERT_EXCLUSIVE_*() in places, especially if a few of
them are in hot paths.

Thanks,
-- Marco






> Regards,
> Boqun
>
> > + * For example, if a per-CPU variable is only meant to be written by a single
> > + * CPU, but may be read from other CPUs; in this case, reads and writes must be
> > + * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
> > + * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
> > + * race condition. Using this macro allows specifying this property in the code
> > + * and catch such bugs.
> > + *
> > + * @var variable to assert on
> > + */
> > +#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
> > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
> > +
> > +/**
> > + * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> > + *
> > + * Assert that no other thread is accessing @var (no readers nor writers). This
> > + * assertion can be used to specify properties of concurrent code, where
> > + * violation cannot be detected as a normal data race.
> > + *
> > + * For example, in a reference-counting algorithm where exclusive access is
> > + * expected after the refcount reaches 0. We can check that this property
> > + * actually holds as follows:
> > + *
> > + *   if (refcount_dec_and_test(&obj->refcnt)) {
> > + *           ASSERT_EXCLUSIVE_ACCESS(*obj);
> > + *           safely_dispose_of(obj);
> > + *   }
> > + *
> > + * @var variable to assert on
> > + */
> > +#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> > +
> >  #endif /* _LINUX_KCSAN_CHECKS_H */
> > --
> > 2.9.5
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO-hjVfp729YOGdoiuwWjLacW%2BOCJ%3D5RnxEYGvQjfQGhA%40mail.gmail.com.
