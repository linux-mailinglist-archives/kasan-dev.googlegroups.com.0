Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMXBYLZQKGQEXBIL2KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E3D361880BA
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 12:12:51 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id z19sf13981711ils.20
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 04:12:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584443570; cv=pass;
        d=google.com; s=arc-20160816;
        b=bMbOAqRx2igGcUCOJs27FNpbxgOnkqr1+DNUUPRqVJJzTDjd+DXLm8R7hK9QDcdFfs
         9KpvwGB5VUs1rW9F2wuNfkNSs1bWCCbbJg3+vYDFF7ncg84Ji1nTUPJy34+ryPYrQLMv
         DCbmeVVu5jCWz4Mpr0u7MCahcELWhxE4+RAx8Mz/jO+nQ1QnPHtgFJ5gXoFJDXRwqTca
         IQiIJXWlXLN6i0+2Nv5qd18nnDxQ28ClYCM9CJ/5pO1mWDRurRGcIq54tsEhQnm0KuqH
         jQQqi4dnoUc8cYZ2lyepcy8cwNsGENiF8yUASFE4sByiwWYMZpBb+NALXXR8bAFRDDUP
         +MGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iPAi7vFk0LI5/oVsJ8mQHrJ8K0OH7mFRWt8BYBSWLl8=;
        b=SEv677RCFrtp1toKl2STRMPX2gL6KiB0WSkPzD4r2xRou+xgbdtiz81E4eXkseLaNV
         wKFUD501Du+ku2nwh/BQSOZ4ERbiSiCuw5tjmvsdKHJsGvkuHquyXqMk2Hk/hhAuX4dj
         jtVXWa/qZZ6TKW/QLSeC2FpgN6CibDIqnAdloHR7SS4smxjihhlJ5W59gBVVwOP2Vz/T
         oKHqFFe/RnjvvitPNiGNT93zFT6QwpMhtNu53fxfAbh9p0tCVGV5tEjVPQ9ROoy4oudl
         8Xtf38oPBk/nE2PEdz7JYs35SJ28CA5NBFx+061vgTL6pQHVzT0FfVvNvKLHwtsconuz
         mk5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OG67LfbU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iPAi7vFk0LI5/oVsJ8mQHrJ8K0OH7mFRWt8BYBSWLl8=;
        b=X/ao64dj3hJk6yFFTS61FckEW9vYxRfHMp6cIRRtjZMERu1BOXJBWSZ1j+mJ0tTEuY
         rvForUG+adTAIHCzJMAc6o3mrv+h/cM8vOqHkozE/W3YHoO6byLHjQqlKeYrFoTkQLud
         YUWalWKqfizszMRlIMWfTXFN2OSsz2QTJY7SkWzeZWksM5Vw0M4XT0oW7L8oTs1nrUji
         wVQaZ5/3zMAJ8enEW+PfiP0ny7AHy4SLdeXjidNe7bcFRDq+cLWm3Wd7owQndcsl5IPW
         TXd3HqgAFmazZDQePOpynIx2WXgLt/hpNzT6ZPQ+eGs0lyjpK6YgQoFBjfEmJnEcPZ2N
         W2dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iPAi7vFk0LI5/oVsJ8mQHrJ8K0OH7mFRWt8BYBSWLl8=;
        b=RUsrutGGp/JjPDRp0lAJJxGL8ChBPtn3QXkRElQg4BQuITLUN8AH13u0h/TK+Z2p62
         IDdvj7ypiR0n6VSY27e1TQzAezLM1DxAb+lgvEru+Ogm8OkfOcWbZS01F4NWlYcQSfx7
         0v0CsXPSRzwKLYRslZ11aqNhoPT2z9Q73qO+F/WM9AG4NXvp524FqoPQmP8vfmUrK5Yd
         Dlkbpup2t9c+tZqgchgpAktysWIdUre0GcAqLdPlsckxI0BAXOO7nZXlKBJ8BBMOWiaj
         YpT5RQHY5ur209CtL5QRnarNx0vvhOy+lWQn0ck8xXWqo7KzpRaDKHZy04vVqtivNs5+
         bkgw==
X-Gm-Message-State: ANhLgQ38RhK5ENvY4zNQwjCjG+Y/7IrRXG2msRjlh4eQTHRL5ZPVRD8l
	oLHrXlvrVLOs4k+oKptJrHQ=
X-Google-Smtp-Source: ADFU+vs06ht2znO04pA4ZkBdnRYNVvXe/dHESH+XoZh2HocpSg1IWEX9RSHt/SJUUbOFfpDGJMwK/g==
X-Received: by 2002:a05:6638:921:: with SMTP id 1mr4841058jak.110.1584443570575;
        Tue, 17 Mar 2020 04:12:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:cb08:: with SMTP id j8ls2576765jap.4.gmail; Tue, 17 Mar
 2020 04:12:50 -0700 (PDT)
X-Received: by 2002:a02:a50f:: with SMTP id e15mr4738005jam.142.1584443570108;
        Tue, 17 Mar 2020 04:12:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584443570; cv=none;
        d=google.com; s=arc-20160816;
        b=A9rARgJfhSteQcapWPKZY8/NLJfqYGH1/OqqOtw8aM/dBeqRmERKgpIoXfRestA4Cz
         cPJV/j63kruxqL45tqH2q32om35N91KPmJ+uWxaAqNOverza3a3yukhE96GYkg+SGpGb
         2i3+/5LF2yHOenJx8Rw4un0wLa9dpWHnLpK57EGasB9/8q+uEw7hYaiQhq+Dk0em7eOT
         G5zGHpRCdsQh7/Pp1d4/MhnlJvgadSKfKS0L2tyyBxyDNEKXcHGoEvxBLEQJV3XmzsEv
         uUpSDfL8e2s54qRc6Hr6rtXbN08SeRyljFTujheQSLwQFxVGOU+FmLQdKek4jc6rqehm
         QHcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tDIGHzM00UxgsxqOQfj1JbuGjgWmon8niln7RYiZPTE=;
        b=CzlTUQ+xJ/krB0NqYAMKJ+gbbdv7vLtKg1lQrBrAPomYBQRy769L1cXwCm0vjLPQwe
         pFtRbIhLvrhNntVrnHNe68zgRFL/ARhR8RaSo+G5bzVOvOJTdE1S/3PNNty3t3IW8aq1
         kobzh0v6FZUOjV9PKNYtbybNV0u3Dnivb1xHzCkoxAvmu1rHD7vqwjnJimJdhwd/3Ypq
         PZaYRG4npPTTzUgaufQ90sCljEpdIY30jXxOVKg0Di1EjAze4AmWarz4VofR9LGuv5Nq
         Y7EvGFzPUzCstX0FhO+M2awf2Z77Jqhp5D7sTxls84gq/bbBfjLAGzwlVw0u654jfLLE
         wDOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OG67LfbU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id t13si214167ilk.5.2020.03.17.04.12.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Mar 2020 04:12:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id k8so19838951oik.2
        for <kasan-dev@googlegroups.com>; Tue, 17 Mar 2020 04:12:50 -0700 (PDT)
X-Received: by 2002:aca:4cd8:: with SMTP id z207mr2922845oia.155.1584443569132;
 Tue, 17 Mar 2020 04:12:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200309190359.GA5822@paulmck-ThinkPad-P72> <20200309190420.6100-17-paulmck@kernel.org>
 <20200313085220.GC105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
 <CANpmjNO-hjVfp729YOGdoiuwWjLacW+OCJ=5RnxEYGvQjfQGhA@mail.gmail.com> <20200314022210.GD105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
In-Reply-To: <20200314022210.GD105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Mar 2020 12:12:36 +0100
Message-ID: <CANpmjNPu67nnaWbOtA8xntBWafDm5Ykspzj43wuSdRckLGC=UA@mail.gmail.com>
Subject: Re: [PATCH kcsan 17/32] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com, 
	Ingo Molnar <mingo@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OG67LfbU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Sat, 14 Mar 2020 at 03:22, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> On Fri, Mar 13, 2020 at 05:15:32PM +0100, Marco Elver wrote:
> > On Fri, 13 Mar 2020 at 09:52, Boqun Feng <boqun.feng@gmail.com> wrote:
> > >
> > > Hi Marco,
> > >
> > > On Mon, Mar 09, 2020 at 12:04:05PM -0700, paulmck@kernel.org wrote:
> > > > From: Marco Elver <elver@google.com>
> > > >
> > > > Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> > > > may be used to assert properties of synchronization logic, where
> > > > violation cannot be detected as a normal data race.
> > > >
> > > > Examples of the reports that may be generated:
> > > >
> > > >     ==================================================================
> > > >     BUG: KCSAN: assert: race in test_thread / test_thread
> > > >
> > > >     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
> > > >      test_thread+0x8d/0x111
> > > >      debugfs_write.cold+0x32/0x44
> > > >      ...
> > > >
> > > >     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > > >      test_thread+0xa3/0x111
> > > >      debugfs_write.cold+0x32/0x44
> > > >      ...
> > > >     ==================================================================
> > > >
> > > >     ==================================================================
> > > >     BUG: KCSAN: assert: race in test_thread / test_thread
> > > >
> > > >     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
> > > >      test_thread+0xb9/0x111
> > > >      debugfs_write.cold+0x32/0x44
> > > >      ...
> > > >
> > > >     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > > >      test_thread+0x77/0x111
> > > >      debugfs_write.cold+0x32/0x44
> > > >      ...
> > > >     ==================================================================
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > > ---
> > > >  include/linux/kcsan-checks.h | 40 ++++++++++++++++++++++++++++++++++++++++
> > > >  1 file changed, 40 insertions(+)
> > > >
> > > > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > > > index 5dcadc2..cf69617 100644
> > > > --- a/include/linux/kcsan-checks.h
> > > > +++ b/include/linux/kcsan-checks.h
> > > > @@ -96,4 +96,44 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> > > >       kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
> > > >  #endif
> > > >
> > > > +/**
> > > > + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> > > > + *
> > > > + * Assert that there are no other threads writing @var; other readers are
> > > > + * allowed. This assertion can be used to specify properties of concurrent code,
> > > > + * where violation cannot be detected as a normal data race.
> > > > + *
> > >
> > > I like the idea that we can assert no other writers, however I think
> > > assertions like ASSERT_EXCLUSIVE_WRITER() are a little limited. For
> > > example, if we have the following code:
> > >
> > >         preempt_disable();
> > >         do_sth();
> > >         raw_cpu_write(var, 1);
> > >         do_sth_else();
> > >         preempt_enable();
> > >
> > > we can add the assert to detect another potential writer like:
> > >
> > >         preempt_disable();
> > >         do_sth();
> > >         ASSERT_EXCLUSIVE_WRITER(var);
> > >         raw_cpu_write(var, 1);
> > >         do_sth_else();
> > >         preempt_enable();
> > >
> > > , but, if I understand how KCSAN works correctly, it only works if the
> > > another writer happens when the ASSERT_EXCLUSIVE_WRITER(var) is called,
> > > IOW, it can only detect another writer between do_sth() and
> > > raw_cpu_write(). But our intent is to prevent other writers for the
> > > whole preemption-off section. With this assertion introduced, people may
> > > end up with code like:
> >
> > To confirm: KCSAN will detect a race if it sets up a watchpoint on
> > ASSERT_EXCLUSIVE_WRITER(var), and a concurrent write happens. Note
> > that the watchpoints aren't always set up, but only periodically
> > (discussed more below). For every watchpoint, we also inject an
> > artificial delay. Pseudo-code:
> >
> > if watchpoint for access already set up {
> >   consume watchpoint;
> > else if should set up watchpoint {
> >   setup watchpoint;
> >   udelay(...);
> >   check watchpoint consumed;
> >   release watchpoint;
> > }
> >
>
> Yes, I get this part.
>
> > >         preempt_disable();
> > >         ASSERT_EXCLUSIVE_WRITER(var);
> > >         do_sth();
> > >         ASSERT_EXCLUSIVE_WRITER(var);
> > >         raw_cpu_write(var, 1);
> > >         ASSERT_EXCLUSIVE_WRITER(var);
> > >         do_sth_else();
> > >         ASSERT_EXCLUSIVE_WRITER(var);
> > >         preempt_enable();
> > >
> > > and that is horrible...
> >
> > It is, and I would strongly discourage any such use, because it's not
> > necessary. See below.
> >
> > > So how about making a pair of annotations
> > > ASSERT_EXCLUSIVE_WRITER_BEGIN() and ASSERT_EXCLUSIVE_WRITER_END(), so
> > > that we can write code like:
> > >
> > >         preempt_disable();
> > >         ASSERT_EXCLUSIVE_WRITER_BEGIN(var);
> > >         do_sth();
> > >         raw_cpu_write(var, 1);
> > >         do_sth_else();
> > >         ASSERT_EXCLUSIVE_WRITER_END(var);
> > >         preempt_enable();
> > >
> > > ASSERT_EXCLUSIVE_WRITER_BEGIN() could be a rough version of watchpoint
> > > setting up and ASSERT_EXCLUSIVE_WRITER_END() could be watchpoint
> > > removing. So I think it's feasible.
> >
> > Keep in mind that the time from ASSERT_EXCLUSIVE_WRITER_BEGIN to END
> > might be on the order of a few nanosec, whereas KCSAN's default
> > watchpoint delay is 10s of microsec (default ~80 for tasks). That
> > means we would still have to set up a delay somewhere, and the few
> > nanosec between BEGIN and END are insignificant and don't buy us
> > anything.
> >
>
> Yeah, the delay doesn't buy us anything given the default watchpoint
> delay, and I agree even with *_{BEGIN/END}, we still need to set up a
> delay somewhere. Adding a delay makes the watchpoint live longer so that
> a problem will more likely happen, but sometimes the delay won't be
> enough, considering another writer like:
>
>         if (per_cpu(var, cpu) == 1)
>                 per_cpu(var, cpu) = 0;
>
> in this user case, percpu variable "var" is used for maintaining some
> state machine, and a CPU set a state with its own variable so that other
> CPUs can consume it. And this another writer cannot be catched by:
>
>         preempt_disable();
>         do_sth();
>         ASSERT_EXCLUSIVE_WRITER(var);
>         raw_cpu_write(var, 1);
>         do_sth_else();
>         preempt_enable();
>

Right, the example makes sense.

That is assuming there are various other expected racy reads that are
fine. If that's not true, ASSERT_EXCLUSIVE_ACCESS should be
considered.

> , no matter how long the delay is set. Another example: let's say the
> do_sth_else() above is actually an operation that queues a callback
> which writes to "var". In one version, do_sth_else() uses call_rcu(),
> which works, because preemption-off is treated as RCU read-side critical
> section, so we are fine. But if someone else changes it to queue_work()
> for some reason, the code is just broken, and KCSAN cannot detect it, no
> matter how long the delay is.
>
> To summarize, a delay is helpful to trigger a problem because it allows
> _other_ CPU/threads to run more code and do more memory accesses,
> however it's not helpful if a particular problem happens due to some
> memory effects of the current/watched CPU/thread. While *_{BEGIN/END}
> can be helpful in this case.

Makes sense.

> > Re feasibility: Right now setting up and removing watchpoints is not
> > exposed, and doing something like this would be an extremely intrusive
> > change. Because of that, without being able to quantify the actual
> > usefulness of this, and having evaluated better options (see below),
> > I'd recommend not pursuing this.
> >
> > > Thoughts?
> >
> > Firstly, what is your objective? From what I gather you want to
> > increase the probability of detecting a race with 'var'.
> >
>
> Right, I want to increase the probablity.
>
> > I agree, and have been thinking about it, but there are other options
> > that haven't been exhausted, before we go and make the interface more
> > complicated.
> >
> > == Interface design ==
> > The interface as it is right now, is intuitive and using it is hard to
> > get wrong. Demanding begin/end markers introduces complexity that will
>
> Yeah, the interface is intuitive, however it's still an extra effort to
> put those assertions, right? Which means it doesn't come for free,
> compared to other detection KCSAN can do, the developers don't need to
> put extra lines of code. Given the extra effort for developers to use
> the detect, I think we should dicuss the design thoroughly.
>
> Besides the semantics of assertions is usually "do some checking right
> now to see if things go wrong", and I don't think it quite matches the
> semantics of an exclusive writer: "in this piece of code, I'm the only
> one who can do the write".
>
> > undoubtedly result in incorrect usage, because as soon as you somehow
> > forget to end the region, you'll get tons of false positives. This may
> > be due to control-flow that was missed etc. We had a similar problem
> > with seqlocks, and getting them to work correctly with KCSAN was
> > extremely difficult, because clear begin and end markers weren't
> > always given. I imagine introducing an interface like this will
> > ultimately result in similar problems, as much as we'd like to believe
> > this won't ever happen.
> >
>
> Well, if we use *_{BEGIN,END} approach, one solution is combining them
> with sections introducing primitives (such as preemp_disable() and
> preempt_enable()), for example, we can add
>
>         #define preempt_disable_for(var)                                \
>         do {                                                            \
>                 preempt_disable();                                      \
>                 ASSERT_EXCLUSIVE_WRITER_BEGIN(var);                     \
>         }
>
>         #define preempt_enable_for(var)                                 \
>         do {                                                            \
>                 ASSERT_EXCLUSIVE_WRITER_END(var);                       \
>                 preempt_enable();                                       \
>         }
>
>         (similar for spin lock)
>
>         #define spin_lock_for(lock, var)                                \
>         do {                                                            \
>                 spin_lock(lock);                                        \
>                 ASSERT_EXCLUSIVE_WRITER_BEGIN(var);                     \
>         }
>
>         #define spin_unlock_for(lock, var)                              \
>         do {                                                            \
>                 ASSERT_EXCLUSIVE_WRITER_END(var);                       \
>                 spin_unlock(lock);                                      \
>         }
>
> I admit that I haven't thought this thoroughly, but I think this works,
> and besides primitives like above can help the reader to understand the
> questions like: what this lock/preemption-off critical sections are
> protecting?

I can't say anything about introducing even more macros. I'd say we
need at least a dozen use-cases or more and understand them, otherwise
we may end up with the wrong API that we can never take back.

> Thoughts?

Makes sense for the cases you described.

Changing KCSAN to do this is a major change. On surface, it seems like
a refactor and exporting some existing functionality, but there are
various new corner cases, because now 2 accesses don't really have to
be concurrent anymore to detect a race (and simple properties like a
thread can't race with itself need to be taken care of). The existing
ASSERT_EXCLUSIVE macros were able to leverage existing functionality
mostly as-is. So, to motivate something like this, we need at least a
dozen or so good use-cases, where careful placement of an existing
ASSERT_EXCLUSIVE would not catch what you describe.

Thanks,
-- Marco

> Regards,
> Boqun
>
> > == Improving race detection for KCSAN_ACCESS_ASSERT access types ==
> > There are several options:
> >
> > 1. Always set up a watchpoint for assert-type accesses, and ignore
> > KCSAN_SKIP_WATCH/kcsan_skip counter (see 'should_watch()'). One
> > problem with this is that it would seriously impact overall
> > performance as soon as we get a few ASSERT_EXCLUSIVE_*() in a hot path
> > somewhere. A compromise might be simply being more aggressive with
> > setting up watchpoints on assert-type accesses.
> >
> > 2. Let's say in the above example (without BEGIN/END) the total
> > duration (via udelay) of watchpoints for 'var' being set up is 4*D.
> > Why not just increase the watchpoint delay for assert-type accesses to
> > 4*D? Then, just having one ASSERT_EXCLUSIVE_WRITER(var) somewhere in
> > the region would have the same probability of catching a race.
> > (Assuming that the region's remaining execution time is on the order
> > of nanosecs.)
> >
> > I have some limited evidence that (1) is going to help, but not (2).
> > This is based on experiments trying to reproduce racy use-after-free
> > bugs that KASAN found, but with KCSAN. The problem is that it does
> > slow-down overall system performance if in a hot path like an
> > allocator. Which led me to a 3rd option.
> >
> > 3. Do option (1) but do the opposite of (2), i.e. always set up a
> > watchpoint on assert-type accesses, but *reduce* the watchpoint delay.
> >
> > I haven't yet sent a patch for any one of 1-3 because I'm hesitant
> > until we can actually show one of them would always be useful and
> > improve things. For now, the best thing is to dynamically adjust
> > udelay_{task,interrupt} and skip_watch either via Kconfig options or
> > /sys/modules/kcsan/parameters/ and not add more complexity without
> > good justification. A good stress test will also go a long way.
> >
> > There are some more (probably bad) ideas I have, but the above are the
> > best options for now.
> >
> > So, anything that somehow increases the total time that a watchpoint
> > is set up will increase the probability of detecting a race. However,
> > we're also trying to balance overall system performance, as poor
> > performance could equally affect race detection negatively (fewer
> > instructions executed, etc.). Right now any one of 1-3 might sound
> > like a decent idea, but I don't know what it will look like once we
> > have dozens of ASSERT_EXCLUSIVE_*() in places, especially if a few of
> > them are in hot paths.
> >
> > Thanks,
> > -- Marco
> >
> >
> >
> >
> >
> >
> > > Regards,
> > > Boqun
> > >
> > > > + * For example, if a per-CPU variable is only meant to be written by a single
> > > > + * CPU, but may be read from other CPUs; in this case, reads and writes must be
> > > > + * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
> > > > + * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
> > > > + * race condition. Using this macro allows specifying this property in the code
> > > > + * and catch such bugs.
> > > > + *
> > > > + * @var variable to assert on
> > > > + */
> > > > +#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
> > > > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
> > > > +
> > > > +/**
> > > > + * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> > > > + *
> > > > + * Assert that no other thread is accessing @var (no readers nor writers). This
> > > > + * assertion can be used to specify properties of concurrent code, where
> > > > + * violation cannot be detected as a normal data race.
> > > > + *
> > > > + * For example, in a reference-counting algorithm where exclusive access is
> > > > + * expected after the refcount reaches 0. We can check that this property
> > > > + * actually holds as follows:
> > > > + *
> > > > + *   if (refcount_dec_and_test(&obj->refcnt)) {
> > > > + *           ASSERT_EXCLUSIVE_ACCESS(*obj);
> > > > + *           safely_dispose_of(obj);
> > > > + *   }
> > > > + *
> > > > + * @var variable to assert on
> > > > + */
> > > > +#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> > > > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> > > > +
> > > >  #endif /* _LINUX_KCSAN_CHECKS_H */
> > > > --
> > > > 2.9.5
> > > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPu67nnaWbOtA8xntBWafDm5Ykspzj43wuSdRckLGC%3DUA%40mail.gmail.com.
