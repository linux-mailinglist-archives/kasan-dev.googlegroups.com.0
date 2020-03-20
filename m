Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCNQ2PZQKGQENACCBTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B0BA818D176
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 15:49:48 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id q65sf1925535vka.3
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 07:49:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584715787; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wl6avTqTeDbHWuvjzx4+pGZ8ftXxEbMniybzQnMDPacidlnwtClT+O7/kNiBRyVZmc
         v8XW0smdcq47gpj28aqLBJMjDmDbw4WwKn2K3Ju/jlQ5YiV33zNlPUc0/NUR2z0ebRA9
         FfbYcP796fLn6KfogOrardEnpYasgbu4X8GFHAcovF1LBNycIagHRzcvzbhVL+Yd5+5G
         vOVM7diZAxFrahOZTgXcJYNEaD4QNdwsEVd0hYQ8Ag9NKps7DlUmfBdR4xOND13OW8lJ
         08677PtrKVVvUbAByNis0xBW6it/M0/JEP0wpHE3sHNU4n5mpy1/l+rqrOWrnnezly+H
         8zJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UnbGqcxv03RxES/5gI+v4gvK699D/r5ew3LOwf0KvNc=;
        b=hNK4gVAP7BpsBmklSdeDpK2GbyKUG8nYKHQ2yy3NRlgaRhJxWo4W4IZ4+/Ht67Vq9q
         /lnSg2NVmfOOOAnOQ3QYzwO9bRhV34O8czGeF7phPctWEhP36d9U9a2uMed9ytId0h2H
         dOQoE1xf0MZqtsXj7qxmtnxa/mYOtUdfWDmIVBtNaYzDcL8J72dk/+cRnOlHRK5/KXfY
         z76HT9VYuJHvhlQzsWzoBNMZngyZmRapb3pT9eKwbTnM6YPuFrLl++JZvLDeyJ/POv0s
         wEd4Utuzv7yUdXH/fJAoIK21BTFYBzKgZ0qGGJ4bsNNsWML9P12OtvhJa/yw6uWa/vwF
         QGnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Q1KfnjtV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UnbGqcxv03RxES/5gI+v4gvK699D/r5ew3LOwf0KvNc=;
        b=rXlKn5dzxRHDvF+rIGlALrVvk4bgVfhSiUuwJ8BYqTazajQawws3n17KbqmSKS0vjZ
         r4JEHO68+1DMsrDx/LKE1VGutWvufFQpGKkfV4B8ML7mOAk9SFe7lt8xTkNcqb1iQkFC
         db+OffD5+SUfOCMvAryd5MT3uwNBwBaKXeJxalPoaZQe+HUMfEuX2MFh4QW6dOCNlJt+
         3sHtpBRYPDYsJeR88+rHZpdN71DYHJ8gADBDFKWCq6sRGQoKRuv7himrAfLh4nBdUTut
         uM77XuhSXm17HLQ3DzEzbw8GJVqKBSri5sKUiFYVHEI0VRIxEKMALTnf3iDTkCQOtdOi
         9WYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UnbGqcxv03RxES/5gI+v4gvK699D/r5ew3LOwf0KvNc=;
        b=K6d1iS+DOBuWlsAaj1lS2Vep0gXXkfFm8jmIDLxTdI6Y0GlnBKHY4DJZu9/mZcaLmo
         tro25EdmiEjkQ66LZqunsdX+XE4XYxQm5n0KXoRj1G4U2ZvWGmZVP9KDuC9XgxoZn8w2
         jrHip7RNNc+do37ZrKCFz1/SmQat8L8Yne00JNemErRuUKdW8G/W0iot367jy6sg3U55
         IhpRDt9/JR/obqgXMKBVsqLDFafVh6mI3/zHJovTfQ4DfpT01dOoagcXr6XAj7hvPQEb
         23vq+xKtSx3poYNn+qy1UiRrbV0179JXc/UaDtkzHe4rVGPbmnrWQZI1FaxzYG48m6KP
         lKpw==
X-Gm-Message-State: ANhLgQ3czjG1+CuKN1JR/56/JYbe31isaPldMisPMCgn/DCzUwccNpNX
	2gXtr5FgKQ+FqykeipOjqvE=
X-Google-Smtp-Source: ADFU+vsVSPH9UCVw+chGc2hiiB8QVT/Vxk8SnQuv4dAnrfxpw8pSiPMyZ4TkLNhpYu6PiKZuTxpzsA==
X-Received: by 2002:ab0:2448:: with SMTP id g8mr5924711uan.108.1584715786037;
        Fri, 20 Mar 2020 07:49:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:388a:: with SMTP id t10ls496525uaf.0.gmail; Fri, 20 Mar
 2020 07:49:44 -0700 (PDT)
X-Received: by 2002:ab0:4543:: with SMTP id r61mr5888492uar.113.1584715784026;
        Fri, 20 Mar 2020 07:49:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584715784; cv=none;
        d=google.com; s=arc-20160816;
        b=ygxXuotq380UGUqcXgZXqsp4sDD4OqGl9XDv5n/DJbOfWyXvakrCcOg1Gfa/86MX3d
         +SnXs8OeAOUbGRcSZgH2IiWgsBujW1u7cObysEW9RMXlI4vIiyd737hYpXk1hLcorQwA
         jYSkYuvjWD6iuSmVwamhiR79zshNKC/I3H5SG4bvMjbRHHHGPipX6AkTuN9ikJAAc85f
         ugtSosqhvUhUG92S5rR0nvE9L7akmxNGZRXICBGVBZXDe+nglgRjd+9MEJooCGhvyH32
         skjygpvemQ0XYeUW4H6X9lB8ZmXycJwjQlEUD1cS340EF8D4hbN6s7l9QGBQ7JOAsfg2
         itdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sYXSjYRj4e0el0aohJdLv/kFhC+73J+gTXrl9WkNGlo=;
        b=RQTMBmw/vTBCdGdwgP13/2xe8y6E+XZUDBuswwZHYEbJEzcoMJ2+9RwscNwv+cKANP
         ngIT6wN2xMFI44sIQGaAIcR1i3VUMAAcXCY6RqbKau+qiYaJ3GMKOQLK6Fmq/kC3z2J2
         vAadS6BJTgt2LeZ15iUpVMS41xtiqI3DfDgzUywvu0E5iR/T+QouuK27g0diVxh30I4w
         h9PPXPO41HPi9NlGAoILByMGANZdLP9+PoMQzSOclRa/GosbXxZTQ2ajwAgOHO3m5Ykp
         Pv0/YKP6NrSkpXe4eK3LKlDeHCeHVlWOHBO52/eoTFN9mwTfTXeOYpDVO4SSkmFpfeSe
         9vwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Q1KfnjtV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id z26si253147vsp.1.2020.03.20.07.49.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Mar 2020 07:49:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id k21so6732273oij.5
        for <kasan-dev@googlegroups.com>; Fri, 20 Mar 2020 07:49:43 -0700 (PDT)
X-Received: by 2002:aca:3089:: with SMTP id w131mr6911074oiw.121.1584715783013;
 Fri, 20 Mar 2020 07:49:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200309190359.GA5822@paulmck-ThinkPad-P72> <20200309190420.6100-17-paulmck@kernel.org>
 <20200313085220.GC105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
 <CANpmjNO-hjVfp729YOGdoiuwWjLacW+OCJ=5RnxEYGvQjfQGhA@mail.gmail.com>
 <20200314022210.GD105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
 <CANpmjNPu67nnaWbOtA8xntBWafDm5Ykspzj43wuSdRckLGC=UA@mail.gmail.com> <20200319032326.GE105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
In-Reply-To: <20200319032326.GE105953@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Mar 2020 15:49:31 +0100
Message-ID: <CANpmjNOvDrzb=hbA2D+HW12Jy3LMLfdTrd2H=wgYCwQUcZgDzw@mail.gmail.com>
Subject: Re: [PATCH kcsan 17/32] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com, 
	Ingo Molnar <mingo@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Q1KfnjtV;       spf=pass
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

On Thu, 19 Mar 2020 at 04:23, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> On Tue, Mar 17, 2020 at 12:12:36PM +0100, Marco Elver wrote:
> > On Sat, 14 Mar 2020 at 03:22, Boqun Feng <boqun.feng@gmail.com> wrote:
> > >
> > > On Fri, Mar 13, 2020 at 05:15:32PM +0100, Marco Elver wrote:
> > > > On Fri, 13 Mar 2020 at 09:52, Boqun Feng <boqun.feng@gmail.com> wrote:
> > > > >
> > > > > Hi Marco,
> > > > >
> > > > > On Mon, Mar 09, 2020 at 12:04:05PM -0700, paulmck@kernel.org wrote:
> > > > > > From: Marco Elver <elver@google.com>
> > > > > >
> > > > > > Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> > > > > > may be used to assert properties of synchronization logic, where
> > > > > > violation cannot be detected as a normal data race.
> > > > > >
> > > > > > Examples of the reports that may be generated:
> > > > > >
> > > > > >     ==================================================================
> > > > > >     BUG: KCSAN: assert: race in test_thread / test_thread
> > > > > >
> > > > > >     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
> > > > > >      test_thread+0x8d/0x111
> > > > > >      debugfs_write.cold+0x32/0x44
> > > > > >      ...
> > > > > >
> > > > > >     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > > > > >      test_thread+0xa3/0x111
> > > > > >      debugfs_write.cold+0x32/0x44
> > > > > >      ...
> > > > > >     ==================================================================
> > > > > >
> > > > > >     ==================================================================
> > > > > >     BUG: KCSAN: assert: race in test_thread / test_thread
> > > > > >
> > > > > >     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
> > > > > >      test_thread+0xb9/0x111
> > > > > >      debugfs_write.cold+0x32/0x44
> > > > > >      ...
> > > > > >
> > > > > >     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > > > > >      test_thread+0x77/0x111
> > > > > >      debugfs_write.cold+0x32/0x44
> > > > > >      ...
> > > > > >     ==================================================================
> > > > > >
> > > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > > > > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > > > > ---
> > > > > >  include/linux/kcsan-checks.h | 40 ++++++++++++++++++++++++++++++++++++++++
> > > > > >  1 file changed, 40 insertions(+)
> > > > > >
> > > > > > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > > > > > index 5dcadc2..cf69617 100644
> > > > > > --- a/include/linux/kcsan-checks.h
> > > > > > +++ b/include/linux/kcsan-checks.h
> > > > > > @@ -96,4 +96,44 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> > > > > >       kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
> > > > > >  #endif
> > > > > >
> > > > > > +/**
> > > > > > + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> > > > > > + *
> > > > > > + * Assert that there are no other threads writing @var; other readers are
> > > > > > + * allowed. This assertion can be used to specify properties of concurrent code,
> > > > > > + * where violation cannot be detected as a normal data race.
> > > > > > + *
> > > > >
> > > > > I like the idea that we can assert no other writers, however I think
> > > > > assertions like ASSERT_EXCLUSIVE_WRITER() are a little limited. For
> > > > > example, if we have the following code:
> > > > >
> > > > >         preempt_disable();
> > > > >         do_sth();
> > > > >         raw_cpu_write(var, 1);
> > > > >         do_sth_else();
> > > > >         preempt_enable();
> > > > >
> > > > > we can add the assert to detect another potential writer like:
> > > > >
> > > > >         preempt_disable();
> > > > >         do_sth();
> > > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > > >         raw_cpu_write(var, 1);
> > > > >         do_sth_else();
> > > > >         preempt_enable();
> > > > >
> > > > > , but, if I understand how KCSAN works correctly, it only works if the
> > > > > another writer happens when the ASSERT_EXCLUSIVE_WRITER(var) is called,
> > > > > IOW, it can only detect another writer between do_sth() and
> > > > > raw_cpu_write(). But our intent is to prevent other writers for the
> > > > > whole preemption-off section. With this assertion introduced, people may
> > > > > end up with code like:
> > > >
> > > > To confirm: KCSAN will detect a race if it sets up a watchpoint on
> > > > ASSERT_EXCLUSIVE_WRITER(var), and a concurrent write happens. Note
> > > > that the watchpoints aren't always set up, but only periodically
> > > > (discussed more below). For every watchpoint, we also inject an
> > > > artificial delay. Pseudo-code:
> > > >
> > > > if watchpoint for access already set up {
> > > >   consume watchpoint;
> > > > else if should set up watchpoint {
> > > >   setup watchpoint;
> > > >   udelay(...);
> > > >   check watchpoint consumed;
> > > >   release watchpoint;
> > > > }
> > > >
> > >
> > > Yes, I get this part.
> > >
> > > > >         preempt_disable();
> > > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > > >         do_sth();
> > > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > > >         raw_cpu_write(var, 1);
> > > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > > >         do_sth_else();
> > > > >         ASSERT_EXCLUSIVE_WRITER(var);
> > > > >         preempt_enable();
> > > > >
> > > > > and that is horrible...
> > > >
> > > > It is, and I would strongly discourage any such use, because it's not
> > > > necessary. See below.
> > > >
> > > > > So how about making a pair of annotations
> > > > > ASSERT_EXCLUSIVE_WRITER_BEGIN() and ASSERT_EXCLUSIVE_WRITER_END(), so
> > > > > that we can write code like:
> > > > >
> > > > >         preempt_disable();
> > > > >         ASSERT_EXCLUSIVE_WRITER_BEGIN(var);
> > > > >         do_sth();
> > > > >         raw_cpu_write(var, 1);
> > > > >         do_sth_else();
> > > > >         ASSERT_EXCLUSIVE_WRITER_END(var);
> > > > >         preempt_enable();
> > > > >
> > > > > ASSERT_EXCLUSIVE_WRITER_BEGIN() could be a rough version of watchpoint
> > > > > setting up and ASSERT_EXCLUSIVE_WRITER_END() could be watchpoint
> > > > > removing. So I think it's feasible.
> > > >
> > > > Keep in mind that the time from ASSERT_EXCLUSIVE_WRITER_BEGIN to END
> > > > might be on the order of a few nanosec, whereas KCSAN's default
> > > > watchpoint delay is 10s of microsec (default ~80 for tasks). That
> > > > means we would still have to set up a delay somewhere, and the few
> > > > nanosec between BEGIN and END are insignificant and don't buy us
> > > > anything.
> > > >
> > >
> > > Yeah, the delay doesn't buy us anything given the default watchpoint
> > > delay, and I agree even with *_{BEGIN/END}, we still need to set up a
> > > delay somewhere. Adding a delay makes the watchpoint live longer so that
> > > a problem will more likely happen, but sometimes the delay won't be
> > > enough, considering another writer like:
> > >
> > >         if (per_cpu(var, cpu) == 1)
> > >                 per_cpu(var, cpu) = 0;
> > >
> > > in this user case, percpu variable "var" is used for maintaining some
> > > state machine, and a CPU set a state with its own variable so that other
> > > CPUs can consume it. And this another writer cannot be catched by:
> > >
> > >         preempt_disable();
> > >         do_sth();
> > >         ASSERT_EXCLUSIVE_WRITER(var);
> > >         raw_cpu_write(var, 1);
> > >         do_sth_else();
> > >         preempt_enable();
> > >
> >
> > Right, the example makes sense.
> >
> > That is assuming there are various other expected racy reads that are
> > fine. If that's not true, ASSERT_EXCLUSIVE_ACCESS should be
> > considered.
> >
> > > , no matter how long the delay is set. Another example: let's say the
> > > do_sth_else() above is actually an operation that queues a callback
> > > which writes to "var". In one version, do_sth_else() uses call_rcu(),
> > > which works, because preemption-off is treated as RCU read-side critical
> > > section, so we are fine. But if someone else changes it to queue_work()
> > > for some reason, the code is just broken, and KCSAN cannot detect it, no
> > > matter how long the delay is.
> > >
> > > To summarize, a delay is helpful to trigger a problem because it allows
> > > _other_ CPU/threads to run more code and do more memory accesses,
> > > however it's not helpful if a particular problem happens due to some
> > > memory effects of the current/watched CPU/thread. While *_{BEGIN/END}
> > > can be helpful in this case.
> >
> > Makes sense.
> >
> > > > Re feasibility: Right now setting up and removing watchpoints is not
> > > > exposed, and doing something like this would be an extremely intrusive
> > > > change. Because of that, without being able to quantify the actual
> > > > usefulness of this, and having evaluated better options (see below),
> > > > I'd recommend not pursuing this.
> > > >
> > > > > Thoughts?
> > > >
> > > > Firstly, what is your objective? From what I gather you want to
> > > > increase the probability of detecting a race with 'var'.
> > > >
> > >
> > > Right, I want to increase the probablity.
> > >
> > > > I agree, and have been thinking about it, but there are other options
> > > > that haven't been exhausted, before we go and make the interface more
> > > > complicated.
> > > >
> > > > == Interface design ==
> > > > The interface as it is right now, is intuitive and using it is hard to
> > > > get wrong. Demanding begin/end markers introduces complexity that will
> > >
> > > Yeah, the interface is intuitive, however it's still an extra effort to
> > > put those assertions, right? Which means it doesn't come for free,
> > > compared to other detection KCSAN can do, the developers don't need to
> > > put extra lines of code. Given the extra effort for developers to use
> > > the detect, I think we should dicuss the design thoroughly.
> > >
> > > Besides the semantics of assertions is usually "do some checking right
> > > now to see if things go wrong", and I don't think it quite matches the
> > > semantics of an exclusive writer: "in this piece of code, I'm the only
> > > one who can do the write".
> > >
> > > > undoubtedly result in incorrect usage, because as soon as you somehow
> > > > forget to end the region, you'll get tons of false positives. This may
> > > > be due to control-flow that was missed etc. We had a similar problem
> > > > with seqlocks, and getting them to work correctly with KCSAN was
> > > > extremely difficult, because clear begin and end markers weren't
> > > > always given. I imagine introducing an interface like this will
> > > > ultimately result in similar problems, as much as we'd like to believe
> > > > this won't ever happen.
> > > >
> > >
> > > Well, if we use *_{BEGIN,END} approach, one solution is combining them
> > > with sections introducing primitives (such as preemp_disable() and
> > > preempt_enable()), for example, we can add
> > >
> > >         #define preempt_disable_for(var)                                \
> > >         do {                                                            \
> > >                 preempt_disable();                                      \
> > >                 ASSERT_EXCLUSIVE_WRITER_BEGIN(var);                     \
> > >         }
> > >
> > >         #define preempt_enable_for(var)                                 \
> > >         do {                                                            \
> > >                 ASSERT_EXCLUSIVE_WRITER_END(var);                       \
> > >                 preempt_enable();                                       \
> > >         }
> > >
> > >         (similar for spin lock)
> > >
> > >         #define spin_lock_for(lock, var)                                \
> > >         do {                                                            \
> > >                 spin_lock(lock);                                        \
> > >                 ASSERT_EXCLUSIVE_WRITER_BEGIN(var);                     \
> > >         }
> > >
> > >         #define spin_unlock_for(lock, var)                              \
> > >         do {                                                            \
> > >                 ASSERT_EXCLUSIVE_WRITER_END(var);                       \
> > >                 spin_unlock(lock);                                      \
> > >         }
> > >
> > > I admit that I haven't thought this thoroughly, but I think this works,
> > > and besides primitives like above can help the reader to understand the
> > > questions like: what this lock/preemption-off critical sections are
> > > protecting?
> >
> > I can't say anything about introducing even more macros. I'd say we
> > need at least a dozen use-cases or more and understand them, otherwise
> > we may end up with the wrong API that we can never take back.
> >
>
> Agreed, real use-cases are needed for the justification of introducing
> those APIs.
>
> > > Thoughts?
> >
> > Makes sense for the cases you described.
> >
> > Changing KCSAN to do this is a major change. On surface, it seems like
> > a refactor and exporting some existing functionality, but there are
> > various new corner cases, because now 2 accesses don't really have to
> > be concurrent anymore to detect a race (and simple properties like a
> > thread can't race with itself need to be taken care of). The existing
> > ASSERT_EXCLUSIVE macros were able to leverage existing functionality
> > mostly as-is. So, to motivate something like this, we need at least a
> > dozen or so good use-cases, where careful placement of an existing
> > ASSERT_EXCLUSIVE would not catch what you describe.
> >
>
> Right, I think at this point, I'm not object to merging this into
> kernel, using ASSERT_EXCLUSIVE_*() does provide more chances for us to
> catch bugs. That said, I think it's better if we have some comments
> describing the semantics (or the limitation) of the annotations to avoid
> "mis-use"s (for example, using multiple ASSERT_EXCLUSIVE_WRITER()s for
> one variables in a function). But that doesn't necessarily block the
> merge of this feature, we can always do that later.
>
> Also, I think it's worthwhile to do some experiments on the
> *_{BEGIN,END} interfaces. If you're interested and have cycles to work
> on this, please let me, othwerwise, I can have a look at it.

Because I really think the BEGIN/END interface is error-prone, I was
curious if I could make this work:

         preempt_disable();
         {
                  ASSERT_EXCLUSIVE_WRITER_SCOPED(var);
                  do_sth();
                  raw_cpu_write(var, 1);
                  do_sth_else();
         }
         preempt_enable();

Since all compilers that support TSAN instrumentation support
attribute "cleanup", this works for KCSAN. Half-baked patch:
  https://github.com/melver/linux/commit/d5a510a80b9755909d8b2ccc7bcfdeac99fc0080

Since it's not too intrusive, I'd be fine including this. But I think
you have to come up with the use-cases. :-)

I can send the patch once I'm done with it.

Thanks,
-- Marco


> Thanks!
>
> Regards,
> Boqun
>
>
> > Thanks,
> > -- Marco
> >
> > > Regards,
> > > Boqun
> > >
> [...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOvDrzb%3DhbA2D%2BHW12Jy3LMLfdTrd2H%3DwgYCwQUcZgDzw%40mail.gmail.com.
