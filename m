Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4G7VSDAMGQECQDBHAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BD303AB260
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 13:20:19 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id b12-20020a056808010cb029021dde407eb3sf279641oie.13
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 04:20:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623928818; cv=pass;
        d=google.com; s=arc-20160816;
        b=mSmDCI8JshKQbtLW11MV25Ola2FgHeyxuyr1zNF40EbAZkKAlN98D7/tySLcJXclw7
         Hg5j517IzdNIpG1MKuWTpanJFHA3U/eYxquv7/u6gQ/v9unmCJADFk7K+mqqLQ+TR6YH
         logYcWpsch3yAEm5IrglccN+fsVUeu1xV1gCF5zCIvn5KReKADkiAv1Go5uBlUl86dyH
         r4XDytH9FMe9H4VcJdwtwJ8iGiHAN5AcQyNitMtWulbP/xmqcxtTzadmYazXwr1RHiGb
         0rvCyufevpf6hKhpzy6UYW0Cs2MEoE8jy6QihR2LDRc0+R6rUgmsnIOqvRGtcLPv7Uae
         MEEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=a5kgnc5qtMRSbnDHGy7qSGmTRKCkGgU6mQXHhYT4FFM=;
        b=bJ1buYE93jEN/GMme968r1n7Uds00M1uFIKu34BTasY1lhyhKQWNbzuPubb+pGbPs3
         PGfHRnd7kB1+wFXm16Gh3YxcxMrEN2h9d4xacnOFViPvw4YZ84lQJh+9tnbZlOJ1QSCp
         jLpwQPXH1RjUvbCLB8Fd41q2pIROsOxMc/jAU57vLemNwbkpxmfOXrg7+3eNccEX1QR4
         aM1p0eMDVGip3PAwwh/SOvrODKpHh9qSKVPUeMBjssWkR18Lj8SMVar5mg8deOcv4JOA
         1+5y3pJQbACjfHcdpG9IxBCrCG6OQuyqpXXNSV+P/LoPP9I0qhUrtFqURIAR6i0gLJIf
         /vCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bVWLaNJA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a5kgnc5qtMRSbnDHGy7qSGmTRKCkGgU6mQXHhYT4FFM=;
        b=FFse/3TLGHO3dTtS61pMnREIit1Fip6kS92/vEQ2o2pDN+t3w84CPPBHJgNDjkLrJB
         GuoZhQUb/n3U6HHDnGymFmlfPeIwlGR5c3jfGUM+8FshXnfp34WOvuzlNRUcCIyEzcEK
         Emi4osi4oSdJSOmE6HkA12h/5Ho+nDHQgaOK86K1kHc4uT9gPCJjBpCtgA7VXYQlCfo3
         5ErfLm0jCxfQRw0/4jYEYkckve6+Ftge74EbVf8P7wj2QqEkz2c7SSELHwFQ6Vyr4Mxu
         xgFg/13dI4/IuMZ2dsr88loY2jd9pll2dc8EI62Z3FzA/n6OeTgdMOTfuxKxUwqDm0Or
         R5cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a5kgnc5qtMRSbnDHGy7qSGmTRKCkGgU6mQXHhYT4FFM=;
        b=ZQI3b9UB+0hxBytS5u5e9GbnTLC4hOJzocCOqIpeHZe/ooEToy0hzAkPtUCNdQrGFq
         fSSvsCvIEU0m4/0cidslyR72f8i3lUIgRTD3DVf+GKJ8Gcbbxm4lpxqCHhDjF4ZH1gyt
         RNsLQ63q5RnxbDBkF0Z3wv/7HihWS+Jm8PJDYVvQ94kuzQEPrs9KewsaEeHy3ZNs8S2m
         6pW8zNGttxw4Rv1CpH9ySqa77etYGtYP1423r2XMRgTseAj3N0RemCOf7iaNjmeTgL1J
         bPs56fDtSceynSXaw1mZ6GjUuzX9iLh1PmIuGmsV/EcSSvIrnUvfHk7PLCv+EJdCU5W3
         Qfeg==
X-Gm-Message-State: AOAM530CeTCRoA8t12eoHLEP2e+403rbaXRlPlzkiTYcAm4Tk3uk5O7n
	VXCYY/GvdDp5l9tCHPboRfE=
X-Google-Smtp-Source: ABdhPJwegY+Q6fRPMQcDoynJ0isQ8zM6lrnPuLvdCFOFzA9i5XZCL9AxFa/M91mDOQbHKrtoH9uRDg==
X-Received: by 2002:a05:6830:15cd:: with SMTP id j13mr4034192otr.147.1623928816586;
        Thu, 17 Jun 2021 04:20:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ca8c:: with SMTP id x12ls689085ooq.11.gmail; Thu, 17 Jun
 2021 04:20:16 -0700 (PDT)
X-Received: by 2002:a4a:9b0f:: with SMTP id a15mr4003676ook.4.1623928816200;
        Thu, 17 Jun 2021 04:20:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623928816; cv=none;
        d=google.com; s=arc-20160816;
        b=l70DzXqgibq6wj1ozXW3Nq55dtRZbqNt3U0cA3pNCutIk/doX8pfSy3CKqdAkHvkvC
         jt9R0W3UucMHy7fLkOBbrk2HJkMvP4YqEMewg0wXP+IEHwD0epqJu0guAdq8wa5+Xm9B
         j7NU1b470jYvDGklTT5rqawZZfUWHzsWrhlg1oTUZdF3gT7TskwnkZg/hDNlaa5cgRje
         sVRRsTEDvkxnGNviZLiNKZXqf3cjncfmPelahiTaURpVP83yHMNSxCkhsxg/MLN2o0Xh
         Ozp5BL6nVMpaZunc8dgAf892F+jVwXdeAGTO6QzPDlUtJfqDKsHDXaN7Xg767WJckQ9V
         hfaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BMuz+6EbRX0GYCNZ/NIh2vrv+u+nXTsBXh9kSJ1GCn0=;
        b=Kj+WCx82bzZFjtl9zhwjsB2XR4Yl1hOlHdnJSJkT11LPeWAf8LkFInmzp1ergHoCAu
         /jdJ2+S2qI5jgbTLB+u8Bs0XtFN8vG9CxoPOrlhhJ0eLG3etblQvMpUO9KSQeaYlmO4f
         ECTVPZZGI0NrmB0RAw4anoChmX/hjzVJUpAPQShlX834BmBvku0wDUyjaq/R5YXm9hw2
         zSLTK+ZvwB37dpPR/Ik3IxgH5swRFKNErSjjwx/5h6yGeaty9z7pZpyl9pmlY1hXHKtM
         spGkhNwtV+TgRWX5osscGP1XUCuhD1TmJ7sOLqvXl3zoa4zbRu+8OZoUGr5K9+9Ap+Y/
         uVIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bVWLaNJA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 25si357157oiz.0.2021.06.17.04.20.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 04:20:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id q5-20020a9d66450000b02903f18d65089fso5734259otm.11
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 04:20:16 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr4086458oto.17.1623928815711;
 Thu, 17 Jun 2021 04:20:15 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
In-Reply-To: <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jun 2021 13:20:04 +0200
Message-ID: <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
Subject: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: "Paul E. McKenney" <paulmck@kernel.org>, bristot@redhat.com
Cc: Dmitry Vyukov <dvyukov@google.com>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bVWLaNJA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
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

[+Daniel, just FYI. We had a discussion about "functional coverage"
and fuzzing, and I've just seen your wonderful work on RV. If you have
thought about fuzzing with RV and how coverage of the model impacts
test generation, I'd be curious to hear.]

Looks like there is ongoing work on specifying models and running them
along with the kernel: https://lwn.net/Articles/857862/

Those models that are run alongside the kernel would have their own
coverage, and since there's a mapping between real code and model, a
fuzzer trying to reach new code in one or the other will ultimately
improve coverage for both.

Just wanted to document this here, because it seems quite relevant.
I'm guessing that "functional coverage" would indeed be a side-effect
of a good RV model?

Previous discussion below.

Thanks,
-- Marco

On Wed, 19 May 2021 at 22:24, Marco Elver <elver@google.com> wrote:
> On Wed, 19 May 2021 at 20:53, Paul E. McKenney <paulmck@kernel.org> wrote:
> > On Wed, May 19, 2021 at 11:02:43AM +0200, Marco Elver wrote:
> > > On Tue, 18 May 2021 at 22:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > [...]
> > > > > All the above sound like "functional coverage" to me, and could be
> > > > > implemented on top of a well-thought-out functional coverage API.
> > > > > Functional coverage is common in the hardware verification space to
> > > > > drive simulation and model checking; for example, functional coverage
> > > > > could be "buffer is full" vs just structural (code) coverage which
> > > > > cannot capture complex state properties like that easily.
> > > > >
> > > > > Similarly, you could then say things like "number of held locks" or
> > > > > even alluding to your example (5) above, "observed race on address
> > > > > range". In the end, with decent functional coverage abstractions,
> > > > > anything should hopefully be possible.
> > > >
> > > > Those were in fact the lines along which I was thinking.
> > > >
> > > > > I've been wondering if this could be something useful for the Linux
> > > > > kernel, but my guess has always been that it'd not be too-well
> > > > > received because people don't like to see strange annotations in their
> > > > > code. But maybe I'm wrong.
> > > >
> > > > I agree that it is much easier to get people to use a tool that does not
> > > > require annotations.  In fact, it is best if it requires nothing at all
> > > > from them...
> > >
> > > While I'd like to see something like that, because it'd be beneficial
> > > to see properties of the code written down to document its behaviour
> > > better and at the same time machine checkable, like you say, if it
> > > requires additional effort, it's a difficult sell. (Although the same
> > > is true for all other efforts to improve reliability that require a
> > > departure from the "way it used to be done", be it data_race(), or
> > > even efforts introducing whole new programming languages to the
> > > kernel.)
> >
> > Fair point!  But what exactly did you have in mind?
>
> Good question, I'll try to be more concrete -- most of it are
> half-baked ideas and questions ;-), but if any of it makes sense, I
> should maybe write a doc to summarize.
>
> What I had in mind is a system to write properties for both functional
> coverage, but also checking more general properties of the kernel. The
> latter I'm not sure about how useful. But all this isn't really used
> for anything other than in debug builds.
>
> Assume we start with macros such as "ASSERT_COVER(...)" (for
> functional coverage) and "ASSERT(...)" (just plain-old assertions).
> The former is a way to document potentially interesting states (useful
> for fuzzers to reach them), and the latter just a way to just specify
> properties of the system (useful for finding the actual bugs).
> Implementation-wise the latter is trivial, the former requires some
> thought on how to expose that information to fuzzers and how to use
> (as Dmitry suggested it's not trivial). I'd also imagine we can have
> module-level variants ("GLOBAL_ASSERT*(...)") that monitor some global
> state, and also add support for some subset of temporal properties
> like "GLOBAL_ASSERT_EVENTUALLY(precond, eventually_holds)" as
> suggested below.
>
> I guess maybe I'd have to take a step back and just ask why we have no
> way to write plain and simple assertions that are removed in non-debug
> builds? Some subsystems seem to roll their own, which a 'git grep
> "#define ASSERT"' tells me.
>
> Is there a fundamental reason why we shouldn't have them, perhaps
> there was some past discussion? Today we have things like
> lockdep_assert_held(), but nothing to even write a simple assert
> otherwise. If I had to guess why something like ASSERT is bad, it is
> because it gives people a way to check for unexpected conditions, but
> if those checks disappear in non-debug builds, the kernel might be
> unstable. Therefore every possible state must be handled and we must
> always be able to recover. The argument in favor is, if the ASSERT()s
> are proven invariants or conditions where we'd recover either way, and
> are only there to catch accidental regressions during testing; and in
> non-debug builds we don't suffer the performance overheads.
..
> > > > > My ideal abstractions I've been thinking of isn't just for coverage,
> > > > > but to also capture temporal properties (which should be inspired by
> > > > > something like LTL or such), on top of which you can also build
> > > > > coverage. Then we can specify things like "if I observe some state X,
> > > > > then eventually we observe state Y", and such logic can also just be
> > > > > used to define functional coverage of interest (again all this
> > > > > inspired by what's already done in hardware verification).
> > > >
> > > > Promela/spin provides an LTL interface, but of course cannot handle
> > > > much of RCU, let alone of the entire kernel.  And LTL can be quite
> > > > useful.  But in a runtime system, how do you decide when "eventually"
> > > > has arrived?  The lockdep system does so by tracking entry to idle
> > > > and to userspace execution, along with exit from interrupt handlers.
> > > > Or did you have something else in mind?
> > >
> > > For coverage, one could simply await the transition to the "eventually
> > > state" indefinitely; once reached we have coverage.
> > >
> > > But for verification, because unlike explicit state model checkers
> > > like Spin, we don't have the complete state and can't build an
> > > exhaustive state-graph, we'd have to approximate. And without knowing
> > > exactly what it is we're waiting for, the simplest option would be to
> > > just rely on a timeout, either part of the property or implicit. What
> > > the units of that timeout are I'm not sure, because a system might
> > > e.g. be put to sleep.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss%3DEZ4xAbrHnMwdt5g%40mail.gmail.com.
