Return-Path: <kasan-dev+bncBCMIZB7QWENRBOPIVSDAMGQEMSWFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id DFD193AB2C8
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 13:38:34 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id f4-20020a0568302044b029044be209a5d7sf488004otp.10
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 04:38:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623929914; cv=pass;
        d=google.com; s=arc-20160816;
        b=GWkd9rHm5SG+rdM5vyfbMbhZTPk3waOem++EjsII2OCDC4ODm4S99rX6FMMTaM4xWw
         a+VjbosoeGOAf63YTgnwPE74ovNSufFq0DEMFXMyWGGTaO862er/Ji/alM0SsqmAbFR8
         I4klKnuj4rET/ntzI1jQlvgilG6jo/gH7JpNQP/aFHauA/zyEodHdrDjsagVNOuBS6vB
         NNQ4hZ9BeIUWxvzSFoHm9NW3LTW+gGmUnUsQKUIl2yyJbF4d/v+5Rf/J/eFsY7O0Ru+7
         2HNLYHw95HFeETH1hpWd2gdhmG6cjxWmefpSpWFUjbrVgGnO5C6Zk4cB8F/BqinpGUbV
         wiSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QaBSGevEFWhG5ZypoAyHDdMAF9FomHw0EEauftP3j8Q=;
        b=La8A4awPT8n14OBCE8hym0CZakMQgxFam2vj1Xn6mYL67LsFRiCSaEPX/MavYbXwDc
         qKflzxwQ+GLcGO/9f/fa49B9xhbG7WbCjqA1IzQEwTXXFofXE7QUo6AO2rxB0Amp+/mH
         NHwKizFxDANrROZdrfpnWV8p0KvnEhMc8h+mEhVl0t5m6LTH/aNjyulrHDMXndmsYITN
         rZaVa73IpNZKMNOlznLIZNTSEyLoL0+tcJububWgl0DFoyLsaHSuOWGOQ1uaFeWbPo4A
         wuHbuiJXw/xs+CHe8eBs2x4lmKnk4+9NfkhKg5KJqvpUBKRTBW8XQ3EbQvWq03lHpKc3
         QWYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NATwsH0M;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QaBSGevEFWhG5ZypoAyHDdMAF9FomHw0EEauftP3j8Q=;
        b=Ap585CiMWkU3XCYe0xk3SlikYv/o9BlKSABwQqGO8TLw/p65401ysuSBAmosisoR+X
         8UqDXzOnrDtLqfXy+CCQA3WavmFd1X9Jt6yxCbjKSC6ysEB5H1i8Mo0nE+VQqsl0eBts
         oWHdb5XwmKqDKRiXI/ng9PBXbLZ/mK7Zz+u7rfM9IvyI9vTGZMBCI5+CUhfBsWpQgbPH
         yLkvt3NmtpMklUP6Ki5/xrAGXCmn7HI2sELwXwZMRBR5SMyfTAr8WvRtF0jV2BxQX345
         cbntP7X4DxLpGNh2X3QzqMIu2cdPKWYnRYs6jcsZDEUObENySryuFF7nx72v2ISfgOcc
         3KTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QaBSGevEFWhG5ZypoAyHDdMAF9FomHw0EEauftP3j8Q=;
        b=qxOhyS9PDK9dk1EB/f5dWtmyCyB1VO4is1RNmtMZBArDjULija3ZSUf+5o6vmfCIKn
         ZSJd2QeVwEtdKqcrDaQRb49KMjJ0uwU0mac0leKD0g0N0FGMofD1Q48tbc29MNm7pQzO
         qFHK9/4EmmQxzpCKM8+pL7q6uecYUFUsLCHIcNQUGrwVXz1JO3agLKEhHyVqVGgdL+Em
         fHCJcUzH2BtHocDctr6/C8xG8fFM5KwDV4pL+2CH8A5CgyZeC2qQNLn+j8dYnOqwmMvG
         QnUM3qEK6H8qxzxbr+anrM4abXv49nVXmK0zmo2qMVjNcH2fa7cZG5yHoP2tVgBu4cyN
         sr0A==
X-Gm-Message-State: AOAM530GNnTnn0LZxCYrETeNH8qHITp1hX3sy15GzO9PEKve7qEkqiKt
	pvPUGhhCcKZCukJ1qzI94aQ=
X-Google-Smtp-Source: ABdhPJwQfgic/TQOvaTDreoCBwwzFKOpFqxn0czodXymZztNZDNkyUj3hkIMsrhEPPLGAyHq6cX8xg==
X-Received: by 2002:a9d:1a8:: with SMTP id e37mr3994057ote.316.1623929913901;
        Thu, 17 Jun 2021 04:38:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a84:: with SMTP id l4ls2691271otq.1.gmail; Thu, 17 Jun
 2021 04:38:33 -0700 (PDT)
X-Received: by 2002:a9d:715c:: with SMTP id y28mr4246513otj.275.1623929913425;
        Thu, 17 Jun 2021 04:38:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623929913; cv=none;
        d=google.com; s=arc-20160816;
        b=iH9XfNvRM4m5Kfft5tpNsLZmGO3+fbubL+TE1I5QlhF+34gjFtlmLqupWOSKgdHeOu
         vF0rhER+U6etOgDQYZC9iup6e+tQYPZLJ9uZokPvhgkI1h1yNeg+1hhtB0swUmPDMSFf
         smysvBEPrGunT0jjRhU6Mof+ntuSqW/jb423v/WZv7Yu8+/u7O8A5ja7UQAQS2PmLnvy
         uu4enyW2gt9AosaTSX/U9AlzlkqMVqwqQI+17mC7dUem3TuzdKcWYmy0z6xUw+ShE12g
         b5aOtk57zPpcomV/DnVmw2hhOoWVwPFL3O6US6JCiA3iEfoOERx17im8D/twAbLfUsbv
         fPBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mdk2K6YNuHKJ6sAQSHbbeZM3FdkcC1jUn1HPsXDQrYs=;
        b=R/1w7Qgk7JYpHqWqcvPe5DsRK3KOdijhbX4IDZfrlVhKnp7j8GyLJz6TIchN77UUmn
         iHAh7WqQdTSZs76DiaoafWVpoiZ0Vw9PlfCgwZhr4vG0vvnDe+In0HcIGoh8pOgqHPfv
         CKBouggUDIDxhKXdQXelbWU2WalsuyGArVmWdZN8DmZfoh2f16Tz6E9S6pWaeydAMdSm
         TmCpncYgPCNR3g8bvAnCQFoTMxst17r/aenU2aWfsISw6BX8kDo1rd+Pz4G8zUa1o7Mu
         qOv4vmkjxZhDMx8jV1E6FsSrjEMZFAMe2ZMvbet/ST3arDkjuMLcpHljyzfb3UY7PlMq
         B/Rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NATwsH0M;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id d13si672362oti.0.2021.06.17.04.38.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 04:38:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id o19so4400845qtp.5
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 04:38:33 -0700 (PDT)
X-Received: by 2002:ac8:5dce:: with SMTP id e14mr4504876qtx.43.1623929912762;
 Thu, 17 Jun 2021 04:38:32 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
In-Reply-To: <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jun 2021 13:38:21 +0200
Message-ID: <CACT4Y+YEVQQ7sGePt_k=byu91tXh=OB=vZ13PB3Q3=G91b4oog@mail.gmail.com>
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, bristot@redhat.com, 
	syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NATwsH0M;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::830
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Jun 17, 2021 at 1:20 PM 'Marco Elver' via syzkaller
<syzkaller@googlegroups.com> wrote:
>
> [+Daniel, just FYI. We had a discussion about "functional coverage"
> and fuzzing, and I've just seen your wonderful work on RV. If you have
> thought about fuzzing with RV and how coverage of the model impacts
> test generation, I'd be curious to hear.]
>
> Looks like there is ongoing work on specifying models and running them
> along with the kernel: https://lwn.net/Articles/857862/
>
> Those models that are run alongside the kernel would have their own
> coverage, and since there's a mapping between real code and model, a
> fuzzer trying to reach new code in one or the other will ultimately
> improve coverage for both.
>
> Just wanted to document this here, because it seems quite relevant.
> I'm guessing that "functional coverage" would indeed be a side-effect
> of a good RV model?

Ha! That's interesting. RV can indeed be a source of high-quality
meaningful states.

The idea behind states is to "multiply" code coverage by the dimension
of states, right? Instead of checking "have we covered this code?", we
will be checking "have we covered this code in this state or not?".
This will require some way of figuring what code is affected by what
model, right? Otherwise it still can lead to state explosion I think.
E.g. if we have 5 models with 5 states each, it will increase the
amount of effective coverage by 5^5.

The preemption model in the example is "global" (per-task), but there
are also per-object models. I remember we discussed sockets as an
example on LPC. But I don't remember what was proposed API for tieing
states to objects. Maybe that API will help with code regions as
well?...


> Previous discussion below.
>
> Thanks,
> -- Marco
>
> On Wed, 19 May 2021 at 22:24, Marco Elver <elver@google.com> wrote:
> > On Wed, 19 May 2021 at 20:53, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > On Wed, May 19, 2021 at 11:02:43AM +0200, Marco Elver wrote:
> > > > On Tue, 18 May 2021 at 22:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > [...]
> > > > > > All the above sound like "functional coverage" to me, and could be
> > > > > > implemented on top of a well-thought-out functional coverage API.
> > > > > > Functional coverage is common in the hardware verification space to
> > > > > > drive simulation and model checking; for example, functional coverage
> > > > > > could be "buffer is full" vs just structural (code) coverage which
> > > > > > cannot capture complex state properties like that easily.
> > > > > >
> > > > > > Similarly, you could then say things like "number of held locks" or
> > > > > > even alluding to your example (5) above, "observed race on address
> > > > > > range". In the end, with decent functional coverage abstractions,
> > > > > > anything should hopefully be possible.
> > > > >
> > > > > Those were in fact the lines along which I was thinking.
> > > > >
> > > > > > I've been wondering if this could be something useful for the Linux
> > > > > > kernel, but my guess has always been that it'd not be too-well
> > > > > > received because people don't like to see strange annotations in their
> > > > > > code. But maybe I'm wrong.
> > > > >
> > > > > I agree that it is much easier to get people to use a tool that does not
> > > > > require annotations.  In fact, it is best if it requires nothing at all
> > > > > from them...
> > > >
> > > > While I'd like to see something like that, because it'd be beneficial
> > > > to see properties of the code written down to document its behaviour
> > > > better and at the same time machine checkable, like you say, if it
> > > > requires additional effort, it's a difficult sell. (Although the same
> > > > is true for all other efforts to improve reliability that require a
> > > > departure from the "way it used to be done", be it data_race(), or
> > > > even efforts introducing whole new programming languages to the
> > > > kernel.)
> > >
> > > Fair point!  But what exactly did you have in mind?
> >
> > Good question, I'll try to be more concrete -- most of it are
> > half-baked ideas and questions ;-), but if any of it makes sense, I
> > should maybe write a doc to summarize.
> >
> > What I had in mind is a system to write properties for both functional
> > coverage, but also checking more general properties of the kernel. The
> > latter I'm not sure about how useful. But all this isn't really used
> > for anything other than in debug builds.
> >
> > Assume we start with macros such as "ASSERT_COVER(...)" (for
> > functional coverage) and "ASSERT(...)" (just plain-old assertions).
> > The former is a way to document potentially interesting states (useful
> > for fuzzers to reach them), and the latter just a way to just specify
> > properties of the system (useful for finding the actual bugs).
> > Implementation-wise the latter is trivial, the former requires some
> > thought on how to expose that information to fuzzers and how to use
> > (as Dmitry suggested it's not trivial). I'd also imagine we can have
> > module-level variants ("GLOBAL_ASSERT*(...)") that monitor some global
> > state, and also add support for some subset of temporal properties
> > like "GLOBAL_ASSERT_EVENTUALLY(precond, eventually_holds)" as
> > suggested below.
> >
> > I guess maybe I'd have to take a step back and just ask why we have no
> > way to write plain and simple assertions that are removed in non-debug
> > builds? Some subsystems seem to roll their own, which a 'git grep
> > "#define ASSERT"' tells me.
> >
> > Is there a fundamental reason why we shouldn't have them, perhaps
> > there was some past discussion? Today we have things like
> > lockdep_assert_held(), but nothing to even write a simple assert
> > otherwise. If I had to guess why something like ASSERT is bad, it is
> > because it gives people a way to check for unexpected conditions, but
> > if those checks disappear in non-debug builds, the kernel might be
> > unstable. Therefore every possible state must be handled and we must
> > always be able to recover. The argument in favor is, if the ASSERT()s
> > are proven invariants or conditions where we'd recover either way, and
> > are only there to catch accidental regressions during testing; and in
> > non-debug builds we don't suffer the performance overheads.
> ..
> > > > > > My ideal abstractions I've been thinking of isn't just for coverage,
> > > > > > but to also capture temporal properties (which should be inspired by
> > > > > > something like LTL or such), on top of which you can also build
> > > > > > coverage. Then we can specify things like "if I observe some state X,
> > > > > > then eventually we observe state Y", and such logic can also just be
> > > > > > used to define functional coverage of interest (again all this
> > > > > > inspired by what's already done in hardware verification).
> > > > >
> > > > > Promela/spin provides an LTL interface, but of course cannot handle
> > > > > much of RCU, let alone of the entire kernel.  And LTL can be quite
> > > > > useful.  But in a runtime system, how do you decide when "eventually"
> > > > > has arrived?  The lockdep system does so by tracking entry to idle
> > > > > and to userspace execution, along with exit from interrupt handlers.
> > > > > Or did you have something else in mind?
> > > >
> > > > For coverage, one could simply await the transition to the "eventually
> > > > state" indefinitely; once reached we have coverage.
> > > >
> > > > But for verification, because unlike explicit state model checkers
> > > > like Spin, we don't have the complete state and can't build an
> > > > exhaustive state-graph, we'd have to approximate. And without knowing
> > > > exactly what it is we're waiting for, the simplest option would be to
> > > > just rely on a timeout, either part of the property or implicit. What
> > > > the units of that timeout are I'm not sure, because a system might
> > > > e.g. be put to sleep.
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss%3DEZ4xAbrHnMwdt5g%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYEVQQ7sGePt_k%3Dbyu91tXh%3DOB%3DvZ13PB3Q3%3DG91b4oog%40mail.gmail.com.
