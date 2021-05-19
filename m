Return-Path: <kasan-dev+bncBCJZRXGY5YJBBL53S2CQMGQECSIOTIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 187FE3899C0
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 01:22:25 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id b5-20020a0cc9850000b02901eece87073bsf10149663qvk.21
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 16:22:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621466544; cv=pass;
        d=google.com; s=arc-20160816;
        b=b6W3oksBu5LWYrleB4zQUUB5WZM2OZphcbB8lec6W65rvklzWI+3s4hkUavclLe/IE
         +znMyBci35D1K0qA/CJe1fRKxe3+pTcBzk4KOZ9YedQ/oGho1lPNut9Cjqn1MOoy/1Sz
         I8aPGy8I5kJE2e9LSwvUXeqLkZHoLuDbjSQhG6x/so/YrmvPau2moyOkaeTaqXeDF1/q
         UjNG/4Xo4LtTSNcL/fjpNSia9xCvU7c3kfKQHAxG/IQudF0To39akTSlcOziunwTiGIw
         zXc0daz1p+fx2jXUC7Qqah+8umpM4BbKCJuwywtO+ctvYh0OZGItFEyPWXBOb5A4p+g4
         k00w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=cEyZkBQ+3lazO7YOCgRZID2nkkKBluqhuG/jkmSzT14=;
        b=sAnwUI4S0V8aHuf+BrgOvz2Hwv9wWCf3Hkx4UsR/Bl++TvcQZRMPA1ag44VzayYA0H
         dEINvFFNViNiyHMIhcNx40wLtpZhacNBuxLZsCY9j3vKVwAQ+1wZLk7kloja4C7X8W1/
         W0NvU7ZlHAC1CanAXEqPFEgNVtFhaUD4Wxs+2nNMI+pzoDkJYYAHCDHMY29BFY0GdPeB
         s4nUlZYWaxbDQI716n7RJ+RnOFjPoG9zFMdP98ymMVwYipw4Xzxdg+KwFbrU41hebk2g
         PPlOKNVsmdlNG/vHiv+xTR0sdskZ1ysoVBeJIfIbioSI2hZ9uoPcco0/rER3Y2AeIfg6
         PFWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W5G32jzh;
       spf=pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cEyZkBQ+3lazO7YOCgRZID2nkkKBluqhuG/jkmSzT14=;
        b=PsQHij3IaGTLS89Z7ZG5cigF9fl39dFo29P7JQIIb25isqbmp0ju/B9LOTMr+SPxWS
         e4eo6Z4PpT77URAMQet5GgK1XtNYMMJqpsS8IrPjxyvgq7foRbCgjH/hF1PQYYALGvJm
         kuuOwLmJJRESnUS43YICHzH3fbvHDetHeXaOM93W/L5T/5XFrCOWg0S/Ixt53tOJMZb8
         OPIsu1KYyFlC0e0zJyghbhtK5cBgUARGbjg7sz37eX9/fJLIRLtVkm5dB8N+3G5iilZj
         DbS99y6zKp61W0PyMAWKxcKG7KkpI3IS/gPtnbH2qPDDm8O2r4PRjQWsUSzQI7U+SGuH
         aRFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cEyZkBQ+3lazO7YOCgRZID2nkkKBluqhuG/jkmSzT14=;
        b=c7iYJhraxbJb2CsHYp5jml7aE9f1oQm7gUpjARAUFcd85ZSUCwiZIS4bVv/s2cHORD
         LgRmL0/62MJtgK+ZXBk9/4BfkjTRlozI7fQjyewJL1bH2yRpN3uVR4tIOMLuCObLdvT1
         dcTp27HHvfJKw33ab5yVSqN7tvigROf8VtJQrHZGdN8h7S84TNCLOXZtq6s9RzqTH0yL
         TLe4cPl1+t2xVFHCoQNPPAt6/9HgmUJd4gS9SkhpWuZ0bzWNmkgDxC0/VbFv8d5cFrXZ
         TqSu42v4ExbJLE1OpUyShB92YdCZl4EE1NAMCxyk55Og3qS1KuqnQEGI8SfgHMhv906O
         Mwlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sYLeT5sdDZJGCF87rSTv1feKmzJ8obmBs7kzEREFvPQSJ+k5V
	sjsxgWTDkS7gBPCzbqFphlA=
X-Google-Smtp-Source: ABdhPJxl72UkfZaA/QEJvrBO2RSELhXkIJqT1+WeZvpXFgMY8ZPSmDGor5bb+sNc5Dic/qn32BybkA==
X-Received: by 2002:a05:620a:2215:: with SMTP id m21mr2052661qkh.61.1621466543889;
        Wed, 19 May 2021 16:22:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f017:: with SMTP id l23ls619617qkg.2.gmail; Wed, 19 May
 2021 16:22:23 -0700 (PDT)
X-Received: by 2002:a37:63d0:: with SMTP id x199mr667138qkb.105.1621466543453;
        Wed, 19 May 2021 16:22:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621466543; cv=none;
        d=google.com; s=arc-20160816;
        b=sQyKvfOTFEgzHatiIR0HN9JApTAkGsZg6YT4UQFlX+MOg40U0ibvFUIlQrnZEJBnvr
         Lc6bYLZZhVNtkEmg6kUlcFMR9Erlp4wfaMJHOb62dGiQ/tYkSqHpuumk6v8KOxi8cd4w
         hPimBIIFEbXFrNJblKZRrvJ2Rlsac83dEWHIxl/sm0h2CknpN7NTX5kim+8aCu1EuITd
         +R0gunY3SNHwxMKEbsyoccFjWX5KGPoTxnmrD16LWT7DQJy2Lo6rd1CcEP70OmAa/3Z1
         dl/VsW7LR5953wJggr0vDE9x+afXD4JY1nFG31DO6YNPO/OIZgxeSg9FyFQ3tkSsDOYO
         8f4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pS/D1yW+jd7UGpdJmRb1ACz0dY8jH5MiQ0i5n4aJG4Q=;
        b=ENYPvHt1ZnPX8S471SkJLUsdHbRpBQlX/TTBDlaaIxjwlKkgmec7E/OQJxiI93lI3u
         E8zdhuqqRANtxZbAfOJsZv5H1jpX8QpJOZi5fRLLYtFC8lFF9+FZny5Y9tlZhezx9Nf0
         oSn7cZaKSlVX8GUvdxoWUkemuz/8+6kUg0DuR/qOAC1lBKFkVpN7wudi+kkCbyEnnVwZ
         wcInYFtEvQ/ZxL+YIuGSQ2p6h3FzUQER26hDMMNSnT10nKkhXFnSLTyAdSSHrmDEz8qe
         GRsdIM3hlHJXYhbHsecB3WZ+hjDNxyA72plU7wBUAotlCvd/cffTKlWoF+K836h3Y7Nc
         APSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W5G32jzh;
       spf=pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z13si147493qtq.4.2021.05.19.16.22.23
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 May 2021 16:22:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6628E611BD;
	Wed, 19 May 2021 23:22:22 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 336905C0138; Wed, 19 May 2021 16:22:22 -0700 (PDT)
Date: Wed, 19 May 2021 16:22:22 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
Message-ID: <20210519232222.GD4441@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=W5G32jzh;       spf=pass
 (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, May 19, 2021 at 10:24:46PM +0200, Marco Elver wrote:
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
> 
> Thoughts?

One thing that I personally might find useful would be a way of marking
sections of interest from a concurrency viewpoint.  "Here is region
A and here is region B.  You are not done validating until you have a
goodly number of samples showing concurrent execution of A with A, B
with B, and A with B."  Easy to imagine, perhaps somewhat more difficult
to implement efficiently.  To say nothing of designing a good way of
marking the regions.  Exactly where is A?  Well, I likely am concerned
about particular operations...

So please treat this as mostly speculation.

						Thanx, Paul

> Thanks,
> -- Marco
> 
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
> > >
> > > Also see Dmitry's answer, where he has concerns adding more dimensions
> > > to coverage.
> >
> > And I must of course defer to Dmitry's much greater experience with this
> > sort of thing.
> >
> >                                                         Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210519232222.GD4441%40paulmck-ThinkPad-P17-Gen-1.
