Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGXISWCQMGQEJVJR4RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C4F53897D7
	for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 22:25:00 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id l9-20020a1709030049b02900f184d9d878sf6121186pla.16
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 13:25:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621455899; cv=pass;
        d=google.com; s=arc-20160816;
        b=CWIJmM73+SCK8QZDb1XHFe5ys4I7RNASbS38+scX+jBwJcn571fiL4axOo6176d3Hu
         73pJyDwdDQxiIWd15/L8CqPFlhmeKLmr3tC3JWwYpgSpXvzqFlaK7aiIYU1MX3QSgWTQ
         O8FBysAjzpu8clM0Yq1w5md1rKYdU/f9AQY7uiwdKIH62HL7e8RVPkD3F/3ntPwfCllx
         mTJDQ4GQb9UWwt2jjgB3n3uWAVxczr15hDpb2SIAsrQvPytK/MQsNR4Rmpux03nASCde
         pdHyFKswpbpSmWzrH/zOR1edLgUSixuDTMrd1Yb3kqMrDvqIohp9nL5f9D9Em9691Nmh
         wypw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pJTpN7e1iUaPhA5rEZ2bwpc2bZaMIRt7Tia/4Bygm7w=;
        b=RrLpsIZWfV8Bji+FkWilqTfZyp8zUWO9cIWWUCpxfMkoa12lxkq4HhoeT1PyuJkyEf
         hMf77txG09mJ+rvKly/g5zGP+tsMJ/2EAauZi0Y36DSlEPEXfHcLQxCiXf0H/JHlTb4D
         ZcjTGGedrDr8AkkBsRysicE0bJTLl1qUZMlPmRlceHWe8dfc4ZPZ5E/5yZPSdgF7IUMB
         KFF+OGuqxo/AGDxmhUhDsKjqN/QmPrYW3RLtdSlHXVj6ve0nwE6RoU8ZD3zYUl/Mkpw3
         BZMCqiT3H99NJmenhF5rqpFufju0VKMZQYyiRNWh7pPVjonhShMGlz33w0hfpILwTfD+
         n77A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gjyo1+KM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pJTpN7e1iUaPhA5rEZ2bwpc2bZaMIRt7Tia/4Bygm7w=;
        b=Or6wWa0cxSTf18+c39ve8H0klJBZYRIAHPIvJ0CdlSalSCYHOs1PVlibB/X3bwXcfd
         RH7TaOiV3cN4M4CIiOiyOgkTN14RR1jBtdfXXESh2eRGv8xuSGyb0fuMRg80M5CFJsvE
         aWaphTJg+IplMr+Wlgna3NwxVNcw3s3OhwwaRQCFKoicaTNAy+6kJBgvxKMISTlHZ6O5
         OenAmWmppucKdMSWi4wHRpKXi60xfLdSxeZYgDn4VjDy8XpXNg19ATru/6oPiUwvkhJZ
         P6GB0L6M7st81uR+JYr3deWDhHMZOOlj5xtoKImv2Py0eLfP1NNL7oty5qKkwCJy7dAu
         fVmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pJTpN7e1iUaPhA5rEZ2bwpc2bZaMIRt7Tia/4Bygm7w=;
        b=tdK3wyTzqOCN3KlSgpnbnv0ZksrGtL/5MMTE5lb4YGC6yjcCo2IYX34mxoL0kygiTV
         Xkydlakg1bSONnrAvpvq2V2A9V0XuI4+lVXcsjk/Xw/ydIoCXt4a28IGjv3qXdUPkWms
         +DJ0JwcV02WMW6/UsytfwpKmG6dqpqSMrhuNVgwp35ElX5oYI0QKxO8iVq6a80AzXP3m
         ozCvbPgLTvw8Igr7hhQiVWpXG6JcO20PTEraoCMdhenX7vBBIodB67b5UbndcbL2kNfT
         oBIi5PEHn7cawgbmMys3O7M3avWC2PWWnFW0z5wQ0jMbMykzOMbDrv/du1yBCSHrCOYf
         7nlA==
X-Gm-Message-State: AOAM532uHsmTAZm378BfV5njR9TWIYWPZ48sCdtHaWtP/o9EJ0tCOjSY
	xmbqlBqQCwfNqWwkXhIQTA8=
X-Google-Smtp-Source: ABdhPJwK/G0c/1wkxyG/tytC8R3yBgHPyde7jIssrMyqL9IBmJX8GYmSk8WZ7y1MwA2QXkUWvIFxWA==
X-Received: by 2002:a05:6a00:1c63:b029:2a8:b80a:1244 with SMTP id s35-20020a056a001c63b02902a8b80a1244mr861600pfw.72.1621455898985;
        Wed, 19 May 2021 13:24:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b185:: with SMTP id s5ls239351plr.3.gmail; Wed, 19
 May 2021 13:24:58 -0700 (PDT)
X-Received: by 2002:a17:90a:ec03:: with SMTP id l3mr1184091pjy.194.1621455898346;
        Wed, 19 May 2021 13:24:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621455898; cv=none;
        d=google.com; s=arc-20160816;
        b=FT4mifKbAk0P+Rz+k3lfXRB842q2SOoac9EiUSMrmj7PgHIJdr8POnI1njLGQP0uGO
         FF3+D1j3xyxUhCGlbaMml/nPgvW8OJpENOPgr/K0ZAYSEwuhSzT1bHvMgkc/HQNY6iJH
         BIW2WxDjhMeMmb5ztyAcfknifBtOw1+4EVr/HlFi02ccV/CTa1i4MOUGJC4zxmZvWKG7
         i/pjYUUiX+F5j/jCr3pEXYkG8pEy9JMfmGc50c8vFAvlQUOqgsJfR1qPZC0QmS56BNBp
         GVepaZxJ/JNwf4SnavdbN0K4sUF8mt/qRC6HvKcTFFppsZ8/+Ub1InCATrtauNfpHwMI
         UF8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p/KAxrwu5CoFzG/3wkGlEbHJb7Leca27rifaeW6Qq18=;
        b=lJCx7xgoZQpBP+U6HGwbQH7h3eHLkDhAegxD4WYEhWLyXFj08xo/vpDEWui4PBlh1a
         +WZX4c1iTP5t+nOl2f98JWfaHup+36W30XWU7Dw7Wmn/ZXgtzRbyRDQjLZ1HPpbzkMRj
         BGKnRyQU3NxiB8HlAjHv1SYsFrFQTKO8itGlCvaKzqNVrH/rW8lU660heOLC9VFAaDqX
         kjELnb4GWxjt0DWdBnsCoPbW/2Hi3Szo1wnWN8pDU47UWtsHAy4zXqzprvFaka8XrJeF
         OxGAbyFnqUvJLK37/nGM0ntIGjcGPFbtJpLrRznuFoRGudPnCvoL/f8Dkop4jdLgBw5t
         bPBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gjyo1+KM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id n13si108605plf.1.2021.05.19.13.24.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 May 2021 13:24:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id c3so14278759oic.8
        for <kasan-dev@googlegroups.com>; Wed, 19 May 2021 13:24:58 -0700 (PDT)
X-Received: by 2002:a05:6808:f94:: with SMTP id o20mr760355oiw.121.1621455897793;
 Wed, 19 May 2021 13:24:57 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 May 2021 22:24:46 +0200
Message-ID: <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Gjyo1+KM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Wed, 19 May 2021 at 20:53, Paul E. McKenney <paulmck@kernel.org> wrote:
> On Wed, May 19, 2021 at 11:02:43AM +0200, Marco Elver wrote:
> > On Tue, 18 May 2021 at 22:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> > [...]
> > > > All the above sound like "functional coverage" to me, and could be
> > > > implemented on top of a well-thought-out functional coverage API.
> > > > Functional coverage is common in the hardware verification space to
> > > > drive simulation and model checking; for example, functional coverage
> > > > could be "buffer is full" vs just structural (code) coverage which
> > > > cannot capture complex state properties like that easily.
> > > >
> > > > Similarly, you could then say things like "number of held locks" or
> > > > even alluding to your example (5) above, "observed race on address
> > > > range". In the end, with decent functional coverage abstractions,
> > > > anything should hopefully be possible.
> > >
> > > Those were in fact the lines along which I was thinking.
> > >
> > > > I've been wondering if this could be something useful for the Linux
> > > > kernel, but my guess has always been that it'd not be too-well
> > > > received because people don't like to see strange annotations in their
> > > > code. But maybe I'm wrong.
> > >
> > > I agree that it is much easier to get people to use a tool that does not
> > > require annotations.  In fact, it is best if it requires nothing at all
> > > from them...
> >
> > While I'd like to see something like that, because it'd be beneficial
> > to see properties of the code written down to document its behaviour
> > better and at the same time machine checkable, like you say, if it
> > requires additional effort, it's a difficult sell. (Although the same
> > is true for all other efforts to improve reliability that require a
> > departure from the "way it used to be done", be it data_race(), or
> > even efforts introducing whole new programming languages to the
> > kernel.)
>
> Fair point!  But what exactly did you have in mind?

Good question, I'll try to be more concrete -- most of it are
half-baked ideas and questions ;-), but if any of it makes sense, I
should maybe write a doc to summarize.

What I had in mind is a system to write properties for both functional
coverage, but also checking more general properties of the kernel. The
latter I'm not sure about how useful. But all this isn't really used
for anything other than in debug builds.

Assume we start with macros such as "ASSERT_COVER(...)" (for
functional coverage) and "ASSERT(...)" (just plain-old assertions).
The former is a way to document potentially interesting states (useful
for fuzzers to reach them), and the latter just a way to just specify
properties of the system (useful for finding the actual bugs).
Implementation-wise the latter is trivial, the former requires some
thought on how to expose that information to fuzzers and how to use
(as Dmitry suggested it's not trivial). I'd also imagine we can have
module-level variants ("GLOBAL_ASSERT*(...)") that monitor some global
state, and also add support for some subset of temporal properties
like "GLOBAL_ASSERT_EVENTUALLY(precond, eventually_holds)" as
suggested below.

I guess maybe I'd have to take a step back and just ask why we have no
way to write plain and simple assertions that are removed in non-debug
builds? Some subsystems seem to roll their own, which a 'git grep
"#define ASSERT"' tells me.

Is there a fundamental reason why we shouldn't have them, perhaps
there was some past discussion? Today we have things like
lockdep_assert_held(), but nothing to even write a simple assert
otherwise. If I had to guess why something like ASSERT is bad, it is
because it gives people a way to check for unexpected conditions, but
if those checks disappear in non-debug builds, the kernel might be
unstable. Therefore every possible state must be handled and we must
always be able to recover. The argument in favor is, if the ASSERT()s
are proven invariants or conditions where we'd recover either way, and
are only there to catch accidental regressions during testing; and in
non-debug builds we don't suffer the performance overheads.

Thoughts?

Thanks,
-- Marco

> > > > My ideal abstractions I've been thinking of isn't just for coverage,
> > > > but to also capture temporal properties (which should be inspired by
> > > > something like LTL or such), on top of which you can also build
> > > > coverage. Then we can specify things like "if I observe some state X,
> > > > then eventually we observe state Y", and such logic can also just be
> > > > used to define functional coverage of interest (again all this
> > > > inspired by what's already done in hardware verification).
> > >
> > > Promela/spin provides an LTL interface, but of course cannot handle
> > > much of RCU, let alone of the entire kernel.  And LTL can be quite
> > > useful.  But in a runtime system, how do you decide when "eventually"
> > > has arrived?  The lockdep system does so by tracking entry to idle
> > > and to userspace execution, along with exit from interrupt handlers.
> > > Or did you have something else in mind?
> >
> > For coverage, one could simply await the transition to the "eventually
> > state" indefinitely; once reached we have coverage.
> >
> > But for verification, because unlike explicit state model checkers
> > like Spin, we don't have the complete state and can't build an
> > exhaustive state-graph, we'd have to approximate. And without knowing
> > exactly what it is we're waiting for, the simplest option would be to
> > just rely on a timeout, either part of the property or implicit. What
> > the units of that timeout are I'm not sure, because a system might
> > e.g. be put to sleep.
> >
> > Also see Dmitry's answer, where he has concerns adding more dimensions
> > to coverage.
>
> And I must of course defer to Dmitry's much greater experience with this
> sort of thing.
>
>                                                         Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMskihABCyNo%3DcK5c0vbNBP%3DfcUO5-ZqBJCiO4XGM47DA%40mail.gmail.com.
