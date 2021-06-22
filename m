Return-Path: <kasan-dev+bncBC7OBJGL2MHBB577Y2DAMGQESWHTR3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 2473D3B01BC
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 12:48:24 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id e9-20020a5d6d090000b0290119e91be97dsf9575549wrq.1
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 03:48:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624358904; cv=pass;
        d=google.com; s=arc-20160816;
        b=sGojzl3nFAQh1vKHNsWDRkegg2I/4BDOiTP6yG47VMb/I8EcwNSEbwy7ccTQYyRXnd
         +I10to/9ghW2WNMbjKcYuq7NylGVvi4OWgakzrWII6xyD2lGfte9P9KsloGZ9xln3le2
         GrYUxOohx6BcegK84mIUxUNPmTS1e8zWId9ptxomJ4XBE3AP6J3i828O3pc0KHuLVU/j
         rJymx74nwhMr18vgaMv3RGfaeuxjHavOY5vec1VyORJqxnlQ19rk5Jt19w626cQ+GQR7
         9TkxZwEMag3e2pYkWSEMzvQRGGjmxKXCfY/3l4veyUcDS4R7Q6kfPJy3YPaE7cANQ4lW
         lmUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hdg3wFMDp0FkJRB/BCTjxUi2Sv5TVOcFECDRGAhbfQY=;
        b=pqWotnPBn+J4PvY4wMBkqcNTx8RRL9w5LV058tcGHlMzzAR0v4sfNz/uwlLuvtq2gG
         qG523iPJwCf7/1DHGixdy+HhUTvKbggIQ8OcDlO3Ui3vErW+N85n8spLnuVpx5Aa18Ub
         7/Y83NG6ewrq/wVDlfhOp2Os0sgPDPdVMQ1SS/UHN/wktd+9IFUVsF9t2Y5Hk+SQSKbV
         WUvYkPIKw+Y1oud1Xfek+XNdFnQXY64D8zKczYG315JHMexRAp9b/ceemsq0Fk+wN4Bg
         jLvddydA9VvcLn+ws+u762tz8i4kzkuLtq83wGWbvB7Qi8BzniHn4HOsAs+8rzM/IQjJ
         z1qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c+3wpe4A;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hdg3wFMDp0FkJRB/BCTjxUi2Sv5TVOcFECDRGAhbfQY=;
        b=jcWF7RER/xBU9Ze1On6W/bVQET2iJohyLNqhaHinYJQWcNqkBvHXmarkVRlRCtaCGN
         z2iXmKoZt2Tz6cf8Nnt7Tr88iXQA3T7lxwpqbKZGDJKlwbyqO4x0TjCPg9YsKnOiRZME
         JNtDfv+h/1dMsoZU2fxKIWkJsPJcFdMFBlPfy1knpAq51BQq4zimFWwNTUun56j2SIAx
         vTzSY46uN71WLZECMDOxnaxJ5/tT8pGT1wRITLD+hm1HqJsaSy38EZXOepXrylj9K7Ds
         rJl5nAFFfLyMfGSN/U3EN0eURrXvw9uBRYWH47/VGxrmLrckDUNgFpw0fEsCTm+iSwNl
         Pe8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hdg3wFMDp0FkJRB/BCTjxUi2Sv5TVOcFECDRGAhbfQY=;
        b=n9S36yFTuc1h7dswjA2sHymIqtGImCcV3OvVQKAC8cKAaZQEpp1U5Uza/RexCo+rll
         lz90GDmtIQgyXzJYkFgplLKjMm5BNgXZaD0GOakdw8NkEpfTieWbJJtriaXRWKkTrGSS
         p7Yp99jngOgmm/jxw9CMUPfnlknHjHcmBBWIpBv9tnFjzDn51aEWkl7DsMvK1Q9rQ6h3
         zfE2w385U1AmWuhbA7xKUOjIi6bnYB4B8uYyi/iYitQVffRqWBkDbVCITkve4rGQ7Ph6
         OZ3vagcn80KT/gmzK/HX2Jc9ltiQprBbZH2WTCkxPLS/A6bAGi9R0K7arPjg7y/G453C
         LzMg==
X-Gm-Message-State: AOAM533RyrzAvtJoquBXOqsLMZhEsLznuB6JfbBJZ4cMu+034UB5QAme
	Hp6PDybcyJKLve6DYUA0ntM=
X-Google-Smtp-Source: ABdhPJxwEQkqMbS8KGCOni7lfp0p0kcRbHWc6iRWfnV3CxqGPFw4VXiIY8W1EQnBUpJkpgtEutTC+g==
X-Received: by 2002:a1c:544e:: with SMTP id p14mr3880597wmi.152.1624358903899;
        Tue, 22 Jun 2021 03:48:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:edc4:: with SMTP id v4ls893597wro.0.gmail; Tue, 22 Jun
 2021 03:48:23 -0700 (PDT)
X-Received: by 2002:adf:f587:: with SMTP id f7mr3992486wro.253.1624358902939;
        Tue, 22 Jun 2021 03:48:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624358902; cv=none;
        d=google.com; s=arc-20160816;
        b=r5Q9y/nKnNv7c2dirm6KRcOfRqG/zGOqwk5YYLQ3hLg5/3ms+om+HSBLwhmOAOMhJ0
         Cs72yIabI8XcSPjujbNsKVzU1Ay8aQ0a40QZG+f+aEnkTzIe6qu86pWhjs9iYLWGyveC
         PFLdlrl6g6r9zHBnzmuURJo93/rGojj1LYzija2ZPdIv5BRtCpkiDdkX4OHIdlI1vR6z
         x2v8tXyk+bG3glsiGbT8Fj5j+CEMbfuqP3N1U0pWkxKfWz6zPTFK/T45dgTFJjoSc8eT
         i7kapaOboT/BreEOfKNKRxWT0LxMD9AxLdF7A8si9qXZbn92nmYwzf++nzoRRQciQdWh
         0iRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NxykBNeGwcOrdeucRq1YtpuFobyHaujkbqCNSvgnwdM=;
        b=IIf9CofKGIjHrG2YZvVtV6sPUj/Vv4HUUTjPptHgXabczc3a+kX8aJErVW6vX4KPBM
         uvHFiQCX9WvHNcEsdkHf1Azn2/G68O5RgtQc5ay2ylf2WnGpJKeq/ZpKp15NZFAVzL9z
         MavuiDRBEvXGaCWIZ+uHLP96eprU7pdJjD8aZg2xNBPc0VToZQDgzZxaqgGbNRetNxsw
         LphyhSa0DhMKgJb1kILAnbS7coqKpOw/S3YYu66TzRs86upjtartznA8b2ygl3c9T5cT
         GxT9l3vkhZGyl7d888vczB2gL+MjSv2mcpKUOx4+8qfD1xcRE0HWsx2AR9fNfEiFty9q
         Hl7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c+3wpe4A;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id c26si119731wmr.1.2021.06.22.03.48.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 03:48:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id u5-20020a7bc0450000b02901480e40338bso1306861wmc.1
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 03:48:22 -0700 (PDT)
X-Received: by 2002:a1c:2601:: with SMTP id m1mr3704670wmm.185.1624358902396;
        Tue, 22 Jun 2021 03:48:22 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:cd02:f0e6:eb27:e1e5])
        by smtp.gmail.com with ESMTPSA id o26sm1913119wms.27.2021.06.22.03.48.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 22 Jun 2021 03:48:21 -0700 (PDT)
Date: Tue, 22 Jun 2021 12:48:16 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Daniel Bristot de Oliveira <bristot@redhat.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
Message-ID: <YNG/8EcdPBfH/Taf@elver.google.com>
References: <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com>
 <YMyC/Dy7XoxTeIWb@elver.google.com>
 <35852e24-9b19-a442-694c-42eb4b5a4387@redhat.com>
 <YNBqTVFpvpXUbG4z@elver.google.com>
 <01a0161a-44d2-5a32-7b7a-fdb13debfe57@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <01a0161a-44d2-5a32-7b7a-fdb13debfe57@redhat.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=c+3wpe4A;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Mon, Jun 21, 2021 at 09:25PM +0200, Daniel Bristot de Oliveira wrote:
> On 6/21/21 12:30 PM, Marco Elver wrote:
> > On Mon, Jun 21, 2021 at 10:23AM +0200, Daniel Bristot de Oliveira wrote:
> > [...]
> >>> Yes, unlike code/structural coverage (which is what we have today via
> >>> KCOV) functional coverage checks if some interesting states were reached
> >>> (e.g. was buffer full/empty, did we observe transition a->b etc.).
> >>
> >> So you want to observe a given a->b transition, not that B was visited?
> > 
> > An a->b transition would imply that a and b were visited.
> 
> HA! let's try again with a less abstract example...

Terminology misunderstanding.

I mean "state transition". Writing "a->b transition" led me to infer 'a'
and 'b' are states, but from below I infer that you meant an "event
trace" (viz. event sequence).  So it seems I was wrong.

Let me be clearer: transition A -[a]-> B implies states A and B were
visited. Hence, knowing that event 'a' occurred is sufficient, and
actually provides a little more information than just "A and B were
visited".

> 
>   |   +------------ on --+----------------+
>   v   ^                  +--------v       v
> +========+               |        +===========+>--- suspend ---->+===========+
> |  OFF   |               +- on --<|     ON    |                  | SUSPENDED |
> +========+ <------ shutdown -----<+===========+<----- on -------<+===========+
>     ^                                    v                             v
>     +--------------- off ----------------+-----------------------------+
> 
> Do you care about:
> 
> 1) states [OFF|ON|SUSPENDED] being visited a # of times; or
> 2) the occurrence of the [on|suspend|off] events a # of times; or
> 3) the language generated by the "state machine"; like:
> 
>    the occurrence of *"on -> suspend -> on -> off"*
> 
>          which is != of
> 
>    the occurrence of *"on -> on -> suspend -> off"*
> 
>          although the same events and states occurred the same # of times
> ?

They are all interesting, but unrealistic for a fuzzer to keep track of.
We can't realistically keep track of all possible event traces. Nor that
some state or event was visited # of times.

What I did mean is as described above: the simple occurrence of an
event, as it implies some previous and next state were visited.

The fuzzer then builds up knowledge of which inputs cause some events to
occur. Because it knows it has inputs for such events, it will then try
to further combine these inputs hoping to reach new coverage. This leads
to various distinct event traces using the events it has already
observed. All of this is somewhat random of course, because fuzzers are
not meant to be model checkers.

If someone wants something more complex as you describe, it'd have to
explicitly become part of the model (if possible?). The problem of
coverage explosion applies, and we may not recommend such usage anyway.

> RV can give you all... but the way to inform this might be different.
> 
> >> I still need to understand what you are aiming to verify, and what is the
> >> approach that you would like to use to express the specifications of the systems...
> >>
> >> Can you give me a simple example?
> > 
> > The older discussion started around a discussion how to get the fuzzer
> > into more interesting states in complex concurrent algorithms. But
> > otherwise I have no idea ... we were just brainstorming and got to the
> > point where it looked like "functional coverage" would improve automated
> > test generation in general. And then I found RV which pretty much can
> > specify "functional coverage" and almost gets that information to KCOV
> > "for free".
> 
> I think we will end up having an almost for free solution, but worth the price.
> 
> >> so, you want to have a different function for every transition so KCOV can
> >> observe that?
> > 
> > Not a different function, just distinct "basic blocks". KCOV uses
> > compiler instrumentation, and a sequence of non-branching instructions
> > denote one point of coverage; at the next branch (conditional or otherwise)
> > it then records which branch was taken and therefore we know which code
> > paths were covered.
> 
> ah, got it. But can't KCOV be extended with another source of information?
 
Not without changing KCOV. And I think we're weary of something like
that due to the potential for coverage explosion. -fsanitize-coverage
has various options to capture different types of coverage actually, not
purely basic block based coverage. (KCOV already supports
KCOV_ENABLE_COMPARISONS, perhaps that could help somehow. It captures
arguments of comparisons.)

> >>>
> >>> From what I can tell this doesn't quite happen today, because
> >>> automaton::function is a lookup table as an array.
> >>
> >> It is a the transition function of the formal automaton definition. Check this:
> >>
> >> https://bristot.me/wp-content/uploads/2020/01/JSA_preprint.pdf
> >>
> >> page 9.
> >>
> >> Could this just
> >>> become a generated function with a switch statement? Because then I
> >>> think we'd pretty much have all the ingredients we need.
> >>
> >> a switch statement that would.... call a different function for each transition?
> > 
> > No, just a switch statement that returns the same thing as it does
> > today. But KCOV wouldn't see different different coverage with the
> > current version because it's all in one basic block because it looks up
> > the next state given the current state out of the array. If it was a
> > switch statement doing the same thing, the compiler will turn the thing
> > into conditional branches and KCOV then knows which code path
> > (effectively the transition) was covered.
 
Per Dmitry's comment, yes we need to be careful that the compiler
doesn't collapse the switch statement somehow. But this should be
achievable with a bunch or 'barrier()' after every 'case ...:'.

> [ the answer for this points will depend on your answer from my first question
> on this email so... I will reply it later ].
> 
> -- Daniel
> 
> >>> Then:
> >>>
> >>> 1. Create RV models for states of interests not covered by normal code
> >>>    coverage of code under test.
> >>>
> >>> 2. Enable KCOV for everything.
> >>>
> >>> 3. KCOV's coverage of the RV model will tell us if we reached the
> >>>    desired "functional coverage" (and can be used by e.g. syzbot to
> >>>    generate better tests without any additional changes because it
> >>>    already talks to KCOV).
> >>>
> >>> Thoughts?
> >>>
> >>> Thanks,
> >>> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YNG/8EcdPBfH/Taf%40elver.google.com.
