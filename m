Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPH32CDAMGQER33E6LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id A530A3B2A04
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 10:09:33 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id s23-20020a170902b197b029011aafb8fbadsf1930287plr.19
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 01:09:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624522172; cv=pass;
        d=google.com; s=arc-20160816;
        b=ygyj6x3bFOrNpWPyhw0pfafrxqPY3TLDUqE7M5kWoVp9LEBlNdATVWXG4o+k7NUEX/
         1VXqUTb5SjQVHu9LuZV5ZAlnyxeV91PrDRod/R1s0WiJh19oUizfLcm2V4Y5siOkzMfh
         rJp+7zYlvVGJcZC+JW1ejOxCOl+DnoGTkYhIbrZd98coYu70wPhHhz385Kh0MoVHZOWu
         Vb2T8uFVGY3Gt9wL2iCJYMg5QdS6Yy4AzcX3r86VghU61yU/fZJP1a3ccxA/ZPrmLA6b
         XZ3LjoSv19FWNqUZiN7cG7mBKd0EM99Rqq9McNL8egVcayq4l+YnqL2H1zn74FvxyynN
         27NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hU6jciXm/T/X3A8jYkuurpE1R4dUbFUunZ42/3bOb2k=;
        b=XiqbvKBRupf4c3Ns8fYe4yBrLEUHY0XEPK0+eu3BArf1hRZMNj7hv7gmd+ijBCclFK
         Txjq2LzF6qtPSbUD1MGBaIbB/4VysTS2W51fAacixDtRSQxMDPtaFr7f4M0FeIjvjM5v
         7bq0qylk9Ycyyxptg0MCNk8UmskS1hLVr7fb+r0GfpdJ3BT30q+ZdsCQCX3lNtNTCpMI
         fLwGutOh+Shf0SQtc7YJBS/E3vNItqoqgpg7a75YalK2suiaZLeIaAZ7SijkZsVaDhsg
         pRV5u7+7l7iHS+TH01p2qMx3h3wvj9XYxA4Ef1vX3OPyI3eYgnFFn6RdvjnrGV8HNBW7
         k1qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kfrjwpeg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hU6jciXm/T/X3A8jYkuurpE1R4dUbFUunZ42/3bOb2k=;
        b=UeKfOzqlFH7Ez2jMvKNQlCmiVT2vFtQ27oOAP2Q1GNa4GbaCDvaAAHxysQMCt1fZtr
         RPhMuKNfq6CWltcL0aUtC5YpnVA2H31Fu1sksSE032BWL1gNEuLOOH9CkB9PdQoqfXKx
         sZhQ4rcCCKLf6nFdMe9pssfVOMLXusVeJn2ZNY8uIDgHIJusGXweLKCrXEa4LxALr4Wa
         tZpw9O30G4OUBN8czb91WVvdEiHyD3Qbnu7FlQFRIUiFhPD2vVaslOdIKbNfGXfPIsvq
         UqUVd6/UFqsW2qVzQZTb0To46e/UXe/MAIYIfts18/imPF2ecuGgUZV+bkPCycvbjx9m
         rEQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hU6jciXm/T/X3A8jYkuurpE1R4dUbFUunZ42/3bOb2k=;
        b=k3vtKlRA/FuJ5VvIKx5BhQe7UmQtc97GvY90gpqjq675uFfYPAd8ascsfAzuX6pYMj
         15b4m8HNYBFRFF1HNZBvei0GFSeSEsUmGJ10zW1tSOpwZhNdV78u2Z8qgE26Tu4cNf6b
         e2zGdOX5eejc5BoX7DqTRFzIJ89dKtW8vQSKpkILzU2al6xr3R9vJLVZtQ0gaxroopPp
         PhS3gaySQiObekwebR1GFoouHW+SHEeKE6y+0PJlXIizGNsN2R4hdgzgLodGFVPzO2Ns
         SVdEG5ra4AByTNHE+SXpAZLv2dJF8zPFviXYa2wY9oFvtMPUzmM/tLWog9wD8Ce4vv2u
         nTMw==
X-Gm-Message-State: AOAM533X+zwrdmCNrNsR54dB6Sf34Vt1QeBO3/pSN1ByIfB4ieo8EFhc
	niegm+WmhAzxVi+ZZiSPr8c=
X-Google-Smtp-Source: ABdhPJyBBqrHLk/D19+vrF4BO4yfLWaqmZupLKbGW3x1JFvf2M5blWy0Ck8mm3i4fJbA7HN2nnR6GA==
X-Received: by 2002:a17:90a:928c:: with SMTP id n12mr4127535pjo.30.1624522172219;
        Thu, 24 Jun 2021 01:09:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4186:: with SMTP id a6ls2575251pgq.6.gmail; Thu, 24 Jun
 2021 01:09:31 -0700 (PDT)
X-Received: by 2002:a63:5d66:: with SMTP id o38mr3712488pgm.444.1624522171615;
        Thu, 24 Jun 2021 01:09:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624522171; cv=none;
        d=google.com; s=arc-20160816;
        b=ECC6vlbJPlUCnRdpPa2xVdEqFa9zmsJ+ksUsvPHOUTiRse9gE/KikgeOf5eALJxfG+
         /XFI/Ql5JsFS08ec9mcjgYs5Rp2OT01VNv13t9b0xEB6+DO0jshuRBA34TpkCrOossgj
         L7u6ahyY0sE4t2yC0D6p4/YA93QSi4lux1/nExAhjd3K9owDEdeMzWqLrIpqR1Go+BM5
         hZpW/V/yzmHorS2C6NAXWpM4MvaKrGEv/CRGKwbkGala89QAg96mnrAoD3uzInYoW5DG
         nMPxx6ZWcQWumx239Rr3UDf/iaYRA0Fepr96o42OP9Xfk6IiZvRagBfhXF0X7rkY9S9Z
         aZIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wrQrLGlWaZrBRPZ22+kfBbiExxWlcXw34p0FAskUQY0=;
        b=0EJezP1/tTJqLu10CqRo6vztT+nopaldbifcgJMnXUrjJW/d7D1p4qDYXuSdJ6v3S+
         GpoTDjVCRdiBrPg5/HBa1VBNEIm4jEFM074GNpEtHZW0igvzs/cUb0YHZw7N1UwoX9Q5
         bMNUrYKSRzlImbOd4Dy6IT5P0tpv5jFjG8zca8RHs14Pt1Zcpjk/8pQYFYVCxu5nsJ1Q
         ebHWuksgOqd7OrJuvVjJdwDzsVr386VFx9ry2+EpPIHsmLoiIOUOkim+kzQxKIQKPSUm
         FiM4tBLB2ohnn6+EqlVk8ve6IN+OVuCrK/0CuWXvfjkmsrbzZjtrW0Ce9j/sMNFcOLPZ
         sb1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kfrjwpeg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id t15si79705plr.0.2021.06.24.01.09.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jun 2021 01:09:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id o17-20020a9d76510000b02903eabfc221a9so4782286otl.0
        for <kasan-dev@googlegroups.com>; Thu, 24 Jun 2021 01:09:31 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr3658179oto.17.1624522171102;
 Thu, 24 Jun 2021 01:09:31 -0700 (PDT)
MIME-Version: 1.0
References: <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com> <YMyC/Dy7XoxTeIWb@elver.google.com>
 <35852e24-9b19-a442-694c-42eb4b5a4387@redhat.com> <YNBqTVFpvpXUbG4z@elver.google.com>
 <01a0161a-44d2-5a32-7b7a-fdb13debfe57@redhat.com> <YNG/8EcdPBfH/Taf@elver.google.com>
 <93e7048a-209f-82f2-8d28-ff8347595695@redhat.com>
In-Reply-To: <93e7048a-209f-82f2-8d28-ff8347595695@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Jun 2021 10:09:19 +0200
Message-ID: <CANpmjNNZ8rQ3W=3hMemrdS_V7fXf4a_mY785eo5XaPNeTngExg@mail.gmail.com>
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Daniel Bristot de Oliveira <bristot@redhat.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kfrjwpeg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Wed, 23 Jun 2021 at 11:10, Daniel Bristot de Oliveira
<bristot@redhat.com> wrote:
> On 6/22/21 12:48 PM, Marco Elver wrote:
> > On Mon, Jun 21, 2021 at 09:25PM +0200, Daniel Bristot de Oliveira wrote:
> >> On 6/21/21 12:30 PM, Marco Elver wrote:
> >>> On Mon, Jun 21, 2021 at 10:23AM +0200, Daniel Bristot de Oliveira wrote:
> >>> [...]
> >>>>> Yes, unlike code/structural coverage (which is what we have today via
> >>>>> KCOV) functional coverage checks if some interesting states were reached
> >>>>> (e.g. was buffer full/empty, did we observe transition a->b etc.).
> >>>>
> >>>> So you want to observe a given a->b transition, not that B was visited?
> >>>
> >>> An a->b transition would imply that a and b were visited.
> >>
> >> HA! let's try again with a less abstract example...
> >
> > Terminology misunderstanding.
> >
> > I mean "state transition". Writing "a->b transition" led me to infer 'a'
> > and 'b' are states, but from below I infer that you meant an "event
> > trace" (viz. event sequence).  So it seems I was wrong.
> >
> > Let me be clearer: transition A -[a]-> B implies states A and B were
> > visited.
>
> right
>
> Hence, knowing that event 'a' occurred is sufficient, and
> > actually provides a little more information than just "A and B were
> > visited".
>
> iff [a] happens only from A to B...
>
> >
> >>
> >>   |   +------------ on --+----------------+
> >>   v   ^                  +--------v       v
> >> +========+               |        +===========+>--- suspend ---->+===========+
> >> |  OFF   |               +- on --<|     ON    |                  | SUSPENDED |
> >> +========+ <------ shutdown -----<+===========+<----- on -------<+===========+
> >>     ^                                    v                             v
> >>     +--------------- off ----------------+-----------------------------+
> >>
> >> Do you care about:
> >>
> >> 1) states [OFF|ON|SUSPENDED] being visited a # of times; or
> >> 2) the occurrence of the [on|suspend|off] events a # of times; or
> >> 3) the language generated by the "state machine"; like:
> >>
> >>    the occurrence of *"on -> suspend -> on -> off"*
> >>
> >>          which is != of
> >>
> >>    the occurrence of *"on -> on -> suspend -> off"*
> >>
> >>          although the same events and states occurred the same # of times
> >> ?
> >
> > They are all interesting, but unrealistic for a fuzzer to keep track of.
> > We can't realistically keep track of all possible event traces. Nor that
> > some state or event was visited # of times.
>
> We can track this easily via RV, and doing that is already on my todo list. But
> now I got that we do not need all these information for the functional coverage.
>
> > What I did mean is as described above: the simple occurrence of an
> > event, as it implies some previous and next state were visited.
> >
> > The fuzzer then builds up knowledge of which inputs cause some events to
> > occur. Because it knows it has inputs for such events, it will then try
> > to further combine these inputs hoping to reach new coverage. This leads
> > to various distinct event traces using the events it has already
> > observed. All of this is somewhat random of course, because fuzzers are
> > not meant to be model checkers.
> >
> > If someone wants something more complex as you describe, it'd have to
> > explicitly become part of the model (if possible?). The problem of
> > coverage explosion applies, and we may not recommend such usage anyway.
>
> I did not mean to make GCOV/the fuzzer to keep track of these information. I was
> trying to understand what are the best way to provide the information that you
> all need.
>
> >> RV can give you all... but the way to inform this might be different.
> >>
> >>>> I still need to understand what you are aiming to verify, and what is the
> >>>> approach that you would like to use to express the specifications of the systems...
> >>>>
> >>>> Can you give me a simple example?
> >>>
> >>> The older discussion started around a discussion how to get the fuzzer
> >>> into more interesting states in complex concurrent algorithms. But
> >>> otherwise I have no idea ... we were just brainstorming and got to the
> >>> point where it looked like "functional coverage" would improve automated
> >>> test generation in general. And then I found RV which pretty much can
> >>> specify "functional coverage" and almost gets that information to KCOV
> >>> "for free".
> >>
> >> I think we will end up having an almost for free solution, but worth the price.
> >>
> >>>> so, you want to have a different function for every transition so KCOV can
> >>>> observe that?
> >>>
> >>> Not a different function, just distinct "basic blocks". KCOV uses
> >>> compiler instrumentation, and a sequence of non-branching instructions
> >>> denote one point of coverage; at the next branch (conditional or otherwise)
> >>> it then records which branch was taken and therefore we know which code
> >>> paths were covered.
> >>
> >> ah, got it. But can't KCOV be extended with another source of information?
> >
> > Not without changing KCOV. And I think we're weary of something like
> > that due to the potential for coverage explosion. -fsanitize-coverage
> > has various options to capture different types of coverage actually, not
> > purely basic block based coverage. (KCOV already supports
> > KCOV_ENABLE_COMPARISONS, perhaps that could help somehow. It captures
> > arguments of comparisons.)
> >
> >>>>>
> >>>>> From what I can tell this doesn't quite happen today, because
> >>>>> automaton::function is a lookup table as an array.
> >>>>
> >>>> It is a the transition function of the formal automaton definition. Check this:
> >>>>
> >>>> https://bristot.me/wp-content/uploads/2020/01/JSA_preprint.pdf
> >>>>
> >>>> page 9.
> >>>>
> >>>> Could this just
> >>>>> become a generated function with a switch statement? Because then I
> >>>>> think we'd pretty much have all the ingredients we need.
> >>>>
> >>>> a switch statement that would.... call a different function for each transition?
> >>>
> >>> No, just a switch statement that returns the same thing as it does
> >>> today. But KCOV wouldn't see different different coverage with the
> >>> current version because it's all in one basic block because it looks up
> >>> the next state given the current state out of the array. If it was a
> >>> switch statement doing the same thing, the compiler will turn the thing
> >>> into conditional branches and KCOV then knows which code path
> >>> (effectively the transition) was covered.
> >
> > Per Dmitry's comment, yes we need to be careful that the compiler
> > doesn't collapse the switch statement somehow. But this should be
> > achievable with a bunch or 'barrier()' after every 'case ...:'.
>
> Changing the "function" will add some overhead for the runtime monitor use-case.
> For example, for the safety-critical systems that will run with a monitor
> enabled to detect a failure and react to it.
>
> But! I can extend the idea of the reactor to receive the successful state
> transitions or create the "observer" abstraction, to which we can attach a
> generic that will make the switch statements. This function can be
> auto-generated by dot2k as well...
>
> This reactor/observer can be enabed/disabled so... we can add as much annotation
> and barriers as we want.
>
> Thoughts?

That sounds reasonable. Simply having an option (Kconfig would be
ideal) to enable the KCOV-friendly version of the transition function
is good enough for the fuzzer usecase. The kernels built for fuzzing
usually include lots of other debug options anyway, and aren't
production kernels.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNZ8rQ3W%3D3hMemrdS_V7fXf4a_mY785eo5XaPNeTngExg%40mail.gmail.com.
