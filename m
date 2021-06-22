Return-Path: <kasan-dev+bncBCMIZB7QWENRBKMIY2DAMGQERTFTLHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 371CB3AFD15
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 08:33:15 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id f40-20020a9d03ab0000b0290452c397f983sf3601064otf.21
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 23:33:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624343594; cv=pass;
        d=google.com; s=arc-20160816;
        b=xGpKS8zEgUtNfezmPEA7fBFmGYWhq/cY+lDgjDDYgZHA/k7LRqjBfZra3wGv+JOPgS
         xM08R7w0A9NvDe0z0CXpGnyyHM55RuWHgzBD8M4VyCG6mQHTjayNFiefG6XGokG2bur4
         1ndsiLeWUpyCfMNdmoMBW39i7iL57cgt3IvEFA1P0WuwPRWNTu0pULOqYtoqluoW6ZUC
         RQBRXYJjdfj8OkFPiYSYOOy/PB9RVb+nnZJWuKC2/Uuw7edDFnAisY5mMdN6RxSc/FRU
         MqGR2KHkMgK4K1Blw3gbC2+XS5H5mWN4VZ9rDUavIcCvb/1YDXNcjZ5Fhpa93TGzF2Cq
         Bp4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Zl51WhXRbSxjw6VmmKEJYNdvZ+De1E3Yt9HxyvHlH9g=;
        b=p1RgzFE6V6XtpFYAItSdR2Bhe2iW+pijIaFjWl9qTr2w0APNdBSdMl73sB0YwkTxPv
         omwDCaI9JT61LENDSkf4ItcxbJTjgRmWZ51nBHDzkl6M+vd9a3LiDmbUvz1fZDJXtLfx
         Q+i3nMqhKoTHvdKOfMLN81qkjrMfxQmj9ANjpGaupP+6TaW1WZ8rS86e9IXeu77Y/aJ1
         f3aXGacL4nRJGJdd7JWdOjjOxh4LRHQKJRxGFUewTpcaHj5P19ZrAS8QYqrhXY89W6e/
         +So47XZw/+uYNM4BtxWeEaXTbb1aTjvY8Ae1aIEMYGZVlfbAX2TDGr448AoljsrNER5O
         i+uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jKqpgD4y;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zl51WhXRbSxjw6VmmKEJYNdvZ+De1E3Yt9HxyvHlH9g=;
        b=ZXBr9LRU8614RLXU8BovdNcFw1grSkmvzcPAghQqAPJjAyhJx9fitk1trn26s3/VOR
         YcStxeiomnvZriXr1BlO42Nb38Nc6Zx1Wzdj7r+HMY3CFYsjbyZARhx8674f1adbE0SU
         vzdEDIjjh083aA70Q4uApaGeCcUgFa6cIYOuTGBI0bba/+hBXHUYhDF7m/maDrpZ165s
         XCz6abqna+1XnVShuK7J+fXWOGyFfWEoQoBHf2epvtl30iH5pHDt71hVtqqjhq6duJ51
         lB0iCVDJ03+CZ/DfdrirzoOsMPtzaGPV1KN1SvuLTRjAfR6CZInKTkmEZrWVr2kPeXRE
         Pufg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zl51WhXRbSxjw6VmmKEJYNdvZ+De1E3Yt9HxyvHlH9g=;
        b=RQM4BrUuWtaiw9q2VEUEWxagXA+KjK8CtxtQ+1snbHZwJjTX01GHWuOB1DwipWKmKo
         eO7GsLc9xtpnSxVh7R5RQKDVCg4YSNtm4vRacY1Txl1dxc/Cv2TikPRMcmpoDUjbmwry
         sIj+QxTlsp3FSfVa3tAwrl4FBb5bTN2h5IMHzoC0kopJ6Xk7dX7n/wuePPjZk3xDf+Iq
         eRKwZ8ZW+AkyAgpoMkx2Gwn8ipVFS1LwB6htTq2TVfM4mqRuE2kid3d1/dXRZdmkowq7
         gYEGqxsWYaUZFSBaxxRygfHK10c46TN5gPortVQg9CBnCf02Jl6G0V+Y4n5wUuWbB4cj
         7zwA==
X-Gm-Message-State: AOAM531kJd5AzmZrUnWvP2ADnPttmWwvOdHPQstdQCEXp8wf0zxg8+67
	GkuUJBBngF2VBXs2YykGNdc=
X-Google-Smtp-Source: ABdhPJw6mh7GPToS4SV0o0Y2rQIUhA63UovmlUgANYPeI2lJHbyfwWLajwrGWrKL1MUqkIny39eUfA==
X-Received: by 2002:a05:6830:248a:: with SMTP id u10mr1768496ots.264.1624343593724;
        Mon, 21 Jun 2021 23:33:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:604c:: with SMTP id v12ls3777456otj.6.gmail; Mon, 21 Jun
 2021 23:33:13 -0700 (PDT)
X-Received: by 2002:a9d:4689:: with SMTP id z9mr1766649ote.129.1624343593312;
        Mon, 21 Jun 2021 23:33:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624343593; cv=none;
        d=google.com; s=arc-20160816;
        b=g5KHopuz3Xv67rUnIPKDoKv2tPrDLQi/IOzua9+PGvf/r6yHvMG9ihwkyEZqMGOQ7I
         c7qfzku69cR16RKh6T8wMETr6WMcH0fVvCsa4d4xIut0XtAzri8MR3BLuKNWuvessIl2
         xfiwNGYzMiUuKtkAx0/PJ+eJgCL5xyZ6zQ2l4Hn1bvPOFwbpiEqlxR35J1yKqDXAI74r
         yxyWfki+1KX9BepTK0ZqIyfHFW5LuQ+/LxG9p2j3uBILrw0itCckImtVbWDmrHeW8j3P
         9ndd80EpmZue2Z5EGOjR9Oi9/m7va+mQPuclBnZo/sOrIKNomy7g6jjj8rKGLZt2j83N
         w3Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3G07ZNwIzU+ekJbLHOs00ib6qVxDlz3JM+F3J6xC1VQ=;
        b=Dj0ujYekIpu0xv1F7mM4exzFlRPqm0b9WX3G8uNKbv2ulNKPZXdbrIp/E9SCb+QD7q
         ZQWhLkzp/eTzCkfO3J2FtwUCnmGngUgEDkCKDAWDtljYVZd9FJswe2kisY9JnsjxWt+f
         2LJ57qLtYdhe7RQH1fBQNEpZ0TqOzVP6GytEftcYN3WLZ9u0XgeBFwkzy97wESHHngIt
         +QFHMMVUhu+LswvtT1VEpjUkBok4mVbJIdYNTVEBp5seTdu0VL8lSJNR2jGxJj1XGG60
         YWB6q88PPyZBIAg3YbxiR/36yPJ4bVmDBWz2StlL+YkEawWpxk9rjEjY78kl1uHxdKrJ
         4jfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jKqpgD4y;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id x195si111429oia.0.2021.06.21.23.33.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jun 2021 23:33:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id d196so36736363qkg.12
        for <kasan-dev@googlegroups.com>; Mon, 21 Jun 2021 23:33:13 -0700 (PDT)
X-Received: by 2002:a37:8081:: with SMTP id b123mr2615763qkd.231.1624343592648;
 Mon, 21 Jun 2021 23:33:12 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com> <YMyC/Dy7XoxTeIWb@elver.google.com>
 <CACT4Y+YTh=ND_cshGyVi98KiY=pkg3WKrpE__Cn+K0Wgmuyv+w@mail.gmail.com> <8069d809-b133-edbf-4323-45c45a1c3c9d@redhat.com>
In-Reply-To: <8069d809-b133-edbf-4323-45c45a1c3c9d@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jun 2021 08:33:00 +0200
Message-ID: <CACT4Y+ZWwT8Fk2T58saPaK-yfJ_Zxtvg57KE2ubsKG9Jn2TSng@mail.gmail.com>
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Daniel Bristot de Oliveira <bristot@redhat.com>
Cc: Marco Elver <elver@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jKqpgD4y;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735
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

On Mon, Jun 21, 2021 at 10:39 AM Daniel Bristot de Oliveira
<bristot@redhat.com> wrote:
>
> On 6/19/21 1:08 PM, Dmitry Vyukov wrote:
> > On Fri, Jun 18, 2021 at 1:26 PM Marco Elver <elver@google.com> wrote:
> >>
> >> On Fri, Jun 18, 2021 at 09:58AM +0200, Daniel Bristot de Oliveira wrote:
> >>> On 6/17/21 1:20 PM, Marco Elver wrote:
> >>>> [+Daniel, just FYI. We had a discussion about "functional coverage"
> >>>> and fuzzing, and I've just seen your wonderful work on RV. If you have
> >>>> thought about fuzzing with RV and how coverage of the model impacts
> >>>> test generation, I'd be curious to hear.]
> >>>
> >>> One aspect of RV is that we verify the actual execution of the system instead of
> >>> a complete model of the system, so we depend of the testing to cover all the
> >>> aspects of the system <-> model.
> >>>
> >>> There is a natural relation with testing/fuzzing & friends with RV.
> >>>
> >>>> Looks like there is ongoing work on specifying models and running them
> >>>> along with the kernel: https://lwn.net/Articles/857862/
> >>>>
> >>>> Those models that are run alongside the kernel would have their own
> >>>> coverage, and since there's a mapping between real code and model, a
> >>>> fuzzer trying to reach new code in one or the other will ultimately
> >>>> improve coverage for both.
> >>>
> >>> Perfect!
> >>>
> >>>> Just wanted to document this here, because it seems quite relevant.
> >>>> I'm guessing that "functional coverage" would indeed be a side-effect
> >>>> of a good RV model?
> >>>
> >>> So, let me see if I understood the terms. Functional coverage is a way to check
> >>> if all the desired aspects of a code/system/subsystem/functionality were covered
> >>> by a set of tests?
> >>
> >> Yes, unlike code/structural coverage (which is what we have today via
> >> KCOV) functional coverage checks if some interesting states were reached
> >> (e.g. was buffer full/empty, did we observe transition a->b etc.).
> >>
> >> Functional coverage is common in hardware verification, but of course
> >> software verification would benefit just as much -- just haven't seen it
> >> used much in practice yet.
> >> [ Example for HW verification: https://www.chipverify.com/systemverilog/systemverilog-functional-coverage ]
> >>
> >> It still requires some creativity from the designer/developer to come up
> >> with suitable functional coverage. State explosion is a problem, too,
> >> and naturally it is impractical to capture all possible states ... after
> >> all, functional coverage is meant to direct the test generator/fuzzer
> >> into more interesting states -- we're not doing model checking after all.
> >>
> >>> If that is correct, we could use RV to:
> >>>
> >>>  - create an explicit model of the states we want to cover.
> >>>  - check if all the desired states were visited during testing.
> >>>
> >>> ?
> >>
> >> Yes, pretty much. On one hand there could be an interface to query if
> >> all states were covered, but I think this isn't useful out-of-the box.
> >> Instead, I was thinking we can simply get KCOV to help us out: my
> >> hypothesis is that most of this would happen automatically if dot2k's
> >> generated code has distinct code paths per transition.
> >>
> >> If KCOV covers the RV model (since it's executable kernel C code), then
> >> having distinct code paths for "state transitions" will effectively give
> >> us functional coverage indirectly through code coverage (via KCOV) of
> >> the RV model.
> >>
> >> From what I can tell this doesn't quite happen today, because
> >> automaton::function is a lookup table as an array. Could this just
> >> become a generated function with a switch statement? Because then I
> >> think we'd pretty much have all the ingredients we need.
> >>
> >> Then:
> >>
> >> 1. Create RV models for states of interests not covered by normal code
> >>    coverage of code under test.
> >>
> >> 2. Enable KCOV for everything.
> >>
> >> 3. KCOV's coverage of the RV model will tell us if we reached the
> >>    desired "functional coverage" (and can be used by e.g. syzbot to
> >>    generate better tests without any additional changes because it
> >>    already talks to KCOV).
> >>
> >> Thoughts?
> >
> > I think there is usually already some code for any important state
> > transitions. E.g. I can't imagine how a socket can transition to
> > active/listen/shutdown/closed states w/o any code.
>
> makes sense...
>
> > I see RV to be potentially more useful for the "coverage dimensions"
> > idea. I.e. for sockets that would be treating coverage for a socket
> > function X as different coverage based on the current socket state,
> > effectively consider (PC,state) as feedback signal.
>
> How can RV subsystem talk with KCOV?

KCOV collects a trace of covered PCs. One natural way for this
interface would be a callback that allows injecting RV state events
into the KCOV trace. To make it possible to associate states with
code, these events need to be scoped, e.g.:

void kcov_state_start(int model, int state);
void kcov_state_end(int model, int state);

There is no prior art that I am aware of, so I assume it will require
some experimentation and research work to figure out exactly what
interface works best, if it works at all, how much it helps fuzzing,
is it a good metric for assessing testing coverage, etc.

> > But my concern is that we don't want to simply consider combinations
> > of all kernel code multiplied by all combinations of states of all RV
> > models.
>
> I agree! Also because RV monitors will generally monitor an specific part of the
> code (with exceptions for models like the preemption one).
>
> Most likely this will lead to severe feedback signal
> > explosion.So the question is: how do we understand that the socket
> > model relates only to this restricted set of code?
> >
> Should we annotate a model, saying which subsystem it monitors/verify?

Yes. The main question I see: how to specify what "subsystem" is.

Besides dynamic scoping we could use static mapping of models to code.
E.g. socket model covers net/core/*.c and net/tpc/*.c. Then maybe we
don't need dynamic scopes (?) however then it becomes tricker for
models that are associated with objects. Namely, if we traced
different states for different objects, what object does current
executions belong to? Does it belong to any of these at all?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZWwT8Fk2T58saPaK-yfJ_Zxtvg57KE2ubsKG9Jn2TSng%40mail.gmail.com.
