Return-Path: <kasan-dev+bncBCMIZB7QWENRBL5AW6DAMGQERITTAHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B0413AD9BD
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Jun 2021 13:08:33 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id e19-20020a170902ed93b0290110a7ccff51sf3528588plj.20
        for <lists+kasan-dev@lfdr.de>; Sat, 19 Jun 2021 04:08:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624100911; cv=pass;
        d=google.com; s=arc-20160816;
        b=cc2i3C08um62cHoTbP82rubfK+pQ5nuU5jiwYuifCfL+dP/74Sca4ev+xJy/QmjalH
         d0sYPH3/SKY7S8CIMG1iGum5eW0/Zbk/riztTRZHxv1Kwi1U0rvHfo7nrrqUzJsLc9h5
         J6pb7MFnr8CjPr79c9mbHhk9tZWtA8LoekIp0gVoKMVmbCXdY8V882kVz6zXp6jolCoU
         CvYonnZh98iQ0zcJ7BSz4Bpm+ykFTOBz1eJTDKziAFxpUJ2d3kQc+g/kKY4Ry9HBB1xZ
         aqT8O0NXI//mH0qwlBseXyH9nEtehHyYay2XAfVG797zn+M3PV4AfVH4b6AeTTfNiK4j
         XTKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kUb5hwZ5dAura82ST+SpJrjtha8tfbWPGcQLeUCAtZQ=;
        b=k/ddrq+0aK0h12NKCjmS6Ldck2A+q6I8tWJZBt4AD/MB3NTS2pPssh2hJAIadNsALF
         X0hJkazVNYeGuweuh0Npxlu5VvxRB6k2VVo9xVPYrtXv+oEdXtS0Czj8HQjf8s78WJG5
         WRRaVoCE8i04/LRFg/BU07iSPd9GAWqiVnGoXnzuoSJ4DNBjCif4V1KZwrLy3OMvDQhp
         gtCIOh5v0LXllPQiOCgrx4DOKlGsnMKTU+mxa2+ttYhIMxBErKdX1Q85sU7tv4qa4P1q
         IUStXm8XIoEv8LeRC1kLDNJPvdziCkYLH37vusqd9lp9DgbpGyFXan7zyMnAjg+bZEQk
         9W2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cb8Ghqd5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kUb5hwZ5dAura82ST+SpJrjtha8tfbWPGcQLeUCAtZQ=;
        b=N15UnIuvY+3/tpsYM10Bvr8sPKFNwfOKwIHWvv6sodFyBInrj8dVjNG3ymaHBAs218
         kM5UmZYVY//U9S6804XZ/okINtq5uQq6SnlWwkfpuZtedv/myymoGGUlCg+3A3Pc4Ouk
         2+ppIQYBAKF4juUIE9ifmvSkYee2YmrEVDF1lItJX7AVa9sQwho8LTks8TjkG5UexJeO
         feEGDIQCEEPQikFqoc0qPcgCj4I8uxgAfbHtl5xEaKv9Qacwa8fQWkzpmvO8K6pdP/cd
         8G5IbroBi5m/3XA9NfhEpGbOYdqri/435e8SbrFNSPbh0K4KMVl3lxhTjiwuXKnNuD9g
         sFjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kUb5hwZ5dAura82ST+SpJrjtha8tfbWPGcQLeUCAtZQ=;
        b=hcwR4mcP8ybbXI4S+FpmClUSDqe+4VGXIwAGo4mxtdMQcHxSNLOOSn83wsiQTeuCmz
         vAizj/+QpXQbOdhRu3nOcoexrqYntcsg2OUugst5jvBs+MgM0JZ266/LBFtdOA5iaJDy
         vUxaoXJqBH4qgm8JuMo8b/Q3NiikiZxXRLznIti/0pwUnu6qrMXTPQckoZccqKzQAei6
         ChzFXgUId5uwcigLKt0L8rFRYkRJQq2WB3pgMvMjp3auL1QXmgcLnD+LlmDKuGZT9MPD
         aZNfavOHO1tXKbmntkOAljCrxCjc6J3YEFL/KAmNDzaiLRrcuDDcsYz4hmt+1MZ/bEwb
         z2Lw==
X-Gm-Message-State: AOAM5319OnsGtDnyA1QTVgDGY0kOUnYqxCYCucsF4nmTOPvCaAmRTYgj
	FWiMpF15xMcAWthCbQGY0A4=
X-Google-Smtp-Source: ABdhPJy+1kXwTtYN3r7KeH0B/w3cI1b/zQAYevaCclXN0lHjH1iQ3lnCaDjMgSCgiiveFOxFGmNDIg==
X-Received: by 2002:a17:902:fe16:b029:11a:387e:d4e with SMTP id g22-20020a170902fe16b029011a387e0d4emr9027263plj.53.1624100911464;
        Sat, 19 Jun 2021 04:08:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7747:: with SMTP id s68ls1603431pfc.0.gmail; Sat, 19 Jun
 2021 04:08:31 -0700 (PDT)
X-Received: by 2002:a63:e04e:: with SMTP id n14mr5497864pgj.324.1624100910926;
        Sat, 19 Jun 2021 04:08:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624100910; cv=none;
        d=google.com; s=arc-20160816;
        b=Qe/g3xEeLbevMFgV/KGYyvQea81lE1dxFJtbE9xidiy4ihOIwMqrVFAaBKRlnsS/zn
         Ga5c7yNi2ww30ci8T/KGbP7wf84SK0gVV3k3JzqCS6MffEtS1ovK2pFeBQ9qFopVrurZ
         h/iRlkNELHoMtc77AORCEdO8ncbAxnXTOKRpD2UCDWYhEcvR/jGMu+fHbDciddFeqaw5
         wWWtIsQg7irk97cXBV8ewM/GsexSRa7asZ4VJOKr50Op8ZIN82CAlFVmAZZXJQ+EmqO3
         hFyu6VfnyLILvL+1LEDOx5Ouzw07n+uwnKjBzfdUFcHvEbigrkciN6XGQDogajVAsonB
         //vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1d3OtLRBli45MN6wZ1Rv/xKIXGyvei6DXrZPdGqY9R0=;
        b=S54ChxA+ZQh8V+yE7DlGFv9phsIst1f2uCC8dQQXlEqRzg7T/BZuVbuaQOPrWfh2To
         TRkc4RCyiELlzXyygd/7ccyX7rBBZkrXxICnJWFM6DVHQfv0KsR3JqJ7BdIkWfcbem3l
         Ob+mYq3YLFCfLdmn3nwiUKfWLyhiruQs+ZfC2io/guLSlC0TuLX2XiRrGwObsz6zCAmc
         zmM8wxZM6fNxthJk7LzQn6gGWynArHaDL2Rdva5a2UGHXxqgUYX0pq6imPydduPLdIT9
         ffckcGnLQlno4Xv9DBC7a/6nfHLoNyb19ucrFNzgC8axOs5sEPQ+70y9cdKZV95m2xfP
         DVzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cb8Ghqd5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id q7si1075829pgf.3.2021.06.19.04.08.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 19 Jun 2021 04:08:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 5so4957816qvf.1
        for <kasan-dev@googlegroups.com>; Sat, 19 Jun 2021 04:08:30 -0700 (PDT)
X-Received: by 2002:a0c:d7ce:: with SMTP id g14mr10178028qvj.23.1624100909875;
 Sat, 19 Jun 2021 04:08:29 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com> <YMyC/Dy7XoxTeIWb@elver.google.com>
In-Reply-To: <YMyC/Dy7XoxTeIWb@elver.google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 19 Jun 2021 13:08:18 +0200
Message-ID: <CACT4Y+YTh=ND_cshGyVi98KiY=pkg3WKrpE__Cn+K0Wgmuyv+w@mail.gmail.com>
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Marco Elver <elver@google.com>
Cc: Daniel Bristot de Oliveira <bristot@redhat.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cb8Ghqd5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f31
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

On Fri, Jun 18, 2021 at 1:26 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, Jun 18, 2021 at 09:58AM +0200, Daniel Bristot de Oliveira wrote:
> > On 6/17/21 1:20 PM, Marco Elver wrote:
> > > [+Daniel, just FYI. We had a discussion about "functional coverage"
> > > and fuzzing, and I've just seen your wonderful work on RV. If you have
> > > thought about fuzzing with RV and how coverage of the model impacts
> > > test generation, I'd be curious to hear.]
> >
> > One aspect of RV is that we verify the actual execution of the system instead of
> > a complete model of the system, so we depend of the testing to cover all the
> > aspects of the system <-> model.
> >
> > There is a natural relation with testing/fuzzing & friends with RV.
> >
> > > Looks like there is ongoing work on specifying models and running them
> > > along with the kernel: https://lwn.net/Articles/857862/
> > >
> > > Those models that are run alongside the kernel would have their own
> > > coverage, and since there's a mapping between real code and model, a
> > > fuzzer trying to reach new code in one or the other will ultimately
> > > improve coverage for both.
> >
> > Perfect!
> >
> > > Just wanted to document this here, because it seems quite relevant.
> > > I'm guessing that "functional coverage" would indeed be a side-effect
> > > of a good RV model?
> >
> > So, let me see if I understood the terms. Functional coverage is a way to check
> > if all the desired aspects of a code/system/subsystem/functionality were covered
> > by a set of tests?
>
> Yes, unlike code/structural coverage (which is what we have today via
> KCOV) functional coverage checks if some interesting states were reached
> (e.g. was buffer full/empty, did we observe transition a->b etc.).
>
> Functional coverage is common in hardware verification, but of course
> software verification would benefit just as much -- just haven't seen it
> used much in practice yet.
> [ Example for HW verification: https://www.chipverify.com/systemverilog/systemverilog-functional-coverage ]
>
> It still requires some creativity from the designer/developer to come up
> with suitable functional coverage. State explosion is a problem, too,
> and naturally it is impractical to capture all possible states ... after
> all, functional coverage is meant to direct the test generator/fuzzer
> into more interesting states -- we're not doing model checking after all.
>
> > If that is correct, we could use RV to:
> >
> >  - create an explicit model of the states we want to cover.
> >  - check if all the desired states were visited during testing.
> >
> > ?
>
> Yes, pretty much. On one hand there could be an interface to query if
> all states were covered, but I think this isn't useful out-of-the box.
> Instead, I was thinking we can simply get KCOV to help us out: my
> hypothesis is that most of this would happen automatically if dot2k's
> generated code has distinct code paths per transition.
>
> If KCOV covers the RV model (since it's executable kernel C code), then
> having distinct code paths for "state transitions" will effectively give
> us functional coverage indirectly through code coverage (via KCOV) of
> the RV model.
>
> From what I can tell this doesn't quite happen today, because
> automaton::function is a lookup table as an array. Could this just
> become a generated function with a switch statement? Because then I
> think we'd pretty much have all the ingredients we need.
>
> Then:
>
> 1. Create RV models for states of interests not covered by normal code
>    coverage of code under test.
>
> 2. Enable KCOV for everything.
>
> 3. KCOV's coverage of the RV model will tell us if we reached the
>    desired "functional coverage" (and can be used by e.g. syzbot to
>    generate better tests without any additional changes because it
>    already talks to KCOV).
>
> Thoughts?

I think there is usually already some code for any important state
transitions. E.g. I can't imagine how a socket can transition to
active/listen/shutdown/closed states w/o any code.

I see RV to be potentially more useful for the "coverage dimensions"
idea. I.e. for sockets that would be treating coverage for a socket
function X as different coverage based on the current socket state,
effectively consider (PC,state) as feedback signal.
But my concern is that we don't want to simply consider combinations
of all kernel code multiplied by all combinations of states of all RV
models. Most likely this will lead to severe feedback signal
explosion. So the question is: how do we understand that the socket
model relates only to this restricted set of code?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYTh%3DND_cshGyVi98KiY%3Dpkg3WKrpE__Cn%2BK0Wgmuyv%2Bw%40mail.gmail.com.
