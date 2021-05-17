Return-Path: <kasan-dev+bncBCMIZB7QWENRB7M2RKCQMGQE7D2HJLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C1473836C2
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 17:36:31 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id x10-20020a54400a0000b02901e9af7e39cbsf1560302oie.22
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 08:36:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621265790; cv=pass;
        d=google.com; s=arc-20160816;
        b=nDpw9u4M+6VgI+l6I6C2rB8Ia0Bmv+tEATT+cqCKyVR1KcHZlIqpUW1orFse9zYPJR
         gsgiJXCoCpeaFLKt+94CCamIL1LpxDjmquFA1okGD5Xw4LlSagp3LLjzMBCkw98G+k4+
         iLJ0yU2iBmhmYB3F2ncEtzmu+SDlT/ef1AG/rxgUe04/fpKh7f36eAJqjjpU5zg45nYP
         Ejp6rQtBalB1w0lFL8Y9/x+lPfa+RyHCAF2cf8dYgj5/3lnHwfDxPu5CT/IcYRCbxmIM
         wUpsdiiN7NdL/7en2WN1kKPlMKlXIqwQLUKrMU7RQCCZzWj16s6P7jquhTeRcp7VTUKO
         eJog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U/++5jFxJsWfB75vPZ+Km+Twbq+odPuknuJ4LepeBe8=;
        b=IMs78x9wiIaCP7kl66r+8yPZ5rwMZ/xW7T12TIDX+kyRA1ifRV9YZCQS7D3sr7GmbV
         n/VPcO7NX2sxfVrrj9sYt9maZdhgn8z/pHx3SoMDRMDUY00gjy9B0HM981T3QSFsS5hm
         81yXF42tk7uuKH+a5Vj4bdT3wlrm94kMK5974hYqzkV4GOx3jt7VTZ/5VNRm6NkUH5eb
         GAqViqzGGqn6JOpkynzMaaNKi8u67tlG93+yNhyHvI/vLDqJNhm5H5rKgScXefMjKAMN
         cSIt6mlUR+VGYg+XlDLG6eSRSjFky1IWN6UfOlRb+VBWi7U4Fr6oP6PqW2m9lEoSdoPQ
         Cwvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MjSBQFoB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U/++5jFxJsWfB75vPZ+Km+Twbq+odPuknuJ4LepeBe8=;
        b=qUCa1U2OI1ANJ5JnGluUt3cUL6JQVnvCQmlG/7BGUoPD7h7z0aEr5Q7hpaSSXTqqaj
         f063kVnLLPz2SWkS2+ETM/PrQMnZBU6eYzRB9iIDLs1lKOIfR1NHyFYpSC2a6QbI79MB
         IfKqdWwnAFPxdhFUucLwz9JS6p5lfVBapFnh/xXnE7WzBxLtPQWq+uPrSqL+WnJveKHg
         TI43ZoxTXqqBpo7d855CzWOZtolgtunk+Q2d8c3xiVDPom1QMnvneYIzR6zUbZA2x7NP
         k5W5eqEj7B+HC7au8HGeignDxLo7qJicWKo/Y4caA62X4zk2QYAqG8DbffbMfKirepJm
         P0qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U/++5jFxJsWfB75vPZ+Km+Twbq+odPuknuJ4LepeBe8=;
        b=VSr/gayV/ZKdj71x4rzJI4ci6xxDyxdZeLDQwd6NP9H2EWP751qoFWrv0WXhT2LIlr
         i/mQbthZ4ph3bAdun2I+MVKZ19g9fxdg90ui9KOBZMlfXA192jymS5VFPgIweQRld52k
         vU74Wd/34pQTbRhGWvUdeF7UxIzhzeRm4Ndj4f5Ltp9bgM8V6O39B0Gdt5PKpsw1b/NR
         j34v9RlT3y3+yHhnm+IbGJY1rzjpzYDikSkKZX3mU0gYMMNQnWBmVRZZtuhdp/I2GhAL
         1QeQN1nLF0y+FneqQ5S9Tq16ib7OTpkggPMDWLYFgbkjL33hnw/aST1hOq0BAkG83ZVO
         6hWw==
X-Gm-Message-State: AOAM533c/tRiwm8M0gLlv/wII4GQnR/X2N1TqzMttRABKyUF14jEHNCo
	reyQSR6RbNV2qGrEk36ey9U=
X-Google-Smtp-Source: ABdhPJxrk/kVkerI+lrBercGg4jE10L4t8qeIBIsMfol62VNS3pzjKEby6ONKeimBsyOBdteGDYVpg==
X-Received: by 2002:a05:6830:1bd8:: with SMTP id v24mr129746ota.203.1621265789872;
        Mon, 17 May 2021 08:36:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b102:: with SMTP id a2ls4514362oif.5.gmail; Mon, 17 May
 2021 08:36:29 -0700 (PDT)
X-Received: by 2002:aca:ab16:: with SMTP id u22mr303654oie.122.1621265789505;
        Mon, 17 May 2021 08:36:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621265789; cv=none;
        d=google.com; s=arc-20160816;
        b=Dxcn8e/xeltwWLMTjKbNdJl05Q+MZX/0nNKgzbJQkLxlngh9lElF1tiRhSqEgr6osK
         Gslqd0i4xnVCimNO/aGhP3I6C3C/M/XBeAHcLBm6pHNR+BDXYP0IbKjKm4aYXQTZLaLR
         CwAGlL5RPBMqps4dEM6DhVypdBbAbZl3HEyRHhOUWvzSxRM3vM/6i4OZ3Mnlx7vIv03b
         Rxn6CZmOdNYznl8AmKZ0he43hT8CFRpwfjtttpRSRO+v4+IZ430EKCQVHvO4FbYqw60A
         69rqQM/zv3Ub4wJTtiFQt5UK12MbFgS0Io5lBHBxWFFVbYOmMUmDO/kGL9Uimn16vGBQ
         1UGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wo/BszmbLtrqpPjGX8twK3gws7qjQnw3qx7Ups7SP7A=;
        b=yj+OK6nSGO2dYWtsN9NrKdUyUhgqyQ4C17y8mHpCySVLcMQttYaZXlXmaYkRmKDdSI
         kpifcVUarcqAsMJUhsXViKpAmbxzF/LzSFMq9kGGJaQ/jOYngT3PlKJnfuBMgi2xRlGK
         pqgGy3QPGYmD0aq/2KfFjE2TaTY3YSJ5IMMDxERMcbHX+HApreRGj98eCZcaYEV0LDrd
         ZC3gIuSiZcHwdWykittXMJOfp+Ve0VYwi3n03W78de/QSn8cP2/xlso5FWRBgkV0PLUQ
         TeH01c/hOhB+Q1DVxxxgYUeI0mntu7aQq1wpmPZWzUcECZipl5pAkFJd+AbRAVqMU+9+
         tfsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MjSBQFoB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id l81si694903oig.0.2021.05.17.08.36.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 May 2021 08:36:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id i67so6141925qkc.4
        for <kasan-dev@googlegroups.com>; Mon, 17 May 2021 08:36:29 -0700 (PDT)
X-Received: by 2002:ae9:e850:: with SMTP id a77mr446736qkg.424.1621265788578;
 Mon, 17 May 2021 08:36:28 -0700 (PDT)
MIME-Version: 1.0
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 May 2021 17:36:16 +0200
Message-ID: <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MjSBQFoB;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::734
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

On Wed, May 12, 2021 at 8:18 PM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> Hello, Dmitry!
>
> On the perhaps-unlikely off-chance that this is useful new news, there
> is a paper by Mukherjee et al. entitled "Learning-based Controlled
> Concurrency Testing" that suggests use of an augmented coverage state
> as a goal driving random testing.  The meat of this discussion is on
> the eighth page, the one labeled as "230:8".
>
> This builds on tools such as American Fuzzy Lop (AFL) that use straight
> coverage as a testing goal by adding carefully abstracted concurrency
> state, such as which locks are held and which threads are blocked/spinning
> on which lock.  This of course does not help for lockless algorithms,
> but there are plenty of bugs involving straight locking.
>
> Thoughts?
>
>                                                         Thanx, Paul


+syzkaller, kasan-dev

Hi Paul,

Thanks for notifying me, I wasn't aware of this work.

FTR here is a link to the paper I found:
https://www.microsoft.com/en-us/research/uploads/prod/2019/12/QL-OOPSLA-2020.pdf

That's an interesting approach. Initially how they obtain the program
"state" and calculate the reward, but the "default observation" thing
answered my question.
I think such approaches may be useful for the SPIN-territory where we
verify a reasonably local and isolated algorithm, e.g. RAFT
verification they used for benchmarking.
But if we take, say, whole Linux kernel then such approaches become
somewhat fragile, inefficient and impractical, e.g. capturing all
tasks and mutexes may be impractical and inefficient (state
explosion), or controlling all sources of non-determinism may be
infeasible. And at the same time it's unnecessary because we still
don't have even the most basic implementation, the random scheduler,
which is not even what they are trying to improve on, it's several
steps back.
I would start with a random scheduler, maybe with few simple
heuristics. That should be simple and robust and I am sure it will
give us enough low hanging fruits to keep us busy for a prolonged
period of time :) Here are tracking issues for that:
https://bugzilla.kernel.org/show_bug.cgi?id=209219
https://github.com/google/syzkaller/issues/1891

Maybe you did not mean Linux kernel at all, I don't know. For
something like RCU verification (like what you did with SPIN) it's
definitely more suitable.
Interestingly, if we have a notion of "state" we can use
coverage-guided fuzzing techniques as well. Though, I don't see it
mentioned in the text explicitly. But you mentioned AFL, did you see
this mentioned in the paper?
They set a goal of maximizing state coverage, but they don't seem to
preserve a "corpus" of schedules that give maximum coverage. If we do
this, we can mutate schedules in the corpus, splice them, or prime the
corpus with context-bound schedules (see CHESS, another seminal paper
MS research). Generally, the more technique we include into the same
feedback loop, the better, because they all start helping each other
progress deeper.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%2B7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA%40mail.gmail.com.
