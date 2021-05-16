Return-Path: <kasan-dev+bncBC7OBJGL2MHBB64RQWCQMGQE66TP2QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CB22381FFB
	for <lists+kasan-dev@lfdr.de>; Sun, 16 May 2021 18:31:57 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id k7-20020a9d4b870000b02902a5bfbbbd3bsf3638732otf.18
        for <lists+kasan-dev@lfdr.de>; Sun, 16 May 2021 09:31:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621182716; cv=pass;
        d=google.com; s=arc-20160816;
        b=TI3X5LySgH3KCREqZ0lmXKCbRm6AT7it7Vuhss1VWFsVwwOS50Yq8L0MWXW6d8wrxn
         +bLkfmRW1cvVI8zyBPpwAjcqJpFbQMjbECtdPfZpDNvGqvX5TbQB8sq/YETnWg0Rr2n2
         nDOWYlgn5GfCzTpTkDXql+qmkFnnN5yHD/3q1YCOUcbc135iw5IwfN9PPHx8hradmMA4
         7DOLWJHeFaXupKPVsKhG+e5zXQNwCqWfM1+xk+GOsiBt8/rk9WJmyLRYsFf/qCKWbAXN
         C+X8zkdKwfURHgaZWs+IEfXkqYwz+C0N8RthiT3vqYhU1o0kxvmD7+zNT3NJMHqvrt5p
         F+aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0DseEJr+DlfhyaJl02SOUGHl0sg/cp9pBp181NcqkCU=;
        b=z8Bc1BYK4U3Ybn/uCEThV64KoA/C5kbTeTEpA/kXOq29JpMWmsv5c6Yz1PTOEGA6de
         1jDGnO6UAYp7vouKzNEoKCI3MkgURjGeN6sGaZx5Z9Yf9cf7cThn92ZaBGGpX9ISuoIT
         YL8Jd3BQmpcYN70MYUPcrg94hFnGV14L9BlvnMTvo2UT7VUuIKTooIW06f9bBAQfPUd6
         N2Hop1oPijpRHkqI/1Sqnj5PVqVA1vR8SqHDK+NDBSf9o1dd7wjxCDFW2bqLvdvU3wkx
         nMWlQvkbtVfA8jxO2QxRC1qcciBQYNCOxTKgXV/1BtlS0LhamCJJsdeZz7dgMXvkhop6
         ABMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RUk8HZdJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0DseEJr+DlfhyaJl02SOUGHl0sg/cp9pBp181NcqkCU=;
        b=Qn1gnfAYB7yT4nvtpe+k6S4JvGEmMQnDB7WyKO2iwwPaQPLw0AuvmDZLw2ZIC3Hv0/
         xYcmsvuBw72FhZuaiKLXakwN2WzYuqrWiBEra79vqwxxkzjpHum1oDRAKHNu1W5Wizmw
         8HZxa3RBfHcT5vUkubRIMXO7/hL1+LYUQLII6ZjVD9ATT4caaCQQghgWHQ+Rryz5kxQT
         V1oydF3FqnIVrI748fEmButfv5kLDX7xw9aKd0W03o9OR2VVJ8bCIUeAfbihYpLHIHkr
         ttVH6mDooWQdfSTYzWQ1BA+0aCinMD4QP5J1JbxJBmaGniNqLJ2EpQlY0HfFVCxbE7qF
         fCew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0DseEJr+DlfhyaJl02SOUGHl0sg/cp9pBp181NcqkCU=;
        b=oDDwVOdnfo2ffvWJ35z+DKErgan+KwtXBrQTm/BWZOsgzZrMYTR/4nIxYeEhr5EWfw
         c0eLo0K/xy1SKZSgSyDPT3v2aF6223i50Y9SE+ykjabVJGqqL+vb3vwskoqJYhzJlb0a
         Il457LQFBHDBw8cBPs0Absih1KK82sLdwXIGDqbLcx+VxPn7ETKurNa0rD5XdQFYHzMG
         FGk6I4o88hjDc2eIiJ3PXi7HTVARZoF9BCJYgOSqP5CyUbRqT43nawMWqJR/x1aXv6HU
         dTtAsBBNfoyOEpPuykwNMUDMj6xC1VFgmbpyrzsm14USg+ihMmvklf5ls/xiWwDp6jvm
         Y2xg==
X-Gm-Message-State: AOAM530tKIh/kjxyQdQvT9/ZpN8NqMncJOy6EzfC4q/lCTvF/WHkYxGR
	b/T7AdErktOusgnsOcEfz1w=
X-Google-Smtp-Source: ABdhPJyKjdwiUE7atxhJJvIeCquJPxBWYzNMyokOtJtN8KHQx9rcTXn/GRIt24KGt99Fl3f+gQLoxw==
X-Received: by 2002:a05:6808:13d5:: with SMTP id d21mr24533621oiw.31.1621182715966;
        Sun, 16 May 2021 09:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5a18:: with SMTP id v24ls1952505oth.1.gmail; Sun, 16 May
 2021 09:31:55 -0700 (PDT)
X-Received: by 2002:a9d:c64:: with SMTP id 91mr22829382otr.130.1621182715566;
        Sun, 16 May 2021 09:31:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621182715; cv=none;
        d=google.com; s=arc-20160816;
        b=vQtjOKlJf8rbXZq4a7wU3oibQHlHn69GSJRGX9S598XfonyVv0sphp+P49ASMU+m2J
         Dr49UIIo7vvLbrzg+tsh85k3Rrp0NPZ96OogKHPtCgQpx32fgN5NGHaK/+lnXi2VABUY
         vzNHGHW4r9vgNYeqUk41p8HE2tdTuyw98capt1EgVKAMXXnd6hFJG5JCKFi8uvpiJZ1E
         X5D1VAAGuO4eddzuYuYDAHf3zWgpdaGzMWreXqRYZ5JkzkDKd5Hh2ZRrWQcMLpUbKlpY
         2w3XYATeouYezd+sOZY9LC8/6y7MDnUiIo8Z/DOaeEzsuFVbXHW121ZtQ52zNCUSMtdV
         7gdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mwYv7UTLuwBSjEjVm4x0I9QPoE0PGJFp3yc8rjQtWRY=;
        b=Kd0YHXJ+jPkJutVvkN7E52JtfO3FDlhVnhfV8hnE00kXqxW7F9z1/Vo40ipjC2kCND
         WxULxHisEIGPWqMXPcILrzKSFTOvQ+ETzetN6Gl9m/z2+rGAOOU3rjh3dvC1BbhMhqKf
         kHf1RVMwGNdhBi2/rSxZ3KgDConXwEdbJ5X6pizAFk+SxkluFkJlnLyv/61QMJYvachn
         od1TJEm54k61b2/I7Z5cPoBywCa0uJMubWJeCtg/YhOVmF14eQNEmYXsbmeX3HW0lt0T
         MPnkIwlR1BD9lHjxOi2nEEJvCTvVeMXi/Lpc9zTjO9cnmLLWYcX1idPUr0LjnXkSo8yR
         8SOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RUk8HZdJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id x16si1378201otr.5.2021.05.16.09.31.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 16 May 2021 09:31:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id w22so4372527oiw.9
        for <kasan-dev@googlegroups.com>; Sun, 16 May 2021 09:31:55 -0700 (PDT)
X-Received: by 2002:a05:6808:10d4:: with SMTP id s20mr766847ois.70.1621182715023;
 Sun, 16 May 2021 09:31:55 -0700 (PDT)
MIME-Version: 1.0
References: <20210516155251.GA3952724@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20210516155251.GA3952724@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 16 May 2021 18:31:43 +0200
Message-ID: <CANpmjNNd1uybRcxuG6m6vMKjuAMTWzRywo5PwcUU8nUxtu8BZA@mail.gmail.com>
Subject: Re: Fw: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RUk8HZdJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Sun, 16 May 2021 at 17:52, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> [ Restricting to KCSAN people for this question. ]
>
> > On Fri, May 14, 2021 at 07:41:02AM +0200, Manfred Spraul wrote:
> > > On 5/13/21 9:02 PM, Paul E. McKenney wrote:
> > > > On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
>
> [ . . . ]
>
> > > > Actually, you just demonstrated that this example is quite misleading.
> > > > That data_race() works only because the read is for diagnostic
> > > > purposes.  I am queuing a commit with your Reported-by that makes
> > > > read_foo_diagnostic() just do a pr_info(), like this:
> > > >
> > > >   void read_foo_diagnostic(void)
> > > >   {
> > > >           pr_info("Current value of foo: %d\n", data_race(foo));
> > > >   }
> > > >
> > > > So thank you for that!
> > >
> > > I would not like this change at all.
> > > Assume you chase a rare bug, and notice an odd pr_info() output.
> > > It will take you really long until you figure out that a data_race() mislead
> > > you.
> > > Thus for a pr_info(), I would consider READ_ONCE() as the correct thing.
> >
> > It depends, but I agree with a general preference for READ_ONCE() over
> > data_race().
> >
> > However, for some types of concurrency designs, using a READ_ONCE()
> > can make it more difficult to enlist KCSAN's help.  For example, if this
> > variable is read or written only while holding a particular lock, so that
> > read_foo_diagnostic() is the only lockless read, then using READ_ONCE()
> > adds a concurrent read.  In RCU, the updates would now need WRITE_ONCE(),
> > which would cause KCSAN to fail to detect a buggy lockless WRITE_ONCE().
> > If data_race() is used, then adding a buggy lockless WRITE_ONCE() will
> > cause KCSAN to complain.
> >
> > Of course, you would be quite correct to say that this must be balanced
> > against the possibility of a messed-up pr_info() due to compiler mischief.
> > Tradeoffs, tradeoffs!  ;-)
>
> On the other hand, a few quick experiements with data_race(READ_ONCE(foo))
> lead me to believe that this would do what Manfred wants.  If so, I should
> add this possibility to the documentation:  Prevent destructive compiler
> optimizations while at the same time causing KCSAN to ignore the access.
>
> Or did I just get lucky?

Not luck, it does what you think it does.  There's also __no_kcsan
function attribute if one would like a whole function to be ignored,
which in the above read_foo_diagnostic() example might be nicer? But
of course that's not always possible.

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> > I should document this tradeoff, shouldn't I?
> >
> > > What about something like the attached change?
> > >
> > > --
> > >
> > >     Manfred
> > >
> > >
> >
> > > diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/memory-model/Documentation/access-marking.txt
> > > index 1ab189f51f55..588326b60834 100644
> > > --- a/tools/memory-model/Documentation/access-marking.txt
> > > +++ b/tools/memory-model/Documentation/access-marking.txt
> > > @@ -68,6 +68,11 @@ READ_ONCE() and WRITE_ONCE():
> > >
> > >  4. Writes setting values that feed into error-tolerant heuristics.
> > >
> > > +In theory, plain C-language loads can also be used for these use cases.
> > > +However, in practice this will have the disadvantage of causing KCSAN
> > > +to generate false positives because KCSAN will have no way of knowing
> > > +that the resulting data race was intentional.
> > > +
> > >
> > >  Data-Racy Reads for Approximate Diagnostics
> > >
> > > @@ -86,11 +91,6 @@ that fail to exclude the updates.  In this case, it is important to use
> > >  data_race() for the diagnostic reads because otherwise KCSAN would give
> > >  false-positive warnings about these diagnostic reads.
> > >
> > > -In theory, plain C-language loads can also be used for this use case.
> > > -However, in practice this will have the disadvantage of causing KCSAN
> > > -to generate false positives because KCSAN will have no way of knowing
> > > -that the resulting data race was intentional.
> > > -
> > >
> > >  Data-Racy Reads That Are Checked Against Marked Reload
> > >
> > > @@ -110,11 +110,6 @@ that provides the compiler much less scope for mischievous optimizations.
> > >  Capturing the return value from cmpxchg() also saves a memory reference
> > >  in many cases.
> > >
> > > -In theory, plain C-language loads can also be used for this use case.
> > > -However, in practice this will have the disadvantage of causing KCSAN
> > > -to generate false positives because KCSAN will have no way of knowing
> > > -that the resulting data race was intentional.
> >
> > Normally, I would be completely in favor of your suggestion to give
> > this advice only once.  But in this case, there are likely to be people
> > reading just the part of the document that they think applies to their
> > situation.  So it is necessary to replicate the reminder into all the
> > sections.
> >
> > That said, I do applaud your approach of reading the whole thing.  That
> > of course gets you a much more complete understanding of the situation,
> > and gets me more feedback.  ;-)
> >
> > >  Reads Feeding Into Error-Tolerant Heuristics
> > >
> > > @@ -125,11 +120,9 @@ that data_race() loads are subject to load fusing, which can result in
> > >  consistent errors, which in turn are quite capable of breaking heuristics.
> > >  Therefore use of data_race() should be limited to cases where some other
> > >  code (such as a barrier() call) will force the occasional reload.
> > > -
> > > -In theory, plain C-language loads can also be used for this use case.
> > > -However, in practice this will have the disadvantage of causing KCSAN
> > > -to generate false positives because KCSAN will have no way of knowing
> > > -that the resulting data race was intentional.
> > > +The heuristics must be able to handle any error. If the heuristics are
> > > +only able to handle old and new values, then WRITE_ONCE()/READ_ONCE()
> > > +must be used.
> >
> > Excellent addition!  I have applied the commit shown below with your
> > Signed-off-by.  Please let me know if you would like me to take some other
> > course of action.  And also please let me know if I messed something up.
> >
> > >  Writes Setting Values Feeding Into Error-Tolerant Heuristics
> > > @@ -142,11 +135,8 @@ due to compiler-mangled reads, it can also tolerate the occasional
> > >  compiler-mangled write, at least assuming that the proper value is in
> > >  place once the write completes.
> > >
> > > -Plain C-language stores can also be used for this use case.  However,
> > > -in kernels built with CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n, this
> > > -will have the disadvantage of causing KCSAN to generate false positives
> > > -because KCSAN will have no way of knowing that the resulting data race
> > > -was intentional.
> > > +Note that KCSAN will only detect mangled writes in kernels built with
> > > +CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n.
> >
> > And the same point on needing to say this more than once.
> >
> >                                                       Thanx, Paul
> >
> > ------------------------------------------------------------------------
> >
> > commit 48db6caa1d32c39e7405df3940f9f7ba07ed0527
> > Author: Manfred Spraul <manfred@colorfullife.com>
> > Date:   Fri May 14 11:40:06 2021 -0700
> >
> >     tools/memory-model: Heuristics using data_race() must handle all values
> >
> >     Data loaded for use by some sorts of heuristics can tolerate the
> >     occasional erroneous value.  In this case the loads may use data_race()
> >     to give the compiler full freedom to optimize while also informing KCSAN
> >     of the intent.  However, for this to work, the heuristic needs to be
> >     able to tolerate any erroneous value that could possibly arise.  This
> >     commit therefore adds a paragraph spelling this out.
> >
> >     Signed-off-by: Manfred Spraul <manfred@colorfullife.com>
> >     Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> >
> > diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/memory-model/Documentation/access-marking.txt
> > index e4a20ebf565d..22ecadec4894 100644
> > --- a/tools/memory-model/Documentation/access-marking.txt
> > +++ b/tools/memory-model/Documentation/access-marking.txt
> > @@ -126,6 +126,11 @@ consistent errors, which in turn are quite capable of breaking heuristics.
> >  Therefore use of data_race() should be limited to cases where some other
> >  code (such as a barrier() call) will force the occasional reload.
> >
> > +Note that this use case requires that the heuristic be able to handle
> > +any possible error.  In contrast, if the heuristics might be fatally
> > +confused by one or more of the possible erroneous values, use READ_ONCE()
> > +instead of data_race().
> > +
> >  In theory, plain C-language loads can also be used for this use case.
> >  However, in practice this will have the disadvantage of causing KCSAN
> >  to generate false positives because KCSAN will have no way of knowing
> >
> > ----- End forwarded message -----

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNd1uybRcxuG6m6vMKjuAMTWzRywo5PwcUU8nUxtu8BZA%40mail.gmail.com.
