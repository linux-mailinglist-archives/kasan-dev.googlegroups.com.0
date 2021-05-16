Return-Path: <kasan-dev+bncBCJZRXGY5YJBBI6GQ2CQMGQEZQDZKJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id B9AD43821D4
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 00:56:37 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id h23-20020a17090aa897b029015cc61ef388sf2116311pjq.9
        for <lists+kasan-dev@lfdr.de>; Sun, 16 May 2021 15:56:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621205796; cv=pass;
        d=google.com; s=arc-20160816;
        b=UwBHtmiOlZu4iuOKYnfU2dCsX5rN7EAPcyEO+wf84YawZyhA6e3FInZKO6Zw6LkuuI
         u5hHJWN74iNCjz9RQ5nz0X5KJIRWH1HJAaYhHb13/qPrFSIDc9Od54qb5qhwtWaPBaZK
         xL+MnQtOMfOrpRneyxkUkYuhwzpfXu5GMz3KbRdKS6wDPCSFuMclgisIz/KanrpjHD2k
         PswKnv9bH5Pqi4xcXjpUqNEpW2NvwCXjFuYIG2RlmUC7EyO2R62j9f25LQE8xU+whH9S
         iR4IJZvfiZDXdFY1WiXMamjVAsLinr0Wit54R3/55ikaN9R/Gev6hAqaG7qu1h47LZ9f
         Z6Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=9B+h9bxkmZaVwny7bBpUSlcDYa2V1VQqDkyfdm7oamY=;
        b=mgEal2UYgQBMafpK21+qr5ApNcbBck1yY0cSXUp+3BDDH7Rb+jyRwJIfvrCh5pwaQk
         fRAxwTR6Q0Y9puj7mz4Y2X3tj5zWuNFOCgX0yodwnkWkMNFggL0tVxKns95leCJaJwJR
         vnwF19NDbJKkcfSD6ugNDg+UU+OYpt2NbOqOwbZvkn/I/tjDO0cBwhMWGNr9fvnqN+oG
         LZUZIannE+1++7HIFBogX51jKBRD8XFgjNv7XHAqRRnlsbHwGgkzvQ7O4M2qSvlSY5Yj
         EYre3O0SXg4hprc75hfOG9I5DUX2HE8FlTwBMCRtCeJdlZIYYzfGI4ztFfs0KVfw8Ahu
         ZVvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nUwedLk8;
       spf=pass (google.com: domain of srs0=xrg5=kl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XRG5=KL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9B+h9bxkmZaVwny7bBpUSlcDYa2V1VQqDkyfdm7oamY=;
        b=bcvNyVz0iD860yn2t1HORpEVaYj8dWVD5pOSwQDGl22fqxUQHO9sVYC7z6W9iqVPGk
         bbyaruaT94NzJLrVTIS9lO61h84EaWV++0RP5CwaLX2uqQ/LZ2OcA39ZnLfk124GPj+2
         lWhx12dj9p9L3dDLiNkxb2StklJqMFHhDlDcvIRPakR7TzWtGPE3tBUOZFiCoX8MaQ6c
         CTDAFkB/j2yf5AX4Jv87IIi+4qV6TM++58iciLLxETD7b+GsKWdGcYdymrppXWOVElwa
         Y/bjx0rrNED5LYsRBftc7PU312M2v0Hl3017hbFjQiLyO0egX+Keq5Wkf+49SdHE/Lhv
         Xdmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9B+h9bxkmZaVwny7bBpUSlcDYa2V1VQqDkyfdm7oamY=;
        b=fw2l8C2BFfM8wr8NYKsfMIdvS79iXPJcwld3ZO2fp7giCf81n+wctMk7zXfcjS3HXc
         oUYT6djtV4ogtURcKKtBF4QvZH2m4AZ1KWtzP+aOIxBVgw3goXZ0qvJpTe+u2wEh6NuF
         gvbHqfzLDJIruqbbuyzWI0keM2nHSMjEHQbi4d2F8lla8WS85pc6nfB0P/yT86Z6FcDe
         f7CcYOdBYrakW5mXrIbRa/fqrehipGyLU0Bwlc9E+oSPIZY/9OnBgRKHi+oUs2x8tFUV
         VH8op+zkBLoEiksJE7u+LWZQISJTI76e+9GtD3D2PxPIYa2RYyVJ/MEQUSO7bT7DCIKw
         v5rQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PrLWGzhsPElsiTwezr05j3JDUNTlC6fGpU/GpuP9HhKpebwFJ
	4+6mAfG0jlLcYesTja6GtbQ=
X-Google-Smtp-Source: ABdhPJwfkf/HiMmdSZiDvLtGZfWv7Fi8wGPA4ouGCC8IVvy7DwSCYHIATOcvXFjh0SLJ/CCi/UJCXg==
X-Received: by 2002:a17:90b:201:: with SMTP id fy1mr7235386pjb.119.1621205796030;
        Sun, 16 May 2021 15:56:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4145:: with SMTP id x5ls6752127pgp.4.gmail; Sun, 16 May
 2021 15:56:35 -0700 (PDT)
X-Received: by 2002:a63:5b5b:: with SMTP id l27mr11234271pgm.55.1621205795511;
        Sun, 16 May 2021 15:56:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621205795; cv=none;
        d=google.com; s=arc-20160816;
        b=kY74rH81Qd+AQuWVJ4IHXEnjdyeLpISmPO4zhEGiXFdQ7Tewlg18WM0IwbFCChe/Hp
         jENLSvvsW5Vu1LgI64/Au6ULLHYkeSyCyMX8mKfB4jwPUM1kS5RTw1ruUc8oj07/mEhW
         UYrzcH67tXaVvnRypjTkscZgO1teCbOpr647g30vOTpGfFV81Tq9tbmOI+0dVd359U6D
         nRQTR+XZMiCTwGsJOFEU204yzrvS9XHan22YwnqL8RhVJXEu0uR0jGuT2BBj2zQg/eHD
         mXGnZDs7yuFCbtuI9d4CGl3DFKGUzVrbP5mbx7UWFvW4oes/4JR6Z3MyQXtA/10ih07y
         dsIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jPkRzYasN+NjcGWFAsr95mEkpapBXxh4sMpBei7GGwA=;
        b=FfxCF0sbMhNPOVbVHXZ1PdBqFAYieGwk9+m46pDcA0sfAxwefqM8gM1GNwmQ5n87kj
         A85R55GIMsJ2pkwJdeFjkuIdQZQTBIAFTzYsZOh2hAKtGvPELyF+3GL8S14Id1akuukg
         3BP244+n2OcdqkORfJwzN7K4G+cGzDugwUT5JuHiz2dfUaj5R7hr/XVsDfHuAtXVxh+E
         HSH9DxX1XClROCSUsstZjKkVt9IBI88IE6VDxwj3w/ZPZMHZBqLgXYqZeUeGx/OrdPBF
         WVGfyh5eY7infeYloOoH5VVQIaHvce2KgvZB3imK4UK/NpRqNtoxJ5G8p8GPX8l/f0cV
         rEWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nUwedLk8;
       spf=pass (google.com: domain of srs0=xrg5=kl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XRG5=KL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id jf17si254236pjb.3.2021.05.16.15.56.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 16 May 2021 15:56:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xrg5=kl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3758E61073;
	Sun, 16 May 2021 22:56:35 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 00F815C03A8; Sun, 16 May 2021 15:56:34 -0700 (PDT)
Date: Sun, 16 May 2021 15:56:34 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Fw: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210516225634.GC4441@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210516155251.GA3952724@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNNd1uybRcxuG6m6vMKjuAMTWzRywo5PwcUU8nUxtu8BZA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNd1uybRcxuG6m6vMKjuAMTWzRywo5PwcUU8nUxtu8BZA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nUwedLk8;       spf=pass
 (google.com: domain of srs0=xrg5=kl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XRG5=KL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Sun, May 16, 2021 at 06:31:43PM +0200, Marco Elver wrote:
> On Sun, 16 May 2021 at 17:52, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > [ Restricting to KCSAN people for this question. ]
> >
> > > On Fri, May 14, 2021 at 07:41:02AM +0200, Manfred Spraul wrote:
> > > > On 5/13/21 9:02 PM, Paul E. McKenney wrote:
> > > > > On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
> >
> > [ . . . ]
> >
> > > > > Actually, you just demonstrated that this example is quite misleading.
> > > > > That data_race() works only because the read is for diagnostic
> > > > > purposes.  I am queuing a commit with your Reported-by that makes
> > > > > read_foo_diagnostic() just do a pr_info(), like this:
> > > > >
> > > > >   void read_foo_diagnostic(void)
> > > > >   {
> > > > >           pr_info("Current value of foo: %d\n", data_race(foo));
> > > > >   }
> > > > >
> > > > > So thank you for that!
> > > >
> > > > I would not like this change at all.
> > > > Assume you chase a rare bug, and notice an odd pr_info() output.
> > > > It will take you really long until you figure out that a data_race() mislead
> > > > you.
> > > > Thus for a pr_info(), I would consider READ_ONCE() as the correct thing.
> > >
> > > It depends, but I agree with a general preference for READ_ONCE() over
> > > data_race().
> > >
> > > However, for some types of concurrency designs, using a READ_ONCE()
> > > can make it more difficult to enlist KCSAN's help.  For example, if this
> > > variable is read or written only while holding a particular lock, so that
> > > read_foo_diagnostic() is the only lockless read, then using READ_ONCE()
> > > adds a concurrent read.  In RCU, the updates would now need WRITE_ONCE(),
> > > which would cause KCSAN to fail to detect a buggy lockless WRITE_ONCE().
> > > If data_race() is used, then adding a buggy lockless WRITE_ONCE() will
> > > cause KCSAN to complain.
> > >
> > > Of course, you would be quite correct to say that this must be balanced
> > > against the possibility of a messed-up pr_info() due to compiler mischief.
> > > Tradeoffs, tradeoffs!  ;-)
> >
> > On the other hand, a few quick experiements with data_race(READ_ONCE(foo))
> > lead me to believe that this would do what Manfred wants.  If so, I should
> > add this possibility to the documentation:  Prevent destructive compiler
> > optimizations while at the same time causing KCSAN to ignore the access.
> >
> > Or did I just get lucky?
> 
> Not luck, it does what you think it does.  There's also __no_kcsan
> function attribute if one would like a whole function to be ignored,
> which in the above read_foo_diagnostic() example might be nicer? But
> of course that's not always possible.

Very good, thank you!

And also thank you for the reminder about __no_kcsan.  I should look
at using this for some of RCU's diagnostic functions.

But some of them will have both diagnostic and non-diagnostic
fetches from shared variables.  For read_foo_diagnostic(), perhaps
I just show all three alternatives.

							Thanx, Paul

> Thanks,
> -- Marco
> 
> >                                                         Thanx, Paul
> >
> > > I should document this tradeoff, shouldn't I?
> > >
> > > > What about something like the attached change?
> > > >
> > > > --
> > > >
> > > >     Manfred
> > > >
> > > >
> > >
> > > > diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/memory-model/Documentation/access-marking.txt
> > > > index 1ab189f51f55..588326b60834 100644
> > > > --- a/tools/memory-model/Documentation/access-marking.txt
> > > > +++ b/tools/memory-model/Documentation/access-marking.txt
> > > > @@ -68,6 +68,11 @@ READ_ONCE() and WRITE_ONCE():
> > > >
> > > >  4. Writes setting values that feed into error-tolerant heuristics.
> > > >
> > > > +In theory, plain C-language loads can also be used for these use cases.
> > > > +However, in practice this will have the disadvantage of causing KCSAN
> > > > +to generate false positives because KCSAN will have no way of knowing
> > > > +that the resulting data race was intentional.
> > > > +
> > > >
> > > >  Data-Racy Reads for Approximate Diagnostics
> > > >
> > > > @@ -86,11 +91,6 @@ that fail to exclude the updates.  In this case, it is important to use
> > > >  data_race() for the diagnostic reads because otherwise KCSAN would give
> > > >  false-positive warnings about these diagnostic reads.
> > > >
> > > > -In theory, plain C-language loads can also be used for this use case.
> > > > -However, in practice this will have the disadvantage of causing KCSAN
> > > > -to generate false positives because KCSAN will have no way of knowing
> > > > -that the resulting data race was intentional.
> > > > -
> > > >
> > > >  Data-Racy Reads That Are Checked Against Marked Reload
> > > >
> > > > @@ -110,11 +110,6 @@ that provides the compiler much less scope for mischievous optimizations.
> > > >  Capturing the return value from cmpxchg() also saves a memory reference
> > > >  in many cases.
> > > >
> > > > -In theory, plain C-language loads can also be used for this use case.
> > > > -However, in practice this will have the disadvantage of causing KCSAN
> > > > -to generate false positives because KCSAN will have no way of knowing
> > > > -that the resulting data race was intentional.
> > >
> > > Normally, I would be completely in favor of your suggestion to give
> > > this advice only once.  But in this case, there are likely to be people
> > > reading just the part of the document that they think applies to their
> > > situation.  So it is necessary to replicate the reminder into all the
> > > sections.
> > >
> > > That said, I do applaud your approach of reading the whole thing.  That
> > > of course gets you a much more complete understanding of the situation,
> > > and gets me more feedback.  ;-)
> > >
> > > >  Reads Feeding Into Error-Tolerant Heuristics
> > > >
> > > > @@ -125,11 +120,9 @@ that data_race() loads are subject to load fusing, which can result in
> > > >  consistent errors, which in turn are quite capable of breaking heuristics.
> > > >  Therefore use of data_race() should be limited to cases where some other
> > > >  code (such as a barrier() call) will force the occasional reload.
> > > > -
> > > > -In theory, plain C-language loads can also be used for this use case.
> > > > -However, in practice this will have the disadvantage of causing KCSAN
> > > > -to generate false positives because KCSAN will have no way of knowing
> > > > -that the resulting data race was intentional.
> > > > +The heuristics must be able to handle any error. If the heuristics are
> > > > +only able to handle old and new values, then WRITE_ONCE()/READ_ONCE()
> > > > +must be used.
> > >
> > > Excellent addition!  I have applied the commit shown below with your
> > > Signed-off-by.  Please let me know if you would like me to take some other
> > > course of action.  And also please let me know if I messed something up.
> > >
> > > >  Writes Setting Values Feeding Into Error-Tolerant Heuristics
> > > > @@ -142,11 +135,8 @@ due to compiler-mangled reads, it can also tolerate the occasional
> > > >  compiler-mangled write, at least assuming that the proper value is in
> > > >  place once the write completes.
> > > >
> > > > -Plain C-language stores can also be used for this use case.  However,
> > > > -in kernels built with CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n, this
> > > > -will have the disadvantage of causing KCSAN to generate false positives
> > > > -because KCSAN will have no way of knowing that the resulting data race
> > > > -was intentional.
> > > > +Note that KCSAN will only detect mangled writes in kernels built with
> > > > +CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n.
> > >
> > > And the same point on needing to say this more than once.
> > >
> > >                                                       Thanx, Paul
> > >
> > > ------------------------------------------------------------------------
> > >
> > > commit 48db6caa1d32c39e7405df3940f9f7ba07ed0527
> > > Author: Manfred Spraul <manfred@colorfullife.com>
> > > Date:   Fri May 14 11:40:06 2021 -0700
> > >
> > >     tools/memory-model: Heuristics using data_race() must handle all values
> > >
> > >     Data loaded for use by some sorts of heuristics can tolerate the
> > >     occasional erroneous value.  In this case the loads may use data_race()
> > >     to give the compiler full freedom to optimize while also informing KCSAN
> > >     of the intent.  However, for this to work, the heuristic needs to be
> > >     able to tolerate any erroneous value that could possibly arise.  This
> > >     commit therefore adds a paragraph spelling this out.
> > >
> > >     Signed-off-by: Manfred Spraul <manfred@colorfullife.com>
> > >     Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > >
> > > diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/memory-model/Documentation/access-marking.txt
> > > index e4a20ebf565d..22ecadec4894 100644
> > > --- a/tools/memory-model/Documentation/access-marking.txt
> > > +++ b/tools/memory-model/Documentation/access-marking.txt
> > > @@ -126,6 +126,11 @@ consistent errors, which in turn are quite capable of breaking heuristics.
> > >  Therefore use of data_race() should be limited to cases where some other
> > >  code (such as a barrier() call) will force the occasional reload.
> > >
> > > +Note that this use case requires that the heuristic be able to handle
> > > +any possible error.  In contrast, if the heuristics might be fatally
> > > +confused by one or more of the possible erroneous values, use READ_ONCE()
> > > +instead of data_race().
> > > +
> > >  In theory, plain C-language loads can also be used for this use case.
> > >  However, in practice this will have the disadvantage of causing KCSAN
> > >  to generate false positives because KCSAN will have no way of knowing
> > >
> > > ----- End forwarded message -----

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210516225634.GC4441%40paulmck-ThinkPad-P17-Gen-1.
