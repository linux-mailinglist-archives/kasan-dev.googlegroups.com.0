Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNMD6XZAKGQEYS3FKXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id F1CA01760FC
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 18:26:14 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id e8sf319437qtg.9
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 09:26:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583169974; cv=pass;
        d=google.com; s=arc-20160816;
        b=fxA7jrax7qFjhaR/FCsmDZTIwr3I3d2EuDD+ylbnBJfLRou8+hqyzwSTsBS/eebd6E
         64l3W1pfeGNTkLRa8E6KUVKtl1iX57vJCGDirGxBak0kn+4AQEVU3rJR71jgbtnVvNbO
         h0wiqrO4780F2wJ14tEi427uuuQSrUEGCKC8BmEHnv5UV4M4xLa6yoY2+9sFOR9R7Uid
         XdYOWO7KkDEfGYfHi/znaGXKT1ir4cdZZdR6QHFqrgKdcGeampaZgYW1+d4mGzwXWFIL
         4Q6gb7g3EO4w+/VuDedF1/Q5iQZlV2LaxCf/s6Ex1E15JTw+7hAGimGTvn7iIlsQ/N9c
         wUrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lzypTeIutp6t+7nRZduft7nTEsDgwZ2dXc5OlsWZGSs=;
        b=dbQkyyodcTGK/dyhCSgAnpxbS4wTMWlRRdCfWgqKLlo73uEkyWitLlyb3Cfh2IRsWi
         iQLY6iuSASKFPWAaqBQNb/7OhkzDo9Baedyp7aGJpDQar9FZAhzHm5foN8ggN0KcQR8J
         pihl4tk5XMybcoD4UOsuaBegbcrdzCz/8PH41M1fP8RYMR/sErvbyVA1lGiCKDFNY4t5
         Kkn0OlWwzVHIQe8TQVD0CDcfP2MbCsu5VMT8l0lpCOH7hE8XyybVHPSf/xdb2XFrrgrM
         Ml1SaxeYo3tGwMV6sRQRHI1s0uI9i4ZI5PHRDZLMLlIB5NQXzjsgjKeHqh99FWQdWOIU
         TLaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NKuXIOmW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lzypTeIutp6t+7nRZduft7nTEsDgwZ2dXc5OlsWZGSs=;
        b=qbAx8sTFYoJIlM4QVc7h+RvW5q5XMVmTYKgaDKwr8R9xnrES9MaKy2PJOZK5W72ufV
         UoPFe6BNym6MoUaXdGde3P3qCjv08P6p37BOvkW4VDstA3k4D9lLet0FN5uAG2uNMtUR
         Sk1LfuZ8WwmhrSZ8JJ/QH/oAjqP1SV6uXCRB9lz3wTgbHFd46ZE9aYbgzu7iksGTmkkT
         Tol4EOfqy+O1Vv2Lt07Nwyo0hDm7XUNOn2qfkG+1Alnc4wn74nB3FAlscgwvzESCGqHO
         MTWA5afTVvzQMDp68JfPmD19FNvz/uLl+5x+eiN17xDcLzU7ZDJ7Hx6GhhSFD81RGlo2
         h88Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lzypTeIutp6t+7nRZduft7nTEsDgwZ2dXc5OlsWZGSs=;
        b=fY091LQmSLEqWm89BS3MCI4rEOfDR8UdbYhF01IQLT2yQ5CYH8OWeiBaAeBj7S21of
         a5hyXQwhRzx8DPcXrZjBFppnoqphC2VptSBdWtY8RyGB3901bKcoAOULW7e7rkWmmcRx
         THpSf8bZ0IiIO8wAhgIiYNsODKryCokTfAdc844kyXsLDPKDgni9HRPxy31+tTyA9wnH
         JC4pLXZ27yUjd1AyOQqyNceFJ2/ikLisQZl8uNC0oQq5UHqsUXK8K4ta9mYQF8htMbs9
         ev8c59vCL9PDhpLC30NMur/aiBV9A+oaTktH3HlWvlAujVA+Gw80EIY2PeD28qaJiOSf
         JazQ==
X-Gm-Message-State: ANhLgQ3tQGqyA8Kb8SZqrMCG0MByc36Os/gl+e3U++pielZ00D5KZBk3
	3JyVOViYQ4XxtPujG9vWqxA=
X-Google-Smtp-Source: ADFU+vt+CYv3Meo7VdG2/pvGcRCHBFtRzqF3Yu/u2TwP7+3YkVA6fHdDSrIzqsquzdkQfjB/5LJYIw==
X-Received: by 2002:a37:a8c5:: with SMTP id r188mr334553qke.328.1583169973999;
        Mon, 02 Mar 2020 09:26:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4044:: with SMTP id j4ls53094qtl.7.gmail; Mon, 02 Mar
 2020 09:26:13 -0800 (PST)
X-Received: by 2002:ac8:5510:: with SMTP id j16mr753584qtq.262.1583169973609;
        Mon, 02 Mar 2020 09:26:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583169973; cv=none;
        d=google.com; s=arc-20160816;
        b=HkcmqXHBrfDFrdIVRko8TT5MvpvgV+ATX5ZvFBIrujV9av2OzU1fFKFN/dgyJlufp4
         0IpTXiRLS9wHVODXAQoW8a42k+CQQlSJTgc3fkVV+cbR+6NormbuWzyDm8Ch/CmIbvBL
         vqsNZ1jfdaGfO6+Nrl8fzX6XEkJ3QFuJPv8QnO1INiDUoM9IgmZEFUWSkZCIgkEpOjP0
         eyBQwMOWNydZtiYYJBysBNDjYcXQxIELDHBIU3oW3/+0WUkTZ6x7UmNo4Zxa4qeV9J6f
         BrMN42/SSltCo3lZLsatrqPHEEOuhMTy1iNVQr1Ei0iLgdGNHDlcdbonYJUfAAYYoiJC
         fmcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZaTSpHFt5MftmtYSad2hy72pa4qDj42XRRqq+4ZzagY=;
        b=wUFVGnxkY/s5YdGBvKKTSivAepwSalAZYdndGyL9CyMD/MyKf6/nZSgun28HsJT7n+
         RRzpEi6s+eiLtDWq4V4cmUhH0X4QVkqCwVzH/86nZPTHczMgNIgsuGjxydgW+n460Mqy
         IBTHcMiHL2WFJzAxtiI/uU4XOnU9pz0exbrcRuRGMBtpWD7N4T5d35xt56lqLG4Hfvrc
         MIhN59qFaGEFa3JqshNg6cOjeP5ZawttWkyuGz/HSIMbkhs364M88rP/IEhOnhRDqp95
         w2BHsk+xwDbalAqmxrJaXdJlRcfXicHpNNo1Ob3p8mDtrJqrIfGIDbvlLfDKNKTUcR2/
         i3bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NKuXIOmW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id s202si468941qke.3.2020.03.02.09.26.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 09:26:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id g6so22486oiy.1
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 09:26:13 -0800 (PST)
X-Received: by 2002:a54:4510:: with SMTP id l16mr138926oil.70.1583169972647;
 Mon, 02 Mar 2020 09:26:12 -0800 (PST)
MIME-Version: 1.0
References: <20200302141819.40270-1-elver@google.com> <Pine.LNX.4.44L0.2003021134360.1555-100000@iolanthe.rowland.org>
In-Reply-To: <Pine.LNX.4.44L0.2003021134360.1555-100000@iolanthe.rowland.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Mar 2020 18:26:01 +0100
Message-ID: <CANpmjNPeRibmjpNfWEcfayPsEqKJ0uwU7=7w4CGuyWMdhdPrrg@mail.gmail.com>
Subject: Re: [PATCH v2] tools/memory-model/Documentation: Fix "conflict" definition
To: Alan Stern <stern@rowland.harvard.edu>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Nicholas Piggin <npiggin@gmail.com>, David Howells <dhowells@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Luc Maranget <luc.maranget@inria.fr>, 
	"Paul E. McKenney" <paulmck@kernel.org>, LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Joel Fernandes <joel@joelfernandes.org>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NKuXIOmW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Mon, 2 Mar 2020 at 17:47, Alan Stern <stern@rowland.harvard.edu> wrote:
>
> On Mon, 2 Mar 2020, Marco Elver wrote:
>
> > Alan: I think this needs your Signed-off-by, since I added you as
> > Co-developed-by.
>
> Here you go:
>
> Signed-off-by: Alan Stern <stern@rowland.harvard.edu>
>
> > Let me know if this works for you.
>
> See below.
>
> > The definition of "conflict" should not include the type of access nor
> > whether the accesses are concurrent or not, which this patch addresses.
> > The definition of "data race" remains unchanged.
> >
> > The definition of "conflict" as we know it and is cited by various
> > papers on memory consistency models appeared in [1]: "Two accesses to
> > the same variable conflict if at least one is a write; two operations
> > conflict if they execute conflicting accesses."
> >
> > The LKMM as well as the C11 memory model are adaptations of
> > data-race-free, which are based on the work in [2]. Necessarily, we need
> > both conflicting data operations (plain) and synchronization operations
> > (marked). For example, C11's definition is based on [3], which defines a
> > "data race" as: "Two memory operations conflict if they access the same
> > memory location, and at least one of them is a store, atomic store, or
> > atomic read-modify-write operation. In a sequentially consistent
> > execution, two memory operations from different threads form a type 1
> > data race if they conflict, at least one of them is a data operation,
> > and they are adjacent in <T (i.e., they may be executed concurrently)."
> >
> > [1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
> >     Programs that Share Memory", 1988.
> >       URL: http://snir.cs.illinois.edu/listed/J21.pdf
> >
> > [2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
> >     Multiprocessors", 1993.
> >       URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf
> >
> > [3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
> >     Model", 2008.
> >       URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Co-developed-by: Alan Stern <stern@rowland.harvard.edu>
> > ---
> > v2:
> > * Apply Alan's suggested version.
> >   - Move "from different CPUs (or threads)" from "conflict" to "data
> >     race" definition. Update "race candidate" accordingly.
> > * Add citations to commit message.
> >
> > v1: http://lkml.kernel.org/r/20200228164621.87523-1-elver@google.com
> > ---
> >  .../Documentation/explanation.txt             | 77 +++++++++----------
> >  1 file changed, 38 insertions(+), 39 deletions(-)
> >
> > diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
> > index e91a2eb19592a..7a59cadc2f4ca 100644
> > --- a/tools/memory-model/Documentation/explanation.txt
> > +++ b/tools/memory-model/Documentation/explanation.txt
> > @@ -1987,28 +1987,28 @@ outcome undefined.
> >
> >  In technical terms, the compiler is allowed to assume that when the
> >  program executes, there will not be any data races.  A "data race"
> > -occurs when two conflicting memory accesses execute concurrently;
> > -two memory accesses "conflict" if:
> > +occurs when two conflicting memory accesses from different CPUs (or
> > +different threads on the same CPU) execute concurrently, and at least
> > +one of them is plain.  Two memory accesses "conflict" if:
> >
> >       they access the same location,
> >
> > -     they occur on different CPUs (or in different threads on the
> > -     same CPU),
> > -
> > -     at least one of them is a plain access,
> > -
> >       and at least one of them is a store.
> >
> > -The LKMM tries to determine whether a program contains two conflicting
> > -accesses which may execute concurrently; if it does then the LKMM says
> > -there is a potential data race and makes no predictions about the
> > -program's outcome.
> > -
> > -Determining whether two accesses conflict is easy; you can see that
> > -all the concepts involved in the definition above are already part of
> > -the memory model.  The hard part is telling whether they may execute
> > -concurrently.  The LKMM takes a conservative attitude, assuming that
> > -accesses may be concurrent unless it can prove they cannot.
> > +We'll say that two accesses from different threads are "race
> > +candidates" if they conflict and at least one of them is plain.
> > +Whether or not two candidates actually do race in a given execution
> > +then depends on whether they are concurrent.  The LKMM tries to
> > +determine whether a program contains race candidates which may execute
> > +concurrently; if it does then the LKMM says there is a potential data
> > +race and makes no predictions about the program's outcome.
>
> Hmmm.  Although the content is okay, I don't like the organization very
> much.  What do you think of this for the above portion of the patch)?

Thanks, looks good to me. Applied in v3:
http://lkml.kernel.org/r/20200302172101.157917-1-elver@google.com

-- Marco

> Alan Stern
>
>
>
> Index: usb-devel/tools/memory-model/Documentation/explanation.txt
> ===================================================================
> --- usb-devel.orig/tools/memory-model/Documentation/explanation.txt
> +++ usb-devel/tools/memory-model/Documentation/explanation.txt
> @@ -1987,28 +1987,36 @@ outcome undefined.
>
>  In technical terms, the compiler is allowed to assume that when the
>  program executes, there will not be any data races.  A "data race"
> -occurs when two conflicting memory accesses execute concurrently;
> -two memory accesses "conflict" if:
> +occurs when there are two memory accesses such that:
>
> -       they access the same location,
> +1.     they access the same location,
>
> -       they occur on different CPUs (or in different threads on the
> -       same CPU),
> +2.     at least one of them is a store,
> +
> +3.     at least one of them is plain,
>
> -       at least one of them is a plain access,
> +4.     they occur on different CPUs (or in different threads on the
> +       same CPU), and
>
> -       and at least one of them is a store.
> +5.     they execute concurrently.
>
> -The LKMM tries to determine whether a program contains two conflicting
> -accesses which may execute concurrently; if it does then the LKMM says
> -there is a potential data race and makes no predictions about the
> +In the literature, two accesses are said to "conflict" if they satisfy
> +1 and 2 above.  We'll go a little farther and say that two accesses
> +are "race candidates" if they satisfy 1 - 4.  Thus, whether or not two
> +race candidates actually do race in a given execution depends on
> +whether they are concurrent.
> +
> +The LKMM tries to determine whether a program contains two race
> +candidates which may execute concurrently; if it does then the LKMM
> +says there is a potential data race and makes no predictions about the
>  program's outcome.
>
> -Determining whether two accesses conflict is easy; you can see that
> -all the concepts involved in the definition above are already part of
> -the memory model.  The hard part is telling whether they may execute
> -concurrently.  The LKMM takes a conservative attitude, assuming that
> -accesses may be concurrent unless it can prove they cannot.
> +Determining whether two accesses are race candidates is easy; you can
> +see that all the concepts involved in the definition above are already
> +part of the memory model.  The hard part is telling whether they may
> +execute concurrently.  The LKMM takes a conservative attitude,
> +assuming that accesses may be concurrent unless it can prove they
> +are not.
>
>  If two memory accesses aren't concurrent then one must execute before
>  the other.  Therefore the LKMM decides two accesses aren't concurrent
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPeRibmjpNfWEcfayPsEqKJ0uwU7%3D7w4CGuyWMdhdPrrg%40mail.gmail.com.
