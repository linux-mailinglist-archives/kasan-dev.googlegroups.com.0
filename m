Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX6D4XZAKGQEHWVSOEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0400F173FF8
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 19:54:25 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id y20sf1377900pfb.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 10:54:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582916063; cv=pass;
        d=google.com; s=arc-20160816;
        b=WcHXDZ5LqqpepwjLJx83CUGhE5m87d2oVbZaEPFkr3Ao/L2lIlmCv8b1XmlTlBemXX
         zbT57jL0jNZ9GWKKfkoryY465e9w5DpVdSL0fS3+Kh6D1Qnk+DQEQxpcR0g6Sz86Eqoo
         v4sFJ8fBcnBqP2SPM32QU3A+f3HQIOu2DKNA1RJg/931dFmtHOaIsnSZ8OWX3QPvoUub
         OqXMoYyOOmuVqYivni6vqQvHgC1M3BekdFkcNsfUOt83nV9t+5z+lhVdC8xhmUu2RpJI
         oRixmDRYopyJh+1BRL5fLaRTAfwqPeLOwxjWOd3UiUuX7d2pd6xNz9i1CjoqWnkS2VdO
         MRcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FnnuS7qjEXOWzD1H8RH5KYhUbfSYqIjXyl4cdyBFXR0=;
        b=lnBZ0EG7eChbphnJXmAzrNVycu3UU/o06J+zydW+mJg35eVt4PPXxviZBrNiGcckZz
         cCjnhk6IcB6LR7Ef5Y0dQyFRJLVXGtGqsW5NOlSmGfLhnt/Pg0nI771+xJEuC7BUOcdQ
         v9xhm/ulH8IWE38Ft9047K7dNaeSCTUnCV7/9H9nW/o5s9wTksn8mYsxwtk/T9efI0zP
         XEkpp2Wv/JNQ0xbe/mu69YPmcJevKI0xhXb5pnhqLPwicgdUr+5YTvRM9GKITCksDmwy
         sjTn75UdKkfL/rncs0JvP6TsKcnSLasehYPrJPUplNxAi3a3URlbZ8Cery/imb5Ijwqh
         DuxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JfzBdla9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FnnuS7qjEXOWzD1H8RH5KYhUbfSYqIjXyl4cdyBFXR0=;
        b=R9IK9WldssR/XeVjSnICAADTI2J0xZmoclfRmmpH3HHPUkvzeLvc2Tf+rKv8Vr0qTv
         cJS2Rb+Z3V7NP6QNGaJwcwPJpfB+hovDOazrWrJ6HtIKheOcANfMgD441e7qSRoquoUr
         Fxb4tNeehTO4N4Yo1pABY9OkdkAKB6vxm9jmIZzqzut4Em2vHhW5iNscX+LJMctwXu21
         s1BniA/7y7SPXtIUdzco5iF52j5luobXzlzngcn2CfuC0dFa9ZvzmAH+RK3a4+6qrydX
         v4JeWmJNCMI7JBXQKSq5aTrT2v+boh+RhXkxsQ2rtJeAu/UC6+9DELUNyFUECOhRSdSC
         d5Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FnnuS7qjEXOWzD1H8RH5KYhUbfSYqIjXyl4cdyBFXR0=;
        b=hhdu7EowNRUVh9VklYCHXtyaVJUKZB7cYLQpL7tKvgcu7tYJoDFiNyUSMi+a3H02xn
         2VC8sMFB5KVfaXrHCBy6mDl+mwqNEnwzRJNGdGZeBU0zxcDLFDYfxT6/wwPNa8WnFeyg
         DT/M2mrFZH0c84IYfPw+mU3OO4bFLWwbzFg2jz4xVpDi216hrq6RTgNG9PTB04AqbOcp
         1XWPPQlGd0bJzBjCdz4RGwHhpSdTcVajtD2FsB1w3bOy7RFIrupMyc8/4r8SSiZ8ks+M
         LoDwXSHSb2stD/SrnNZEcf0xMo7NWX2Znfdr9Djg6RZJIpjWVbXpOvuQXDju0AQxkI0w
         mwkg==
X-Gm-Message-State: APjAAAUDz8f4hvgs9A40RL8D5rnbCWixe9fIvOmgyAbtxVnHFWKrl/kf
	1jBWBDzqDvh7zMGYvRt/pIg=
X-Google-Smtp-Source: APXvYqyfKo5PiSPdPOVQL423X9zIoyTKDGGjaiWImaoCR/HJ6n16QE3arbo0DNgXKaHXhzIHB6IxDg==
X-Received: by 2002:a17:90a:7303:: with SMTP id m3mr6273974pjk.62.1582916063437;
        Fri, 28 Feb 2020 10:54:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ff11:: with SMTP id f17ls1268411plj.4.gmail; Fri, 28
 Feb 2020 10:54:22 -0800 (PST)
X-Received: by 2002:a17:90a:ac0e:: with SMTP id o14mr6337316pjq.11.1582916062902;
        Fri, 28 Feb 2020 10:54:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582916062; cv=none;
        d=google.com; s=arc-20160816;
        b=NEUIPgUGEpBlwSGTmIfbLHt0zAB9gxnZF7NSNS3j3CniNpEx8MzfLb4y1nHqI6wf0b
         jjrsQLjoj9GDOFRyegwOftz1wDQ0H8DkHi/f47PEixjiHQ/7mOQd9j7X/9owEPkugQ0F
         m1SllzDzQodHe7z4YKsO4z/1OogvSgd9rV40nrso6diQByCYxMizNxWRAEEXe27OSwLA
         FoC3USo8ZliWBSwje3PKAM9cmZuyUST72nnJ/ULkQlu43yyAIfQVVxvIy+u8zR2w1faz
         2v/KWumBHqtEn398nxivndHbFC/Si2jw4ZaEG0daZHpzPCWDCE1pdCYoFBDOyQPDx00G
         kWLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CIzu0bxWTlPcGKncH1ZbGeY7b+QCcXLXrxcS18DRBR4=;
        b=VCgZbZ20o3h2Gpu56np6CMZ5mCgt+/WZ7FPbW5n/f2pdb4UbNINPZfEZ6lEnWmA6iU
         6AUhvcjB8KdI4m3II5+N+7ofnk5PQ4hXb4Y6R5Wgl6CpI+5ekHyrsOsetOlo0BKBlwaD
         5WRMZGvi96onnAlGglSaaSdT0yq1ekS0E/2SyCyxe6j+dhXYIix6nJO7MpDzmP1iX1p2
         MhXdFQlgFGXm/piNeyyDCzd0d6MD+kr5/MNy9F28EFUeNf6/7b+A3CITkbdF83/uUhU3
         M471dmUJ4HYRFHV/J628nXo8909Je9PMGiHrDyoz0Gg2KpTN8mOl4suSkl35VeYYmiJq
         umgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JfzBdla9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id d12si454322pjv.0.2020.02.28.10.54.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 10:54:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id a22so3805502oid.13
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 10:54:22 -0800 (PST)
X-Received: by 2002:a54:4510:: with SMTP id l16mr4143519oil.70.1582916062251;
 Fri, 28 Feb 2020 10:54:22 -0800 (PST)
MIME-Version: 1.0
References: <20200228164621.87523-1-elver@google.com> <Pine.LNX.4.44L0.2002281202230.1599-100000@iolanthe.rowland.org>
In-Reply-To: <Pine.LNX.4.44L0.2002281202230.1599-100000@iolanthe.rowland.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 19:54:10 +0100
Message-ID: <CANpmjNPHfZbBgyJu3hS2sGaN4G+F6_dfavW8Mn7ZmFj60Lb6hg@mail.gmail.com>
Subject: Re: [PATCH] tools/memory-model/Documentation: Fix "conflict" definition
To: Alan Stern <stern@rowland.harvard.edu>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrea Parri <parri.andrea@gmail.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Nicholas Piggin <npiggin@gmail.com>, David Howells <dhowells@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Luc Maranget <luc.maranget@inria.fr>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Daniel Lustig <dlustig@nvidia.com>, 
	Joel Fernandes <joel@joelfernandes.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JfzBdla9;       spf=pass
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

On Fri, 28 Feb 2020 at 18:24, Alan Stern <stern@rowland.harvard.edu> wrote:
>
> On Fri, 28 Feb 2020, Marco Elver wrote:
>
> > For language-level memory consistency models that are adaptations of
> > data-race-free, the definition of "data race" can be summarized as
> > "concurrent conflicting accesses, where at least one is non-sync/plain".
> >
> > The definition of "conflict" should not include the type of access nor
> > whether the accesses are concurrent or not, which this patch addresses
> > for explanation.txt.
>
> Why shouldn't it?  Can you provide any references to justify this
> assertion?

The definition of "conflict" as we know it and is cited by various
papers on memory consistency models appeared in [1]: "Two accesses to
the same variable conflict if at least one is a write; two operations
conflict if they execute conflicting accesses."

The LKMM as well as C11 are adaptations of data-race-free, which are
based on the work in [2]. Necessarily, we need both conflicting data
operations (plain) and synchronization operations (marked). C11's
definition is based on [3], which defines a "data race" as:  "Two
memory operations conflict if they access the same memory location,
and at least one of them is a store, atomic store, or atomic
read-modify-write operation. In a sequentially consistent execution,
two memory operations from different threads form a type 1 data race
if they conflict, at least one of them is a data operation, and they
are adjacent in <T (i.e., they may be executed concurrently)."

[1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
Programs that Share Memory", 1988.
      URL: http://snir.cs.illinois.edu/listed/J21.pdf

[2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
Multiprocessors", 1993.
      URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf

[3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
Model", 2008.
     URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf

> Also, note two things: (1) The existing text does not include
> concurrency in the definition of "conflict".  (2) Your new text does
> include the type of access in the definition (you say that at least one
> of the accesses must be a write).

Yes, "conflict" is defined in terms of "access to the same memory
location and at least one performs a write" (can be any operation that
performs a write, including RMWs etc.). It should not include
concurrency. We can have conflicting operations that are not
concurrent, but these will never be data races.

> > The definition of "data race" remains unchanged, but the informal
> > definition for "conflict" is restored to what can be found in the
> > literature.
>
> It does not remain unchanged.  You removed the portion that talks about
> accesses executing on different CPUs or threads.  Without that
> restriction, you raise the nonsensical possibility that a single thread
> may by definition have a data race with itself (since modern CPUs use
> multiple-instruction dispatch, in which several instructions can
> execute at the same time).

Andrea raised the point that "occur on different CPUs (or in different
threads on the same CPU)" can be interpreted as "in different threads
[even if they are serialized via some other synchronization]".

Arguably, no sane memory model or abstract machine model permits
observable intra-thread concurrency of instructions in the same
thread. At the abstract machine level, whether or not there is true
parallelism shouldn't be something that the model concerns itself
with. Simply talking about "concurrency" is unambiguous, unless the
model says intra-thread concurrency is a thing.

I can add it back if it helps make this clearer, but we need to mention both.

> > Signed-by: Marco Elver <elver@google.com>
> > ---
> >  tools/memory-model/Documentation/explanation.txt | 15 ++++++---------
> >  1 file changed, 6 insertions(+), 9 deletions(-)
> >
> > diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
> > index e91a2eb19592a..11cf89b5b85d9 100644
> > --- a/tools/memory-model/Documentation/explanation.txt
> > +++ b/tools/memory-model/Documentation/explanation.txt
> > @@ -1986,18 +1986,15 @@ violates the compiler's assumptions, which would render the ultimate
> >  outcome undefined.
> >
> >  In technical terms, the compiler is allowed to assume that when the
> > -program executes, there will not be any data races.  A "data race"
> > -occurs when two conflicting memory accesses execute concurrently;
> > -two memory accesses "conflict" if:
> > +program executes, there will not be any data races. A "data race"
>
> Unnecessary (and inconsistent with the rest of the document) whitespace
> change.

Reverted.

> > +occurs if:
> >
> > -     they access the same location,
> > +     two concurrent memory accesses "conflict";
> >
> > -     they occur on different CPUs (or in different threads on the
> > -     same CPU),
> > +     and at least one of the accesses is a plain access;
> >
> > -     at least one of them is a plain access,
> > -
> > -     and at least one of them is a store.
> > +     where two memory accesses "conflict" if they access the same
> > +     memory location, and at least one performs a write;
> >
> >  The LKMM tries to determine whether a program contains two conflicting
> >  accesses which may execute concurrently; if it does then the LKMM says
>
> To tell the truth, the only major change I can see here (apart from the
> "differenct CPUs" restriction) is that you want to remove the "at least
> one is plain" part from the definition of "conflict" and instead make
> it a separate requirement for a data race.  That's fine with me in
> principle, but there ought to be an easier way of doing it.

Yes pretty much. The model needs to be able to talk about "conflicting
synchronization accesses" where all accesses are marked. Right now the
definition of conflict doesn't permit that.

> Furthermore, this section of explanation.txt goes on to use the words
> "conflict" and "conflicting" in a way that your patch doesn't address.
> For example, shortly after this spot it says "Determining whether two
> accesses conflict is easy"; you should change it to say "Determining
> whether two accesses conflict and at least one of them is plain is
> easy" -- but this looks pretty ungainly.  A better approach might be to
> introduce a new term, define it to mean "conflicting accesses at least
> one of which is plain", and then use it instead throughout.

The definition of "conflict" as used in the later text is synonymous
with "data race".

> Alternatively, you could simply leave the text as it stands and just
> add a parenthetical disclaimer pointing out that in the CS literature,
> the term "conflict" is used even when both accesses are marked, so the
> usage here is somewhat non-standard.

The definition of what a "conflict" is, is decades old [1, 2]. I
merely thought we should avoid changing fundamental definitions that
have not changed in decades, to avoid confusing people. The literature
on memory models is confusing enough, so fundamental definitions that
are "common ground" shouldn't be changed if it can be avoided. I think
here it is pretty trivial to avoid.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPHfZbBgyJu3hS2sGaN4G%2BF6_dfavW8Mn7ZmFj60Lb6hg%40mail.gmail.com.
