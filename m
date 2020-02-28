Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRWG4XZAKGQESY3DXVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 59034174005
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 20:00:23 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id z13sf870312oti.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 11:00:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582916422; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hh2IrcW1cYXsYe4PU/w+LefCNO8Ulnm6OvDpesz/3TltIOpFgjZoIX6D2bs+pbW9CA
         e1wuCnozhgv03SMVykPxdICgyODZUd9HVGHkEpFDiMaRN1n6/gQaUXXC/mCzKusBnib/
         k0pOEGhCHxaZ97t+/POQ6L+lRIoXMlmYBDA1L5ACiIiftzHteZk+JYjbMg8kEISYYDz5
         T/VSojkDsvik3+9qtG034EGQRhL4FXSgt1YEnprdKcA335A1VWTTp+wo2jkZYVzMZGDy
         ktTuBORjWQl//m3acvHLAiff/6gE8uIYGdLIBEOabWE09et+6VipIVZAv+jLajx4CYqp
         FFOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CiitYwmWsVaMJksk+hKenbr2/R1K/9OY3seK+XuFjEk=;
        b=SXkFQ5VH9ibzrc6YV53psBwHgXObEJsRtj1gZ0cdG0f62WFRXu3chDJT2396ZZrbWa
         kV1BfZm8aHKnscMIFKupjfYLVJfXPJVaFkoZPldp5+zmiTwY6KvwpnH2jJDaTnWtuOE/
         eYkPvHcOWJZZ+Iqmr4TdWw+/VpRZxMO7Yr3A+YZmD85IDDETJ+cJezwZETu02tS4aymD
         VTnS0yod5FOQms/TpMG2HFUnWqEmQrW7vAHMoVMmZF6MrHbVT06i9Fy69JlurghGwFUY
         AQAZhWQz+khNtLxLl/s+4Qz0DYhdosJycn9lk5H4ao3FMEI0ICdTHkP0TQr6ZMTB1VuI
         h01g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CDbxfYCQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CiitYwmWsVaMJksk+hKenbr2/R1K/9OY3seK+XuFjEk=;
        b=FXORTvqoYwNA/z41qrYo5pCtuw0qpN0LoDRG0mxUxRq7S/SkUyYD5PJ8G36dzdzh9W
         njQtMiyunGg8gczNAM9ZMIXJyntdR7tmPv8oYuiMY7bbgyxRxp059S54691sceO9nQB4
         lP1vJ69PFIx95oHmCdLg9EGqJicoCiEjAYR4Sz70Udetz6+xXFyJ0UrWexaaZnLPKF9r
         C8rHLS5VkN/yynZ05XvCM9VO336QIGm5Jdjtp7X9nm3o1z/ygLGMeiMhs2YP7Rso9RUA
         +O5RkUtC2vQoUn1itU1L2pk8oxKYJ921OIZ7y6QGM8ehASo+CX9+bcvwfNdaAu3y3Fyb
         ajPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CiitYwmWsVaMJksk+hKenbr2/R1K/9OY3seK+XuFjEk=;
        b=Z3PffvCNu4um+nkXfWysiVycTqTkur4TAwvwQIItHKaf+BRHViy6o9WubqJTobSINR
         +bRGlUpah9PkPReszOCUoJHsyWiMXXCvzPn+OcQHpJbchKgrOkmwF8V0g/WfXuNE4LvZ
         d7wSY2XRUDXkS68uEW+HuYvtlNytrcUZlLxfVAWQksZSi3HL3dECyfbANzKA8xCQd7Fo
         Lnt0Ued/SHOUvb7etwVz33BFloq4jonV8LqI3AtnugVBMkf2sf7FhQsa1eYaxBG9X9d/
         6Ta6qjqzc8m8r5yuHilHFiS+c6WLZfA4Dmey9Kiy8Uml2ETfsyD5mTfWnVq/0XZ0Zy6f
         3/1w==
X-Gm-Message-State: APjAAAUOhczKUf0Y/f3FvDQuuG/0Ul1tA/IfnqVAx+rRgQACfbpOqc8s
	Q7wW9epL+LU7RNBuDgmqjd0=
X-Google-Smtp-Source: APXvYqwUUn0e1o1q5B+B9g1RG4qiUQble5XfnoNVWJFMQgoMHO+AtKn5nP5e2ohkulaJcnEDwnwFZg==
X-Received: by 2002:aca:3805:: with SMTP id f5mr4209377oia.6.1582916422216;
        Fri, 28 Feb 2020 11:00:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:895:: with SMTP id 143ls1347912oii.1.gmail; Fri, 28 Feb
 2020 11:00:21 -0800 (PST)
X-Received: by 2002:aca:5f87:: with SMTP id t129mr4230538oib.36.1582916421789;
        Fri, 28 Feb 2020 11:00:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582916421; cv=none;
        d=google.com; s=arc-20160816;
        b=vmScVfM0EH2k7wX1yUkNUpTASmdZPITSqeQfGVShkY+TEglU2UkbkLxehP8OIzz2/A
         SXKjIHMj1HY/wzCNO6269lItdrG4gWP1iefVroNsZpE987Q+Oo+S7dXBHxa6QPCBNr+U
         5NsIGByuqsBpVHoTa+3O1Jdel1I1VHeE2S3CHxRXRPFA8H2Fh0BKvKhWMinBLK+AJH/c
         7cdaMffQ6fjt85J0Y1fHqgIyVdQkFMjwqwqnA26c0ulYFum/xro58qaN/DZ+GsK+Z8s/
         /lVo4KcUOzq/5kOWyMEl4FfSx4rbJtt+4UK1LkGpLpAtF9Cae+SzdLBObnT8Hb487hsE
         W5rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E3314c38kKdtMv4Y2j3OsEk0lExKN7QFZinFcFgHh+g=;
        b=w5BSko3jKgZQIK649ssvju5onx1kzQXwS4Ygp0Irwn5ngappRT/jdU2enrPE4hP599
         Lj5+e1Q8L0l+zXKWzvmqeJ6oID1QhukmcQMsOrLJaUmZXr4EQQ5yFUKc5iUUMPjTzC8F
         j8qVxCJcKWb3ka99Zyia911d+PWZRud4JzQm4Fo61xDu3d9aVTA9GBEhdkKbR/g6nfH8
         KzCyA65tKPFwg4HzZ9EGgSblWZKzTcv2T79wrrpfDSc3O5sY8jzRMve7BqgwtsnSPvCc
         zgM97//IEKYNejZxiMAtMxLN4PFsFViSrX1L4jdETm9EY2nlHMcj31LkC88aSrU0d2R+
         CXeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CDbxfYCQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id h199si182670oib.2.2020.02.28.11.00.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 11:00:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id j16so3609965otl.1
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 11:00:21 -0800 (PST)
X-Received: by 2002:a9d:906:: with SMTP id 6mr2079998otp.251.1582916421150;
 Fri, 28 Feb 2020 11:00:21 -0800 (PST)
MIME-Version: 1.0
References: <20200228164621.87523-1-elver@google.com> <Pine.LNX.4.44L0.2002281202230.1599-100000@iolanthe.rowland.org>
 <CANpmjNPHfZbBgyJu3hS2sGaN4G+F6_dfavW8Mn7ZmFj60Lb6hg@mail.gmail.com>
In-Reply-To: <CANpmjNPHfZbBgyJu3hS2sGaN4G+F6_dfavW8Mn7ZmFj60Lb6hg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 20:00:09 +0100
Message-ID: <CANpmjNMOmirPRKbjX9=V+eZD-YsEvfhUU8r6EDefkOJTBLDYNQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=CDbxfYCQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Fri, 28 Feb 2020 at 19:54, Marco Elver <elver@google.com> wrote:
>
> On Fri, 28 Feb 2020 at 18:24, Alan Stern <stern@rowland.harvard.edu> wrote:
> >
> > On Fri, 28 Feb 2020, Marco Elver wrote:
> >
> > > For language-level memory consistency models that are adaptations of
> > > data-race-free, the definition of "data race" can be summarized as
> > > "concurrent conflicting accesses, where at least one is non-sync/plain".
> > >
> > > The definition of "conflict" should not include the type of access nor
> > > whether the accesses are concurrent or not, which this patch addresses
> > > for explanation.txt.
> >
> > Why shouldn't it?  Can you provide any references to justify this
> > assertion?
>
> The definition of "conflict" as we know it and is cited by various
> papers on memory consistency models appeared in [1]: "Two accesses to
> the same variable conflict if at least one is a write; two operations
> conflict if they execute conflicting accesses."
>
> The LKMM as well as C11 are adaptations of data-race-free, which are
> based on the work in [2]. Necessarily, we need both conflicting data
> operations (plain) and synchronization operations (marked). C11's
> definition is based on [3], which defines a "data race" as:  "Two
> memory operations conflict if they access the same memory location,
> and at least one of them is a store, atomic store, or atomic
> read-modify-write operation. In a sequentially consistent execution,
> two memory operations from different threads form a type 1 data race
> if they conflict, at least one of them is a data operation, and they
> are adjacent in <T (i.e., they may be executed concurrently)."
>
> [1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
> Programs that Share Memory", 1988.
>       URL: http://snir.cs.illinois.edu/listed/J21.pdf
>
> [2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
> Multiprocessors", 1993.
>       URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf
>
> [3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
> Model", 2008.
>      URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf
>
> > Also, note two things: (1) The existing text does not include
> > concurrency in the definition of "conflict".  (2) Your new text does
> > include the type of access in the definition (you say that at least one
> > of the accesses must be a write).
>
> Yes, "conflict" is defined in terms of "access to the same memory
> location and at least one performs a write" (can be any operation that
> performs a write, including RMWs etc.). It should not include
> concurrency. We can have conflicting operations that are not
> concurrent, but these will never be data races.
>
> > > The definition of "data race" remains unchanged, but the informal
> > > definition for "conflict" is restored to what can be found in the
> > > literature.
> >
> > It does not remain unchanged.  You removed the portion that talks about
> > accesses executing on different CPUs or threads.  Without that
> > restriction, you raise the nonsensical possibility that a single thread
> > may by definition have a data race with itself (since modern CPUs use
> > multiple-instruction dispatch, in which several instructions can
> > execute at the same time).
>
> Andrea raised the point that "occur on different CPUs (or in different
> threads on the same CPU)" can be interpreted as "in different threads
> [even if they are serialized via some other synchronization]".
>
> Arguably, no sane memory model or abstract machine model permits
> observable intra-thread concurrency of instructions in the same
> thread. At the abstract machine level, whether or not there is true
> parallelism shouldn't be something that the model concerns itself
> with. Simply talking about "concurrency" is unambiguous, unless the
> model says intra-thread concurrency is a thing.
>
> I can add it back if it helps make this clearer, but we need to mention both.
>
> > > Signed-by: Marco Elver <elver@google.com>
> > > ---
> > >  tools/memory-model/Documentation/explanation.txt | 15 ++++++---------
> > >  1 file changed, 6 insertions(+), 9 deletions(-)
> > >
> > > diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
> > > index e91a2eb19592a..11cf89b5b85d9 100644
> > > --- a/tools/memory-model/Documentation/explanation.txt
> > > +++ b/tools/memory-model/Documentation/explanation.txt
> > > @@ -1986,18 +1986,15 @@ violates the compiler's assumptions, which would render the ultimate
> > >  outcome undefined.
> > >
> > >  In technical terms, the compiler is allowed to assume that when the
> > > -program executes, there will not be any data races.  A "data race"
> > > -occurs when two conflicting memory accesses execute concurrently;
> > > -two memory accesses "conflict" if:
> > > +program executes, there will not be any data races. A "data race"
> >
> > Unnecessary (and inconsistent with the rest of the document) whitespace
> > change.
>
> Reverted.
>
> > > +occurs if:
> > >
> > > -     they access the same location,
> > > +     two concurrent memory accesses "conflict";
> > >
> > > -     they occur on different CPUs (or in different threads on the
> > > -     same CPU),
> > > +     and at least one of the accesses is a plain access;
> > >
> > > -     at least one of them is a plain access,
> > > -
> > > -     and at least one of them is a store.
> > > +     where two memory accesses "conflict" if they access the same
> > > +     memory location, and at least one performs a write;
> > >
> > >  The LKMM tries to determine whether a program contains two conflicting
> > >  accesses which may execute concurrently; if it does then the LKMM says
> >
> > To tell the truth, the only major change I can see here (apart from the
> > "differenct CPUs" restriction) is that you want to remove the "at least
> > one is plain" part from the definition of "conflict" and instead make
> > it a separate requirement for a data race.  That's fine with me in
> > principle, but there ought to be an easier way of doing it.
>
> Yes pretty much. The model needs to be able to talk about "conflicting
> synchronization accesses" where all accesses are marked. Right now the
> definition of conflict doesn't permit that.
>
> > Furthermore, this section of explanation.txt goes on to use the words
> > "conflict" and "conflicting" in a way that your patch doesn't address.
> > For example, shortly after this spot it says "Determining whether two
> > accesses conflict is easy"; you should change it to say "Determining
> > whether two accesses conflict and at least one of them is plain is
> > easy" -- but this looks pretty ungainly.  A better approach might be to
> > introduce a new term, define it to mean "conflicting accesses at least
> > one of which is plain", and then use it instead throughout.
>
> The definition of "conflict" as used in the later text is synonymous
> with "data race".

Correction: it's "data race" minus "concurrent" which makes things
more difficult. In which case, fixing this becomes more difficult.

> > Alternatively, you could simply leave the text as it stands and just
> > add a parenthetical disclaimer pointing out that in the CS literature,
> > the term "conflict" is used even when both accesses are marked, so the
> > usage here is somewhat non-standard.
>
> The definition of what a "conflict" is, is decades old [1, 2]. I
> merely thought we should avoid changing fundamental definitions that
> have not changed in decades, to avoid confusing people. The literature
> on memory models is confusing enough, so fundamental definitions that
> are "common ground" shouldn't be changed if it can be avoided. I think
> here it is pretty trivial to avoid.
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMOmirPRKbjX9%3DV%2BeZD-YsEvfhUU8r6EDefkOJTBLDYNQ%40mail.gmail.com.
